// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Cryptography.Implementation;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol
{
    /// <summary>
    /// Shared cryptogram building and verification utilities for secure channel protocols.
    /// Provides common cryptogram operations used across SCP02, SCP03, and other protocols.
    /// </summary>
    [PublicAPI]
    public static class CryptogramBuilder
    {
        /// <summary>
        /// Verifies a card cryptogram using the provided data construction function.
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response.</param>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <param name="sessionKeys">The session keys.</param>
        /// <param name="buildCryptogramData">Function to build protocol-specific cryptogram data.</param>
        /// <param name="keyDerivationService">The key derivation service.</param>
        /// <param name="protocolVersion">The protocol version.</param>
        /// <returns>True if cryptogram is valid, false otherwise.</returns>
        public static Result<bool, SmartCardError> VerifyCardCryptogram(
            InitializeUpdateResponse response,
            byte[] hostChallenge,
            SessionKeys sessionKeys,
            Func<InitializeUpdateResponse, byte[], Result<byte[], SmartCardError>> buildCryptogramData,
            IKeyDerivationService keyDerivationService,
            byte protocolVersion)
        {
            ArgumentNullException.ThrowIfNull(response);
            ArgumentNullException.ThrowIfNull(hostChallenge);
            ArgumentNullException.ThrowIfNull(sessionKeys);
            ArgumentNullException.ThrowIfNull(buildCryptogramData);
            ArgumentNullException.ThrowIfNull(keyDerivationService);

            return buildCryptogramData(response, hostChallenge)
                .Map(cryptogramData =>
                {
                    var cryptogramContext = new CryptogramContext(
                        protocolVersion: protocolVersion,
                        key: sessionKeys.SEnc, // Use S-ENC key for cryptograms per GP specification
                        data: cryptogramData,
                        type: CryptogramType.CardCryptogram
                    );

                    var expectedCryptogram = keyDerivationService.CalculateCryptogram(cryptogramContext);
                    return CryptographicOperations.CompareBytes(expectedCryptogram, response.CardCryptogram);
                });
        }

        /// <summary>
        /// Calculates a host cryptogram using the provided data construction function.
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response.</param>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <param name="sessionKeys">The session keys.</param>
        /// <param name="buildCryptogramData">Function to build protocol-specific cryptogram data.</param>
        /// <param name="keyDerivationService">The key derivation service.</param>
        /// <param name="protocolVersion">The protocol version.</param>
        /// <returns>The calculated host cryptogram.</returns>
        public static Result<byte[], SmartCardError> CalculateHostCryptogram(
            InitializeUpdateResponse response,
            byte[] hostChallenge,
            SessionKeys sessionKeys,
            Func<InitializeUpdateResponse, byte[], Result<byte[], SmartCardError>> buildCryptogramData,
            IKeyDerivationService keyDerivationService,
            byte protocolVersion)
        {
            ArgumentNullException.ThrowIfNull(response);
            ArgumentNullException.ThrowIfNull(hostChallenge);
            ArgumentNullException.ThrowIfNull(sessionKeys);
            ArgumentNullException.ThrowIfNull(buildCryptogramData);
            ArgumentNullException.ThrowIfNull(keyDerivationService);

            return buildCryptogramData(response, hostChallenge)
                .Map(cryptogramData =>
                {
                    var cryptogramContext = new CryptogramContext(
                        protocolVersion: protocolVersion,
                        key: sessionKeys.SEnc, // Use S-ENC key for cryptograms per GP specification
                        data: cryptogramData,
                        type: CryptogramType.HostCryptogram
                    );

                    return keyDerivationService.CalculateCryptogram(cryptogramContext);
                });
        }

        /// <summary>
        /// Builds SCP02-specific card cryptogram data.
        /// Per GP Card Specification Appendix E.4.2.1: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6)
        /// with ISO 7816-4 padding to 24 bytes total.
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response.</param>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <returns>The SCP02 card cryptogram data.</returns>
        public static Result<byte[], SmartCardError> BuildScp02CardCryptogramData(
            InitializeUpdateResponse response,
            byte[] hostChallenge)
        {
            var hostValidation = ProtocolValidation.ValidateHostChallenge(hostChallenge);
            if (hostValidation.IsFailure)
                return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidData(hostValidation.Error));
            
            var cardValidation = ProtocolValidation.ValidateCardChallenge(response.CardChallenge, 6);
            if (cardValidation.IsFailure)
                return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidResponse(cardValidation.Error));
            
            return ExtractScp02SequenceCounter(response)
                .Map(sequenceCounter =>
                {
                    // SCP02 card cryptogram data: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6)
                    var hostBytes = hostChallenge;
                    var seqCounterBytes = sequenceCounter[..2]; // First 2 bytes
                    var cardBytes = CryptographicOperations.ExtractBytes(response.CardChallenge, 0, 6);
                    
                    var data = CryptographicOperations.ConcatenateArrays(hostBytes, seqCounterBytes, cardBytes);
                    
                    // Apply ISO 7816-4 padding to make 24 bytes total
                    return CryptographicOperations.ApplyIso7816Padding(data, 24);
                });
        }

        /// <summary>
        /// Builds SCP02-specific host cryptogram data.
        /// Per GP Card Specification Appendix E.4.2.2: Sequence Counter (2) || Card Challenge (6) || Host Challenge (8)
        /// with ISO 7816-4 padding to 24 bytes total.
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response.</param>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <returns>The SCP02 host cryptogram data.</returns>
        public static Result<byte[], SmartCardError> BuildScp02HostCryptogramData(
            InitializeUpdateResponse response,
            byte[] hostChallenge)
        {
            var hostValidation = ProtocolValidation.ValidateHostChallenge(hostChallenge);
            if (hostValidation.IsFailure)
                return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidData(hostValidation.Error));
            
            var cardValidation = ProtocolValidation.ValidateCardChallenge(response.CardChallenge, 6);
            if (cardValidation.IsFailure)
                return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidResponse(cardValidation.Error));
            
            return ExtractScp02SequenceCounter(response)
                .Map(sequenceCounter =>
                {
                    // SCP02 host cryptogram data: Sequence Counter (2) || Card Challenge (6) || Host Challenge (8)
                    var seqCounterBytes = sequenceCounter[..2]; // First 2 bytes
                    var cardBytes = CryptographicOperations.ExtractBytes(response.CardChallenge, 0, 6);
                    var hostBytes = hostChallenge;
                    
                    var data = CryptographicOperations.ConcatenateArrays(seqCounterBytes, cardBytes, hostBytes);
                    
                    // Apply ISO 7816-4 padding to make 24 bytes total
                    return CryptographicOperations.ApplyIso7816Padding(data, 24);
                });
        }

        /// <summary>
        /// Builds SCP03-specific card cryptogram data.
        /// Per GP SCP03 Specification: Host Challenge (8) || Card Challenge (8) (no padding required).
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response.</param>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <returns>The SCP03 card cryptogram data.</returns>
        public static Result<byte[], SmartCardError> BuildScp03CardCryptogramData(
            InitializeUpdateResponse response,
            byte[] hostChallenge)
        {
            var hostValidation = ProtocolValidation.ValidateHostChallenge(hostChallenge);
            if (hostValidation.IsFailure)
                return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidData(hostValidation.Error));
            
            var cardValidation = ProtocolValidation.ValidateCardChallenge(response.CardChallenge, 8);
            if (cardValidation.IsFailure)
                return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidResponse(cardValidation.Error));
            
            // SCP03 card cryptogram data: Host Challenge (8) || Card Challenge (8)
            return Result.Success<byte[], SmartCardError>(
                CryptographicOperations.ConcatenateArrays(hostChallenge, response.CardChallenge));
        }

        /// <summary>
        /// Builds SCP03-specific host cryptogram data.
        /// Per GP SCP03 Specification: Card Challenge (8) || Host Challenge (8) (no padding required).
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response.</param>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <returns>The SCP03 host cryptogram data.</returns>
        public static Result<byte[], SmartCardError> BuildScp03HostCryptogramData(
            InitializeUpdateResponse response,
            byte[] hostChallenge)
        {
            var hostValidation = ProtocolValidation.ValidateHostChallenge(hostChallenge);
            if (hostValidation.IsFailure)
                return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidData(hostValidation.Error));
            
            var cardValidation = ProtocolValidation.ValidateCardChallenge(response.CardChallenge, 8);
            if (cardValidation.IsFailure)
                return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidResponse(cardValidation.Error));
            
            // SCP03 host cryptogram data: Card Challenge (8) || Host Challenge (8)
            return Result.Success<byte[], SmartCardError>(
                CryptographicOperations.ConcatenateArrays(response.CardChallenge, hostChallenge));
        }

        /// <summary>
        /// Extracts the 2-byte sequence counter from an SCP02 INITIALIZE UPDATE response.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <returns>The sequence counter (at least 2 bytes).</returns>
        private static Result<byte[], SmartCardError> ExtractScp02SequenceCounter(InitializeUpdateResponse response)
        {
            return response.SequenceCounter switch
            {
                null => Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidResponse("SCP02 requires sequence counter in INITIALIZE UPDATE response")),
                { Length: < 2 } => Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidResponse($"SCP02 sequence counter must be at least 2 bytes, got {response.SequenceCounter.Length}")),
                _ => Result.Success<byte[], SmartCardError>(response.SequenceCounter)
            };
        }
    }
}