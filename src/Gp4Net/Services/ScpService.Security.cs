// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Services;

/// <summary>
/// Security operations for the unified SCP service.
/// ONLY orchestrates by calling CryptoService - contains NO crypto logic itself.
/// </summary>
public static partial class ScpService
{
    /// <summary>
    /// Secure command and response processing operations.
    /// Orchestrates security application by delegating to CryptoService.
    /// </summary>
    [PublicAPI]
    public static class Security
    {
        /// <summary>
        /// Applies command security (MAC and/or encryption) to a command APDU.
        /// Orchestrates by calling the appropriate CryptoService operations.
        /// </summary>
        /// <param name="command">The command APDU to secure.</param>
        /// <param name="state">The current secure channel state.</param>
        /// <returns>The secured command and new state.</returns>
        public static Result<(byte[] securedCommand, SecureChannelState newState), SmartCardError> ApplyCommandSecurity(
            byte[] command,
            SecureChannelState state)
        {
            return state.Protocol switch
            {
                CryptoService.ScpVersion.Scp02 => ApplyScp02CommandSecurity(command, state),
                CryptoService.ScpVersion.Scp03 => ApplyScp03CommandSecurity(command, state),
                _ => Result.Failure<(byte[], SecureChannelState), SmartCardError>(
                    SmartCardError.InvalidArgument($"Unsupported protocol: {state.Protocol}"))
            };
        }

        /// <summary>
        /// Processes response security (MAC verification and/or decryption) for a response APDU.
        /// Orchestrates by calling the appropriate CryptoService operations.
        /// </summary>
        /// <param name="response">The response APDU to process.</param>
        /// <param name="state">The current secure channel state.</param>
        /// <returns>The processed response and new state.</returns>
        public static Result<(byte[] processedResponse, SecureChannelState newState), SmartCardError> ProcessResponseSecurity(
            byte[] response,
            SecureChannelState state)
        {
            // Check if response security should be applied
            ushort statusWord = (ushort)(response[^2] << 8 | response[^1]);
            if (!Scp.StatusWords.ShouldApplyResponseSecurity(statusWord))
                return Result.Success<(byte[], SecureChannelState), SmartCardError>((response, state));

            return state.Protocol switch
            {
                CryptoService.ScpVersion.Scp02 => ProcessScp02ResponseSecurity(response, state),
                CryptoService.ScpVersion.Scp03 => ProcessScp03ResponseSecurity(response, state),
                _ => Result.Failure<(byte[], SecureChannelState), SmartCardError>(
                    SmartCardError.InvalidArgument($"Unsupported protocol: {state.Protocol}"))
            };
        }

        /// <summary>
        /// Executes a secure command by applying security, sending, and processing the response.
        /// Complete secure command pipeline using CryptoService operations.
        /// </summary>
        /// <param name="cardService">The card service for communication.</param>
        /// <param name="command">The command APDU to execute.</param>
        /// <param name="state">The current secure channel state.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The command result with response and new state.</returns>
        public static async Task<Result<Types.SecureCommandResult, SmartCardError>> ExecuteSecureCommandAsync(
            ISmartCardService cardService,
            byte[] command,
            SecureChannelState state,
            CancellationToken cancellationToken = default)
        {
            return await ApplyCommandSecurity(command, state)
                .Bind(async secured => 
                {
                    var (securedCommand, intermediateState) = secured;
                    return await cardService.SendCommandAsync(securedCommand, cancellationToken)
                        .Bind(response => ProcessResponseSecurity(response.Data, intermediateState)
                            .Map(processed =>
                            {
                                var (processedResponse, finalState) = processed;
                                ushort statusWord = (ushort)(processedResponse[^2] << 8 | processedResponse[^1]);
                                return new Types.SecureCommandResult(
                                    processedResponse,
                                    finalState,
                                    new StatusWord(statusWord));
                            }));
                });
        }

        /// <summary>
        /// Unified command security application using protocol-specific operations.
        /// Eliminates duplication between SCP02 and SCP03 command security processing.
        /// </summary>
        private static Result<(byte[], SecureChannelState), SmartCardError> ApplyCommandSecurityWithProtocol(
            byte[] command,
            SecureChannelState state,
            Func<byte[], byte[], Result<byte[], SmartCardError>> encryptionOperation,
            Func<byte[], byte[], byte[], Result<byte[], SmartCardError>> macOperation,
            int macSize,
            Func<byte[], Result<SecureChannelState, SmartCardError>> stateUpdateOperation)
        {
            byte[] processedCommand = command;

            // Apply C-ENCRYPTION if required
            if (state.SecurityLevel.HasCEncryption())
            {
                var encryptResult = encryptionOperation(processedCommand, state.SessionKeys.SEnc);
                if (encryptResult.IsFailure)
                    return encryptResult.Error;

                processedCommand = encryptResult.Value;
            }

            // Apply C-MAC if required
            if (!state.SecurityLevel.HasCMac())
                return Result.Success<(byte[], SecureChannelState), SmartCardError>(
                    (processedCommand, state));

            return macOperation(processedCommand, state.SessionKeys.SMac, state.MacChainingValue)
                .Bind(mac =>
                {
                    // Append MAC to command
                    byte[] securedCommand = new byte[processedCommand.Length + macSize];
                    Array.Copy(processedCommand, 0, securedCommand, 0, processedCommand.Length);
                    Array.Copy(mac, 0, securedCommand, processedCommand.Length, macSize);

                    // Set secure messaging bit in CLA
                    securedCommand[0] |= Scp.Common.SecureMessagingClaBit;

                    // Update state using protocol-specific logic
                    return stateUpdateOperation(mac)
                        .Map(newState => (securedCommand, newState));
                });
        }

        private static Result<(byte[], SecureChannelState), SmartCardError> ApplyScp02CommandSecurity(
            byte[] command,
            SecureChannelState state)
        {
            return ApplyCommandSecurityWithProtocol(
                command,
                state,
                CryptoService.ScpOperations.Scp02.ApplyCommandEncryption,
                CryptoService.ScpOperations.Scp02.CalculateCommandMac,
                Scp.Scp02.MacSize,
                mac => state.UpdateMacChainingValue(mac));
        }

        private static Result<(byte[], SecureChannelState), SmartCardError> ApplyScp03CommandSecurity(
            byte[] command,
            SecureChannelState state)
        {
            return ApplyCommandSecurityWithProtocol(
                command,
                state,
                (cmd, key) => CryptoService.ScpOperations.Scp03.ApplyCommandEncryption(cmd, key, state.EncryptionCounter),
                CryptoService.ScpOperations.Scp03.CalculateCommandMac,
                Scp.Scp03.MacSize,
                mac =>
                {
                    // SCP03 uses full MAC for chaining and increments counter
                    byte[] fullMac = new byte[Scp.Scp03.FullMacSize];
                    Array.Copy(mac, 0, fullMac, 0, Scp.Scp03.MacSize);
                    return state.UpdateMacChainingValue(fullMac)
                        .Map(newState => newState.IncrementEncryptionCounter());
                });
        }

        /// <summary>
        /// Unified response security processing using protocol-specific operations.
        /// Eliminates duplication between SCP02 and SCP03 response security processing.
        /// </summary>
        private static Result<(byte[], SecureChannelState), SmartCardError> ProcessResponseSecurityWithProtocol(
            byte[] response,
            SecureChannelState state,
            Func<byte[], byte[], Result<byte[], SmartCardError>> encryptionOperation,
            Func<byte[], byte[], byte[], Result<byte[], SmartCardError>> macOperation,
            int macSize,
            Func<byte[], Result<SecureChannelState, SmartCardError>> stateUpdateOperation)
        {
            byte[] processedResponse = response;

            // Apply R-ENCRYPTION if required
            if (state.SecurityLevel.HasREncryption() && CryptoService.ScpOperations.Common.HasResponseData(response))
            {
                var encryptResult = encryptionOperation(processedResponse, state.SessionKeys.SEnc);
                if (encryptResult.IsFailure)
                    return encryptResult.Error;

                processedResponse = encryptResult.Value;
            }

            // Apply R-MAC if required
            if (!state.SecurityLevel.HasRMac())
                return Result.Success<(byte[], SecureChannelState), SmartCardError>(
                    (processedResponse, state));

            return macOperation(processedResponse, state.SessionKeys.SrMac, state.MacChainingValue)
                .Bind(mac =>
                {
                    // Insert R-MAC before status word
                    int statusOffset = processedResponse.Length - 2;
                    byte[] securedResponse = new byte[processedResponse.Length + macSize];
                    Array.Copy(processedResponse, 0, securedResponse, 0, statusOffset); // Data
                    Array.Copy(mac, 0, securedResponse, statusOffset, macSize); // R-MAC
                    Array.Copy(
                        processedResponse,
                        statusOffset,
                        securedResponse,
                        securedResponse.Length - 2,
                        2); // Status

                    // Update state using protocol-specific logic
                    return stateUpdateOperation(mac)
                        .Map(newState => (securedResponse, newState));
                });
        }

        private static Result<(byte[], SecureChannelState), SmartCardError> ProcessScp02ResponseSecurity(
            byte[] response,
            SecureChannelState state)
        {
            return ProcessResponseSecurityWithProtocol(
                response,
                state,
                CryptoService.ScpOperations.Scp02.ApplyResponseEncryption,
                CryptoService.ScpOperations.Scp02.CalculateResponseMac,
                Scp.Scp02.MacSize,
                mac => state.UpdateMacChainingValue(mac));
        }

        private static Result<(byte[], SecureChannelState), SmartCardError> ProcessScp03ResponseSecurity(
            byte[] response,
            SecureChannelState state)
        {
            return ProcessResponseSecurityWithProtocol(
                response,
                state,
                (resp, key) => CryptoService.ScpOperations.Scp03.ApplyResponseEncryption(resp, key, state.EncryptionCounter),
                CryptoService.ScpOperations.Scp03.CalculateResponseMac,
                Scp.Scp03.MacSize,
                mac =>
                {
                    // SCP03 uses full MAC for chaining and increments counter
                    byte[] fullMac = new byte[Scp.Scp03.FullMacSize];
                    Array.Copy(mac, 0, fullMac, 0, Scp.Scp03.MacSize);
                    return state.UpdateMacChainingValue(fullMac)
                        .Map(newState => newState.IncrementEncryptionCounter());
                });
        }
    }

    /// <summary>
    /// Protocol validation operations for secure channel protocols.
    /// Provides common validation logic used across SCP02, SCP03, and other protocols.
    /// Moved from Domain.Protocol.ProtocolValidation to consolidate SCP logic.
    /// </summary>
    [PublicAPI]
    public static class Validation
    {
        /// <summary>
        /// Validates that a host challenge is exactly 8 bytes.
        /// </summary>
        /// <param name="hostChallenge">The host challenge to validate.</param>
        /// <returns>Success if valid, error if invalid.</returns>
        public static UnitResult<SmartCardError> ValidateHostChallenge(byte[] hostChallenge)
        {
            if (hostChallenge is null)
                return UnitResult.Failure(SmartCardError.InvalidData("Host challenge cannot be null"));
            
            return hostChallenge.Length == 8 
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(SmartCardError.InvalidData($"Host challenge must be 8 bytes, got {hostChallenge.Length}"));
        }

        /// <summary>
        /// Validates that a card challenge meets the minimum length requirement.
        /// </summary>
        /// <param name="cardChallenge">The card challenge to validate.</param>
        /// <param name="expectedLength">The expected minimum length.</param>
        /// <returns>Success if valid, error if invalid.</returns>
        public static UnitResult<SmartCardError> ValidateCardChallenge(byte[] cardChallenge, int expectedLength)
        {
            if (cardChallenge is null)
                return UnitResult.Failure(SmartCardError.InvalidResponse("Card challenge cannot be null"));
            
            return cardChallenge.Length >= expectedLength 
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(SmartCardError.InvalidResponse($"Card challenge must be at least {expectedLength} bytes, got {cardChallenge.Length}"));
        }

        /// <summary>
        /// Validates that a sequence counter meets the expected length requirement.
        /// </summary>
        /// <param name="sequenceCounter">The sequence counter to validate.</param>
        /// <param name="expectedLength">The expected minimum length.</param>
        /// <returns>Success if valid, error if invalid.</returns>
        public static UnitResult<SmartCardError> ValidateSequenceCounter(byte[] sequenceCounter, int expectedLength)
        {
            if (sequenceCounter is null)
                return UnitResult.Failure(SmartCardError.InvalidResponse("Sequence counter cannot be null"));
            
            return sequenceCounter.Length >= expectedLength 
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(SmartCardError.InvalidResponse($"Sequence counter must be at least {expectedLength} bytes, got {sequenceCounter.Length}"));
        }

        /// <summary>
        /// Validates that a response is for the expected secure channel protocol.
        /// </summary>
        /// <param name="responseScpId">The SCP ID from the response.</param>
        /// <param name="expectedProtocol">The expected protocol version.</param>
        /// <returns>Success if valid, error if invalid.</returns>
        public static UnitResult<SmartCardError> ValidateProtocolVersion(
            Maybe<CryptoService.ScpVersion> responseScpId,
            CryptoService.ScpVersion expectedProtocol) =>
            responseScpId.Match(
                actualProtocol => actualProtocol == expectedProtocol
                    ? UnitResult.Success<SmartCardError>()
                    : UnitResult.Failure(SmartCardError.InvalidResponse(
                        $"Expected {expectedProtocol:X2} but received {actualProtocol:X2}")),
                () => UnitResult.Failure(SmartCardError.InvalidResponse("Response SCP ID not provided")));

        /// <summary>
        /// Validates that a key set is compatible with the specified protocol.
        /// </summary>
        /// <param name="keySet">The key set to validate.</param>
        /// <param name="expectedType">The expected key set type.</param>
        /// <returns>Success if valid, error if invalid.</returns>
        public static UnitResult<SmartCardError> ValidateKeySetType(object keySet, Type expectedType)
        {
            if (keySet is null)
                return UnitResult.Failure(SmartCardError.InvalidArgument("Key set cannot be null"));
            
            return keySet.GetType() == expectedType 
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(SmartCardError.InvalidArgument($"Expected {expectedType.Name} but got {keySet.GetType().Name}"));
        }
    }
}