// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Constants;
using Gp4Net.Transport;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Services;

/// <summary>
/// Unified SCP service that ONLY orchestrates secure channel operations.
/// This is a THIN orchestration layer that delegates ALL constants to Constants.cs
/// and ALL crypto operations to CryptoService.cs.
/// 
/// CRITICAL ARCHITECTURE RULE: This class contains NO constants or crypto code itself.
/// It ONLY handles protocol workflow and state management by calling other services.
/// 
/// Per GlobalPlatform Card Specification v2.3.1 Appendix E "Secure Channel Protocol".
/// All methods are static, pure functional, and return Result&lt;T, SmartCardError&gt;.
/// </summary>
[PublicAPI]
public static partial class ScpService
{
    /// <summary>
    /// Supporting types for SCP operations.
    /// </summary>
    [PublicAPI]
    public static class Types
    {
        /// <summary>
        /// SCP protocol and implementation parameter combination.
        /// Immutable value object representing a specific SCP variant.
        /// </summary>
        public sealed record ScpOption(
            CryptoService.ScpVersion Protocol,     // 0x02 or 0x03
            byte Implementation     // i-parameter (0x00, 0x02, 0x04, etc.)
        )
        {
            /// <summary>
            /// Creates a validated SCP option.
            /// </summary>
            public static Result<ScpOption, SmartCardError> Create(CryptoService.ScpVersion protocol, byte implementation) =>
                ValidateImplementation(protocol, implementation)
                    .Map(() => new ScpOption(protocol, implementation));
                    
            private static UnitResult<SmartCardError> ValidateImplementation(CryptoService.ScpVersion protocol, byte implementation) =>
                protocol switch
                {
                    CryptoService.ScpVersion.Scp02 => CryptoService.ScpOperations.Common.IsValidScp02Implementation(implementation)
                        ? UnitResult.Success<SmartCardError>()
                        : UnitResult.Failure(SmartCardError.InvalidArgument($"Invalid SCP02 implementation: {implementation:X2}")),
                    CryptoService.ScpVersion.Scp03 => CryptoService.ScpOperations.Common.IsValidScp03Implementation(implementation)  
                        ? UnitResult.Success<SmartCardError>()
                        : UnitResult.Failure(SmartCardError.InvalidArgument($"Invalid SCP03 implementation: {implementation:X2}")),
                    _ => UnitResult.Failure(SmartCardError.InvalidArgument($"Unsupported protocol: {protocol}"))
                };
        }

        /// <summary>
        /// Result of secure channel establishment containing state and capabilities.
        /// </summary>
        public sealed record SecureChannelSession(
            SecureChannelState State,
            ScpOption ScpOption,
            byte[] SessionId
        );

        /// <summary>
        /// Result of a secure command execution.
        /// </summary>
        public sealed record SecureCommandResult(
            byte[] Response,
            SecureChannelState NewState,
            StatusWord StatusWord
        );
    }

    /// <summary>
    /// Secure Channel Establishment operations.
    /// Orchestrates the complete SCP handshake process by calling CryptoService.
    /// </summary>
    [PublicAPI]  
    public static class Establishment
    {
        /// <summary>
        /// Establishes a secure channel automatically selecting the best available SCP.
        /// Orchestrates by calling CryptoService operations in sequence.
        /// </summary>
        /// <param name="cardService">The card service for communication.</param>
        /// <param name="keySet">The key set to use.</param>
        /// <param name="securityLevel">The desired security level.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The established secure channel session.</returns>
        public static async Task<Result<Types.SecureChannelSession, SmartCardError>> EstablishAsync(
            ISmartCardService cardService,
            IKeySet keySet,
            SecurityLevel securityLevel,
            CancellationToken cancellationToken = default)
        {
            // Auto-select SCP based on key set type
            return keySet switch
            {
                Scp02KeySet scp02KeySet => await EstablishScp02Async(cardService, scp02KeySet, securityLevel, cancellationToken),
                Scp03KeySet scp03KeySet => await EstablishScp03Async(cardService, scp03KeySet, securityLevel, cancellationToken),
                _ => Result.Failure<Types.SecureChannelSession, SmartCardError>(
                    SmartCardError.InvalidArgument($"Unsupported key set type: {keySet.GetType().Name}"))
            };
        }

        /// <summary>
        /// Establishes a secure channel with explicit SCP option.
        /// Orchestrates by calling CryptoService operations in sequence.
        /// </summary>
        /// <param name="cardService">The card service for communication.</param>
        /// <param name="keySet">The key set to use.</param>
        /// <param name="scpOption">The explicit SCP option.</param>
        /// <param name="securityLevel">The desired security level.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The established secure channel session.</returns>
        public static async Task<Result<Types.SecureChannelSession, SmartCardError>> EstablishAsync(
            ISmartCardService cardService,
            IKeySet keySet,
            Types.ScpOption scpOption,
            SecurityLevel securityLevel,
            CancellationToken cancellationToken = default)
        {
            return scpOption.Protocol switch
            {
                CryptoService.ScpVersion.Scp02 when keySet is Scp02KeySet scp02KeySet => 
                    await EstablishScp02Async(cardService, scp02KeySet, securityLevel, cancellationToken),
                CryptoService.ScpVersion.Scp03 when keySet is Scp03KeySet scp03KeySet => 
                    await EstablishScp03Async(cardService, scp03KeySet, securityLevel, cancellationToken),
                _ => Result.Failure<Types.SecureChannelSession, SmartCardError>(
                    SmartCardError.InvalidArgument($"Key set type does not match SCP option: {scpOption}"))
            };
        }

        private static async Task<Result<Types.SecureChannelSession, SmartCardError>> EstablishScp02Async(
            ISmartCardService cardService,
            Scp02KeySet keySet,
            SecurityLevel securityLevel,
            CancellationToken cancellationToken)
        {
            // Generate host challenge
            byte[] hostChallenge = new byte[Scp.Scp02.HostChallengeLength];
            Random.Shared.NextBytes(hostChallenge);

            // Send INITIALIZE UPDATE
            return await SendInitializeUpdate(cardService, hostChallenge, cancellationToken)
                .Bind(async response => await ProcessScp02InitializeUpdate(response, hostChallenge, keySet))
                .Bind(async context => await SendExternalAuthenticate(cardService, context, securityLevel, cancellationToken))
                .Map(state => new Types.SecureChannelSession(
                    state,
                    new Types.ScpOption(CryptoService.ScpVersion.Scp02, state.ImplementationParameter),
                    hostChallenge));
        }

        private static async Task<Result<Types.SecureChannelSession, SmartCardError>> EstablishScp03Async(
            ISmartCardService cardService,
            Scp03KeySet keySet,
            SecurityLevel securityLevel,
            CancellationToken cancellationToken)
        {
            // Generate host challenge
            byte[] hostChallenge = new byte[Scp.Scp03.HostChallengeLength];
            Random.Shared.NextBytes(hostChallenge);

            // Send INITIALIZE UPDATE
            return await SendInitializeUpdate(cardService, hostChallenge, cancellationToken)
                .Bind(async response => await ProcessScp03InitializeUpdate(response, hostChallenge, keySet))
                .Bind(async context => await SendExternalAuthenticate(cardService, context, securityLevel, cancellationToken))
                .Map(state => new Types.SecureChannelSession(
                    state,
                    new Types.ScpOption(CryptoService.ScpVersion.Scp03, state.ImplementationParameter),
                    hostChallenge));
        }

        private static async Task<Result<InitializeUpdateResponse, SmartCardError>> SendInitializeUpdate(
            ISmartCardService cardService,
            byte[] hostChallenge,
            CancellationToken cancellationToken)
        {
            var command = InitializeUpdateCommand.Create(0x00, 0x00, hostChallenge);
            return await command
                .Bind(cmd => cmd.ToCommandApdu())
                .Map(apdu => apdu.ToBytes())
                .Bind(async bytes => await cardService.SendCommandAsync(bytes, cancellationToken))
                .Bind(response => InitializeUpdateResponse.Parse(response.Data));
        }

        private static Task<Result<SecureChannelContext, SmartCardError>> ProcessScp02InitializeUpdate(
            InitializeUpdateResponse response,
            byte[] hostChallenge,
            Scp02KeySet keySet) =>
            Task.FromResult(
                CryptoService.KeyDerivation.DeriveSessionKeys(
                    KeyDerivationContext.CreateForScp02(keySet, hostChallenge, response.CardChallenge, 
                        response.SequenceCounter, (ScpImplementation)response.ImplementationParameter).Value)
                .Bind(sessionKeys => VerifyScp02CardCryptogram(response, hostChallenge, sessionKeys))
                .Bind(sessionKeys => SecureChannelContext.Create(
                    hostChallenge, response, sessionKeys, CryptoService.ScpVersion.Scp02, keySet)));

        private static Task<Result<SecureChannelContext, SmartCardError>> ProcessScp03InitializeUpdate(
            InitializeUpdateResponse response,
            byte[] hostChallenge,
            Scp03KeySet keySet) =>
            Task.FromResult(
                CryptoService.KeyDerivation.DeriveSessionKeys(
                    KeyDerivationContext.CreateForScp03(keySet, hostChallenge, response.CardChallenge, 
                        Maybe<ScpImplementation>.From((ScpImplementation)response.ImplementationParameter)).Value)
                .Bind(sessionKeys => VerifyScp03CardCryptogram(response, hostChallenge, sessionKeys))
                .Bind(sessionKeys => SecureChannelContext.Create(
                    hostChallenge, response, sessionKeys, CryptoService.ScpVersion.Scp03, keySet)));

        private static Result<SessionKeys, SmartCardError> VerifyScp02CardCryptogram(
            InitializeUpdateResponse response,
            byte[] hostChallenge,
            SessionKeys sessionKeys) =>
            CryptoService.Cryptogram.BuildScp02CardCryptogramData(response, hostChallenge)
                .Bind(data => CryptoService.ScpOperations.Scp02.CalculateCryptogram(sessionKeys.SEnc, data))
                .Bind(calculated => CryptoService.Utils.CompareBytes(calculated, response.CardCryptogram)
                    ? Result.Success<SessionKeys, SmartCardError>(sessionKeys)
                    : Result.Failure<SessionKeys, SmartCardError>(
                        SmartCardError.AuthenticationFailed("SCP02 card cryptogram verification failed")));

        private static Result<SessionKeys, SmartCardError> VerifyScp03CardCryptogram(
            InitializeUpdateResponse response,
            byte[] hostChallenge,
            SessionKeys sessionKeys) =>
            CryptoService.Cryptogram.BuildScp03CardCryptogramData(response, hostChallenge)
                .Bind(data => CryptoService.Cryptogram.CalculateScp03Cryptogram(sessionKeys.SEnc, data))
                .Bind(calculated => CryptoService.Utils.CompareBytes(calculated, response.CardCryptogram)
                    ? Result.Success<SessionKeys, SmartCardError>(sessionKeys)
                    : Result.Failure<SessionKeys, SmartCardError>(
                        SmartCardError.AuthenticationFailed("SCP03 card cryptogram verification failed")));

        private static async Task<Result<SecureChannelState, SmartCardError>> SendExternalAuthenticate(
            ISmartCardService cardService,
            SecureChannelContext context,
            SecurityLevel securityLevel,
            CancellationToken cancellationToken) =>
            await CreateExternalAuthenticateCommand(context, securityLevel)
                .Bind(cmd => cmd.ToCommandApdu())
                .Map(apdu => apdu.ToBytes())
                .Bind(async bytes => await cardService.SendCommandAsync(bytes, cancellationToken))
                .Bind(response => response.IsSuccess
                    ? CreateSecureChannelState(context, securityLevel)
                    : Result.Failure<SecureChannelState, SmartCardError>(
                        SmartCardError.AuthenticationFailed("EXTERNAL AUTHENTICATE failed")));

        private static Result<ExternalAuthenticateCommand, SmartCardError> CreateExternalAuthenticateCommand(
            SecureChannelContext context,
            SecurityLevel securityLevel) =>
            context.Protocol switch
            {
                CryptoService.ScpVersion.Scp02 => CreateScp02ExternalAuthenticate(context, securityLevel),
                CryptoService.ScpVersion.Scp03 => CreateScp03ExternalAuthenticate(context, securityLevel),
                _ => Result.Failure<ExternalAuthenticateCommand, SmartCardError>(
                    SmartCardError.InvalidArgument($"Unsupported protocol: {context.Protocol}"))
            };

        private static Result<ExternalAuthenticateCommand, SmartCardError> CreateScp02ExternalAuthenticate(
            SecureChannelContext context,
            SecurityLevel securityLevel) =>
            CryptoService.Cryptogram.BuildScp02HostCryptogramData(context.InitializeUpdateResponse, context.HostChallenge)
                .Bind(data => CryptoService.ScpOperations.Scp02.CalculateCryptogram(context.SessionKeys.SEnc, data))
                .Bind(cryptogram => ExternalAuthenticateCommand.Create([..cryptogram, (byte)securityLevel]))
                .Bind(command => 
                {
                    byte[] macData = [command.Cla, command.Ins, command.P1, command.P2, (byte)command.Data.Length, ..command.Data];
                    return CryptoService.ScpOperations.Scp02.CalculateCommandMac(macData, context.SessionKeys.SMac, Scp.Common.ZeroChaining8)
                        .Map(mac => ExternalAuthenticateCommand.Create([..command.Data, ..mac]).Value);
                });

        private static Result<ExternalAuthenticateCommand, SmartCardError> CreateScp03ExternalAuthenticate(
            SecureChannelContext context,
            SecurityLevel securityLevel) =>
            CryptoService.Cryptogram.BuildScp03HostCryptogramData(context.InitializeUpdateResponse, context.HostChallenge)
                .Bind(data => CryptoService.Cryptogram.CalculateScp03Cryptogram(context.SessionKeys.SEnc, data))
                .Bind(cryptogram => ExternalAuthenticateCommand.Create([..cryptogram, (byte)securityLevel]))
                .Bind(command => 
                {
                    byte[] macData = [command.Cla, command.Ins, command.P1, command.P2, (byte)command.Data.Length, ..command.Data];
                    return CryptoService.ScpOperations.Scp03.CalculateCommandMac(macData, context.SessionKeys.SMac, Scp.Common.ZeroChaining16)
                        .Map(mac => ExternalAuthenticateCommand.Create([..command.Data, ..mac]).Value);
                });

        private static Result<SecureChannelState, SmartCardError> CreateSecureChannelState(
            SecureChannelContext context,
            SecurityLevel securityLevel) =>
            CryptoService.ScpOperations.Common.GetZeroChainingValue(context.Protocol)
                .Bind(initialChaining => SecureChannelState.Create(
                    context.SessionKeys,
                    securityLevel,
                    context.Protocol,
                    initialChaining,
                    context.InitializeUpdateResponse.ImplementationParameter));
    }
}