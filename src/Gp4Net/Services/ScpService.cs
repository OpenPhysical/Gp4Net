// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Pipeline;
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
    private sealed record ExternalAuthenticateMaterial(
        ExternalAuthenticateCommand Command,
        byte[] ChainingMac
    );

    private sealed record AuthenticatedSecureChannel(
        SecureChannelState State,
        Types.SecureChannelVectors Vectors
    );

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
            CryptoService.ScpVersion Protocol, // 0x02 or 0x03
            byte Implementation // i-parameter (0x00, 0x02, 0x04, etc.)
        )
        {
            /// <summary>
            /// Creates a validated SCP option.
            /// </summary>
            public static Result<ScpOption, SmartCardError> Create(
                CryptoService.ScpVersion protocol,
                byte implementation
            ) =>
                ValidateImplementation(protocol, implementation)
                    .Map(() => new ScpOption(protocol, implementation));

            private static UnitResult<SmartCardError> ValidateImplementation(
                CryptoService.ScpVersion protocol,
                byte implementation
            ) =>
                protocol switch
                {
                    CryptoService.ScpVersion.Scp02
                        => CryptoService.ScpOperations.Common.IsValidScp02Implementation(
                            implementation
                        )
                            ? UnitResult.Success<SmartCardError>()
                            : UnitResult.Failure(
                                SmartCardError.InvalidArgument(
                                    $"Invalid SCP02 implementation: {implementation:X2}"
                                )
                            ),
                    CryptoService.ScpVersion.Scp03
                        => CryptoService.ScpOperations.Common.IsValidScp03Implementation(
                            implementation
                        )
                            ? UnitResult.Success<SmartCardError>()
                            : UnitResult.Failure(
                                SmartCardError.InvalidArgument(
                                    $"Invalid SCP03 implementation: {implementation:X2}"
                                )
                            ),
                    _
                        => UnitResult.Failure(
                            SmartCardError.InvalidArgument($"Unsupported protocol: {protocol}")
                        ),
                };
        }

        /// <summary>
        /// Result of secure channel establishment containing state and capabilities.
        /// </summary>
        public sealed record SecureChannelSession(
            SecureChannelState State,
            ScpOption ScpOption,
            byte[] SessionId,
            SecureChannelVectors? Vectors = null
        );

        /// <summary>
        /// Captured secure channel establishment material useful for test vectors.
        /// </summary>
        public sealed record SecureChannelVectors(
            byte[] HostChallenge,
            byte[] InitializeUpdateResponse,
            byte[] KeyDiversificationData,
            byte KeyVersion,
            byte ScpId,
            byte ImplementationParameter,
            byte[] SequenceCounter,
            byte[] CardChallenge,
            byte[] CardCryptogram,
            byte[] SEnc,
            byte[] SMac,
            byte[] SRMac,
            byte[] HostCryptogram,
            byte[] ExternalAuthenticateMac,
            byte[] ExternalAuthenticateChainingMac,
            byte[] ExternalAuthenticateCommand
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
            CancellationToken cancellationToken = default
        )
        {
            // Auto-select SCP based on key set type
            return keySet switch
            {
                Scp02KeySet scp02KeySet
                    => await EstablishScp02Async(
                        cardService,
                        scp02KeySet,
                        securityLevel,
                        cancellationToken
                    ),
                Scp03KeySet scp03KeySet
                    => await EstablishScp03Async(
                        cardService,
                        scp03KeySet,
                        securityLevel,
                        cancellationToken
                    ),
                _
                    => Result.Failure<Types.SecureChannelSession, SmartCardError>(
                        SmartCardError.InvalidArgument(
                            $"Unsupported key set type: {keySet.GetType().Name}"
                        )
                    ),
            };
        }

        /// <summary>
        /// Establishes a secure channel using protocol-agnostic keys, negotiating the protocol
        /// based on the card's INITIALIZE UPDATE response.
        /// This allows proper SCP negotiation per GlobalPlatform specification.
        /// </summary>
        /// <param name="cardService">The card service for communication.</param>
        /// <param name="rawKeyset">Protocol-agnostic keyset that will be converted after negotiation.</param>
        /// <param name="securityLevel">The desired security level.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The established secure channel session.</returns>
        public static async Task<Result<Types.SecureChannelSession, SmartCardError>> EstablishAsync(
            ISmartCardService cardService,
            RawKeyset rawKeyset,
            SecurityLevel securityLevel,
            CancellationToken cancellationToken = default
        )
        {
            return await EstablishAsync(
                cardService,
                rawKeyset,
                securityLevel,
                Maybe<byte>.From(rawKeyset.KeyVersion),
                cancellationToken
            );
        }

        /// <summary>
        /// Establishes a secure channel with optional key version autodetection.
        /// When no explicit KVN is supplied, candidates come from GET DATA(E0) and
        /// then GP P1=00 default key selection.
        /// </summary>
        public static async Task<Result<Types.SecureChannelSession, SmartCardError>> EstablishAsync(
            ISmartCardService cardService,
            RawKeyset rawKeyset,
            SecurityLevel securityLevel,
            Maybe<byte> explicitKeyVersion,
            CancellationToken cancellationToken = default
        )
        {
            // Query card capabilities first (optional, may fail)
            _ = await QueryCardCapabilities(cardService, cancellationToken);

            // GP Card Spec 2.3.1, B.4.3 and SCP03 1.1.2, 5.2 require a fresh
            // unpredictable host challenge for each authentication attempt.
            var challengeResult = CryptoService.Rng.GenerateHostChallenge();
            if (challengeResult.IsFailure)
                return challengeResult.Error;
            byte[] hostChallenge = challengeResult.Value;

            IReadOnlyList<byte> candidateKeyVersions = await ResolveCandidateKeyVersions(
                cardService,
                explicitKeyVersion,
                cancellationToken
            );
            var failures = new List<string>();

            foreach (byte candidateKeyVersion in candidateKeyVersions)
            {
                var initializeUpdateResult = await SendInitializeUpdate(
                    cardService,
                    hostChallenge,
                    candidateKeyVersion,
                    0x00,
                    cancellationToken
                );

                if (initializeUpdateResult.IsFailure)
                {
                    failures.Add(
                        $"P1=0x{candidateKeyVersion:X2}: {initializeUpdateResult.Error.Message}"
                    );
                    continue;
                }

                var sessionResult = await EstablishFromInitializeUpdateResponse(
                    cardService,
                    rawKeyset with
                    {
                        KeyVersion = initializeUpdateResult.Value.KeyVersion,
                    },
                    hostChallenge,
                    initializeUpdateResult.Value,
                    securityLevel,
                    cancellationToken
                );

                if (sessionResult.IsSuccess)
                {
                    return sessionResult;
                }

                failures.Add($"P1=0x{candidateKeyVersion:X2}: {sessionResult.Error.Message}");
            }

            string tried = string.Join(", ", candidateKeyVersions.Select(kvn => $"0x{kvn:X2}"));
            string detail = failures.Count > 0 ? string.Join("; ", failures) : "no candidates";
            return Result.Failure<Types.SecureChannelSession, SmartCardError>(
                SmartCardError.SecurityError(
                    $"Unable to establish secure channel. Tried key versions: {tried}. {detail}"
                )
            );
        }

        private static async Task<
            Result<Types.SecureChannelSession, SmartCardError>
        > EstablishFromInitializeUpdateResponse(
            ISmartCardService cardService,
            RawKeyset rawKeyset,
            byte[] hostChallenge,
            InitializeUpdateResponse initUpdateResponse,
            SecurityLevel securityLevel,
            CancellationToken cancellationToken
        )
        {
            return await initUpdateResponse
                .ScpVersion.ToResult(
                    SmartCardError.InvalidResponse(
                        "Card did not return SCP version in INITIALIZE UPDATE response"
                    )
                )
                .Bind(detectedVersion =>
                    rawKeyset
                        .ToTypedKeyset(detectedVersion)
                        .Bind(async typedKeyset =>
                        {
                            return detectedVersion switch
                            {
                                CryptoService.ScpVersion.Scp02
                                    => await ProcessScp02InitializeUpdate(
                                            initUpdateResponse,
                                            hostChallenge,
                                            (Scp02KeySet)typedKeyset
                                        )
                                        .Bind(async context =>
                                            await SendExternalAuthenticate(
                                                cardService,
                                                context,
                                                securityLevel,
                                                cancellationToken
                                            )
                                        )
                                        .Map(auth => new Types.SecureChannelSession(
                                            auth.State,
                                            new Types.ScpOption(
                                                CryptoService.ScpVersion.Scp02,
                                                auth.State.ImplementationParameter
                                            ),
                                            hostChallenge,
                                            auth.Vectors
                                        )),

                                CryptoService.ScpVersion.Scp03
                                    => await DiversifyScp03KeySetAsync(
                                            (Scp03KeySet)typedKeyset,
                                            rawKeyset.Diversification,
                                            initUpdateResponse.KeyDiversificationData
                                        )
                                        .Bind(async diversifiedKeyset =>
                                            await ProcessScp03InitializeUpdate(
                                                initUpdateResponse,
                                                hostChallenge,
                                                diversifiedKeyset
                                            )
                                        )
                                        .Bind(async context =>
                                            await SendExternalAuthenticate(
                                                cardService,
                                                context,
                                                securityLevel,
                                                cancellationToken
                                            )
                                        )
                                        .Map(auth => new Types.SecureChannelSession(
                                            auth.State,
                                            new Types.ScpOption(
                                                CryptoService.ScpVersion.Scp03,
                                                auth.State.ImplementationParameter
                                            ),
                                            hostChallenge,
                                            auth.Vectors
                                        )),

                                _
                                    => Result.Failure<Types.SecureChannelSession, SmartCardError>(
                                        SmartCardError.InvalidResponse(
                                            $"Unsupported SCP version from card: {detectedVersion}"
                                        )
                                    ),
                            };
                        })
                );
        }

        private static async Task<IReadOnlyList<byte>> ResolveCandidateKeyVersions(
            ISmartCardService cardService,
            Maybe<byte> explicitKeyVersion,
            CancellationToken cancellationToken
        )
        {
            if (explicitKeyVersion.HasValue)
            {
                return [explicitKeyVersion.Value];
            }

            List<byte> candidates = [];
            var keyInfoResult = await TryGetData(
                    GetDataCommand.DataObjects.KeyInformationTemplate,
                    cardService,
                    cancellationToken
                )
                .Bind(ExtractSuccessfulData)
                .Bind(Gp4Net.Domain.CardInfo.KeyInformationTemplate.Parse);

            if (keyInfoResult.IsSuccess)
            {
                candidates.AddRange(
                    keyInfoResult.Value.Keys.Select(key => key.KeyVersion).Distinct()
                );
            }

            if (!candidates.Contains(0x00))
            {
                candidates.Add(0x00);
            }

            return candidates;
        }

        private static async Task<Result<Scp03KeySet, SmartCardError>> DiversifyScp03KeySetAsync(
            Scp03KeySet keySet,
            Maybe<KeyDiversificationSpec> diversification,
            byte[] keyDiversificationData
        )
        {
            return await Task.FromResult(
                diversification.Match(
                    spec =>
                        KeyDiversificationService.DiversifyScp03KeySet(
                            keySet,
                            spec,
                            keyDiversificationData
                        ),
                    () => Result.Success<Scp03KeySet, SmartCardError>(keySet)
                )
            );
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
            CancellationToken cancellationToken = default
        )
        {
            return scpOption.Protocol switch
            {
                CryptoService.ScpVersion.Scp02 when keySet is Scp02KeySet scp02KeySet
                    => await EstablishScp02Async(
                        cardService,
                        scp02KeySet,
                        securityLevel,
                        cancellationToken
                    ),
                CryptoService.ScpVersion.Scp03 when keySet is Scp03KeySet scp03KeySet
                    => await EstablishScp03Async(
                        cardService,
                        scp03KeySet,
                        securityLevel,
                        cancellationToken
                    ),
                _
                    => Result.Failure<Types.SecureChannelSession, SmartCardError>(
                        SmartCardError.InvalidArgument(
                            $"Key set type does not match SCP option: {scpOption}"
                        )
                    ),
            };
        }

        private static async Task<
            Result<Types.SecureChannelSession, SmartCardError>
        > EstablishScp02Async(
            ISmartCardService cardService,
            Scp02KeySet keySet,
            SecurityLevel securityLevel,
            CancellationToken cancellationToken
        )
        {
            // GP Card Spec 2.3.1, B.4.3 requires a fresh random host challenge.
            var challengeResult = CryptoService.Rng.GenerateHostChallenge();
            if (challengeResult.IsFailure)
                return challengeResult.Error;
            byte[] hostChallenge = challengeResult.Value;

            // Send INITIALIZE UPDATE
            return await SendInitializeUpdate(
                    cardService,
                    hostChallenge,
                    keySet.KeyVersion,
                    keySet.KeyId,
                    cancellationToken
                )
                .Bind(async response =>
                    await ProcessScp02InitializeUpdate(response, hostChallenge, keySet)
                )
                .Bind(async context =>
                    await SendExternalAuthenticate(
                        cardService,
                        context,
                        securityLevel,
                        cancellationToken
                    )
                )
                .Map(auth => new Types.SecureChannelSession(
                    auth.State,
                    new Types.ScpOption(
                        CryptoService.ScpVersion.Scp02,
                        auth.State.ImplementationParameter
                    ),
                    hostChallenge,
                    auth.Vectors
                ));
        }

        private static async Task<
            Result<Types.SecureChannelSession, SmartCardError>
        > EstablishScp03Async(
            ISmartCardService cardService,
            Scp03KeySet keySet,
            SecurityLevel securityLevel,
            CancellationToken cancellationToken
        )
        {
            // SCP03 1.1.2, 5.2 requires a fresh random host challenge.
            var challengeResult = CryptoService.Rng.GenerateHostChallenge();
            if (challengeResult.IsFailure)
                return challengeResult.Error;
            byte[] hostChallenge = challengeResult.Value;

            // Send INITIALIZE UPDATE
            return await SendInitializeUpdate(
                    cardService,
                    hostChallenge,
                    keySet.KeyVersion,
                    keySet.KeyId,
                    cancellationToken
                )
                .Bind(async response =>
                    await ProcessScp03InitializeUpdate(response, hostChallenge, keySet)
                )
                .Bind(async context =>
                    await SendExternalAuthenticate(
                        cardService,
                        context,
                        securityLevel,
                        cancellationToken
                    )
                )
                .Map(auth => new Types.SecureChannelSession(
                    auth.State,
                    new Types.ScpOption(
                        CryptoService.ScpVersion.Scp03,
                        auth.State.ImplementationParameter
                    ),
                    hostChallenge,
                    auth.Vectors
                ));
        }

        /// <summary>
        /// Queries card capabilities to determine supported SCP options.
        /// This is optional and may fail on some cards.
        /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.3
        /// </summary>
        private static async Task<Result<byte[], SmartCardError>> QueryCardCapabilities(
            ISmartCardService cardService,
            CancellationToken cancellationToken
        )
        {
            var cardDataResult = await TryGetData(
                GetDataCommand.DataObjects.CardData,
                cardService,
                cancellationToken
            );

            return await cardDataResult.Match(
                response => Task.FromResult(ExtractSuccessfulData(response)),
                async _ =>
                    await TryGetDataOrEmpty(
                        GetDataCommand.DataObjects.CardCapabilities,
                        cardService,
                        cancellationToken
                    )
            );
        }

        private static async Task<Result<CommandResponse, SmartCardError>> TryGetData(
            ushort tagValue,
            ISmartCardService cardService,
            CancellationToken cancellationToken
        ) =>
            await GetDataCommand
                .Create(tagValue)
                .Bind(cmd => cmd.ToCommandApdu())
                .Map(apdu => apdu.ToBytes())
                .Bind(async bytes => await cardService.SendCommandAsync(bytes, cancellationToken));

        private static Result<byte[], SmartCardError> ExtractSuccessfulData(
            CommandResponse response
        ) =>
            response.IsSuccess
                ? Result.Success<byte[], SmartCardError>(response.Data ?? [])
                : Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidResponse("Card data query returned error status")
                );

        private static async Task<Result<byte[], SmartCardError>> TryGetDataOrEmpty(
            ushort tagValue,
            ISmartCardService cardService,
            CancellationToken cancellationToken
        ) =>
            (await TryGetData(tagValue, cardService, cancellationToken))
                .Bind(ExtractSuccessfulData)
                .Match(
                    data => Result.Success<byte[], SmartCardError>(data),
                    _ => Result.Success<byte[], SmartCardError>([]) // Optional, can fail
                );

        private static async Task<
            Result<InitializeUpdateResponse, SmartCardError>
        > SendInitializeUpdate(
            ISmartCardService cardService,
            byte[] hostChallenge,
            byte keyVersion,
            byte keyIdentifier,
            CancellationToken cancellationToken
        )
        {
            var command = InitializeUpdateCommand.Create(keyVersion, keyIdentifier, hostChallenge);
            return await command
                .Bind(cmd => cmd.ToCommandApdu())
                .Map(apdu => apdu.ToBytes())
                .Bind(async bytes => await cardService.SendCommandAsync(bytes, cancellationToken))
                .Bind(response => InitializeUpdateResponse.Parse(response.Data));
        }

        private static Task<
            Result<SecureChannelContext, SmartCardError>
        > ProcessScp02InitializeUpdate(
            InitializeUpdateResponse response,
            byte[] hostChallenge,
            Scp02KeySet keySet
        ) =>
            Task.FromResult(
                KeyDerivationContext
                    .CreateForScp02(
                        keySet,
                        hostChallenge,
                        response.CardChallenge,
                        response.SequenceCounter,
                        (ScpImplementation)response.ImplementationParameter
                    )
                    .Bind(context =>
                        CryptoService
                            .KeyDerivation.DeriveSessionKeys(context)
                            .Bind(sessionKeys =>
                                VerifyScp02CardCryptogram(response, hostChallenge, sessionKeys)
                                    .Map(() => sessionKeys)
                            )
                    )
                    .Bind(sessionKeys =>
                        SecureChannelContext.Create(
                            hostChallenge,
                            response,
                            sessionKeys,
                            CryptoService.ScpVersion.Scp02,
                            keySet
                        )
                    )
            );

        private static Task<
            Result<SecureChannelContext, SmartCardError>
        > ProcessScp03InitializeUpdate(
            InitializeUpdateResponse response,
            byte[] hostChallenge,
            Scp03KeySet keySet
        ) =>
            Task.FromResult(
                CryptoService
                    .KeyDerivation.DeriveSessionKeys(
                        KeyDerivationContext
                            .CreateForScp03(
                                keySet,
                                hostChallenge,
                                response.CardChallenge,
                                Maybe<ScpImplementation>.From(
                                    (ScpImplementation)response.ImplementationParameter
                                )
                            )
                            .Value
                    )
                    .Bind(sessionKeys =>
                        VerifyScp03CardCryptogram(response, hostChallenge, sessionKeys)
                    )
                    .Bind(sessionKeys =>
                        SecureChannelContext.Create(
                            hostChallenge,
                            response,
                            sessionKeys,
                            CryptoService.ScpVersion.Scp03,
                            keySet
                        )
                    )
            );

        private static UnitResult<SmartCardError> VerifyScp02CardCryptogram(
            InitializeUpdateResponse response,
            byte[] hostChallenge,
            SessionKeys sessionKeys
        ) =>
            CryptoService
                .Cryptogram.BuildScp02CardCryptogramData(response, hostChallenge)
                .Bind(data =>
                    CryptoService.ScpOperations.Scp02.CalculateCryptogram(sessionKeys.SEnc, data)
                )
                .Bind(calculated =>
                    CryptoService.Utils.CompareBytes(calculated, response.CardCryptogram)
                        ? UnitResult.Success<SmartCardError>()
                        : UnitResult.Failure(
                            SmartCardError.AuthenticationFailed(
                                "SCP02 card cryptogram verification failed"
                            )
                        )
                );

        private static Result<SessionKeys, SmartCardError> VerifyScp03CardCryptogram(
            InitializeUpdateResponse response,
            byte[] hostChallenge,
            SessionKeys sessionKeys
        ) =>
            CryptoService
                .Cryptogram.BuildScp03CardCryptogramData(response, hostChallenge)
                .Bind(context =>
                    CryptoService.ScpOperations.Scp03.CalculateCryptogram(
                        sessionKeys.SMac,
                        Constants.Constants.Scp.Scp03.CryptogramDerivation.CardCryptogram,
                        context
                    )
                )
                .Bind(calculated =>
                    CryptoService.Utils.CompareBytes(calculated, response.CardCryptogram)
                        ? Result.Success<SessionKeys, SmartCardError>(sessionKeys)
                        : Result.Failure<SessionKeys, SmartCardError>(
                            SmartCardError.AuthenticationFailed(
                                "SCP03 card cryptogram verification failed"
                            )
                        )
                );

        private static async Task<
            Result<AuthenticatedSecureChannel, SmartCardError>
        > SendExternalAuthenticate(
            ISmartCardService cardService,
            SecureChannelContext context,
            SecurityLevel securityLevel,
            CancellationToken cancellationToken
        ) =>
            await CreateExternalAuthenticateCommand(context, securityLevel)
                .Bind(async material =>
                    await material
                        .Command.ToCommandApdu()
                        .Map(apdu => apdu.ToBytes())
                        .Bind(async bytes =>
                            await cardService.SendCommandAsync(bytes, cancellationToken)
                        )
                        .Bind(response =>
                            response.IsSuccess
                                ? CreateSecureChannelState(
                                        context,
                                        securityLevel,
                                        material.ChainingMac
                                    )
                                    .Map(state => new AuthenticatedSecureChannel(
                                        state,
                                        CreateSecureChannelVectors(context, material)
                                    ))
                                : Result.Failure<AuthenticatedSecureChannel, SmartCardError>(
                                    SmartCardError.AuthenticationFailed(
                                        "EXTERNAL AUTHENTICATE failed"
                                    )
                                )
                        )
                );

        private static Result<
            ExternalAuthenticateMaterial,
            SmartCardError
        > CreateExternalAuthenticateCommand(
            SecureChannelContext context,
            SecurityLevel securityLevel
        ) =>
            context.Protocol switch
            {
                CryptoService.ScpVersion.Scp02
                    => CreateScp02ExternalAuthenticate(context, securityLevel),
                CryptoService.ScpVersion.Scp03
                    => CreateScp03ExternalAuthenticate(context, securityLevel),
                _
                    => Result.Failure<ExternalAuthenticateMaterial, SmartCardError>(
                        SmartCardError.InvalidArgument($"Unsupported protocol: {context.Protocol}")
                    ),
            };

        private static Result<
            ExternalAuthenticateMaterial,
            SmartCardError
        > CreateScp02ExternalAuthenticate(
            SecureChannelContext context,
            SecurityLevel securityLevel
        ) =>
            CryptoService
                .Cryptogram.BuildScp02HostCryptogramData(
                    context.InitializeUpdateResponse,
                    context.HostChallenge
                )
                .Bind(data =>
                    CryptoService.ScpOperations.Scp02.CalculateCryptogram(
                        context.SessionKeys.SEnc,
                        data
                    )
                )
                .Bind(cryptogram =>
                    ExternalAuthenticateCommand
                        .CreateWithoutMac(securityLevel, cryptogram)
                        .Bind(command =>
                        {
                            byte lc = (byte)(
                                cryptogram.Length + Constants.Constants.Scp.Scp02.MAC_SIZE
                            );
                            byte[] macInput =
                            [
                                Constants.Constants.Scp.Common.SECURE_CLA,
                                command.Ins,
                                command.P1,
                                command.P2,
                                lc,
                                .. cryptogram,
                            ];

                            return CryptoService
                                .ScpOperations.Scp02.CalculateCommandMac(
                                    macInput,
                                    context.SessionKeys.SMac,
                                    Scp.Common.ZeroChaining8
                                )
                                .Bind(mac =>
                                    ExternalAuthenticateCommand
                                        .CreateWithMac(securityLevel, cryptogram, mac)
                                        .Map(command => new ExternalAuthenticateMaterial(
                                            command,
                                            mac
                                        ))
                                );
                        })
                );

        private static Result<
            ExternalAuthenticateMaterial,
            SmartCardError
        > CreateScp03ExternalAuthenticate(
            SecureChannelContext context,
            SecurityLevel securityLevel
        ) =>
            CryptoService
                .Cryptogram.BuildScp03HostCryptogramData(
                    context.InitializeUpdateResponse,
                    context.HostChallenge
                )
                .Bind(cryptogramContext =>
                    CryptoService.ScpOperations.Scp03.CalculateCryptogram(
                        context.SessionKeys.SMac,
                        Constants.Constants.Scp.Scp03.CryptogramDerivation.HostCryptogram,
                        cryptogramContext
                    )
                )
                .Bind(cryptogram =>
                    ExternalAuthenticateCommand
                        .CreateWithoutMac(securityLevel, cryptogram)
                        .Bind(command =>
                        {
                            byte lc = (byte)(
                                cryptogram.Length + Constants.Constants.Scp.Scp03.MAC_SIZE
                            );
                            byte[] macInput =
                            [
                                Constants.Constants.Scp.Common.SECURE_CLA,
                                command.Ins,
                                command.P1,
                                command.P2,
                                lc,
                                .. cryptogram,
                            ];

                            return CryptoService
                                .ScpOperations.Scp03.CalculateCommandMac(
                                    macInput,
                                    context.SessionKeys.SMac,
                                    Scp.Common.ZeroChaining16
                                )
                                .Bind(fullMac =>
                                    ExternalAuthenticateCommand
                                        .CreateWithMac(
                                            securityLevel,
                                            cryptogram,
                                            fullMac[..Constants.Constants.Scp.Scp03.MAC_SIZE]
                                        )
                                        .Map(command => new ExternalAuthenticateMaterial(
                                            command,
                                            fullMac
                                        ))
                                );
                        })
                );

        private static Result<SecureChannelState, SmartCardError> CreateSecureChannelState(
            SecureChannelContext context,
            SecurityLevel securityLevel,
            byte[] externalAuthenticateMac
        ) =>
            GetInitialMacChainingValue(context, externalAuthenticateMac)
                .Bind(initialChaining =>
                    SecureChannelState
                        .Create(
                            context.SessionKeys,
                            securityLevel,
                            context.Protocol,
                            initialChaining,
                            context.InitializeUpdateResponse.ImplementationParameter
                        )
                        .Map(state =>
                            state with
                            {
                                KeyVersion = context.InitializeUpdateResponse.KeyVersion,
                            }
                        )
                );

        private static Result<byte[], SmartCardError> GetInitialMacChainingValue(
            SecureChannelContext context,
            byte[] externalAuthenticateMac
        )
        {
            if (
                context.Protocol == CryptoService.ScpVersion.Scp02
                && externalAuthenticateMac.Length == Constants.Constants.Scp.Scp02.MAC_SIZE
            )
            {
                return Result.Success<byte[], SmartCardError>(externalAuthenticateMac);
            }

            if (
                context.Protocol == CryptoService.ScpVersion.Scp03
                && externalAuthenticateMac.Length
                    == Constants.Constants.Scp.Scp03.CHAINING_VALUE_SIZE
            )
            {
                return Result.Success<byte[], SmartCardError>(externalAuthenticateMac);
            }

            return CryptoService.ScpOperations.Common.GetZeroChainingValue(context.Protocol);
        }

        private static Types.SecureChannelVectors CreateSecureChannelVectors(
            SecureChannelContext context,
            ExternalAuthenticateMaterial material
        )
        {
            var response = context.InitializeUpdateResponse;

            return new Types.SecureChannelVectors(
                HostChallenge: [.. context.HostChallenge],
                InitializeUpdateResponse:
                [
                    .. response.KeyDiversificationData,
                    .. response.KeyInformation,
                    .. response.SequenceCounter,
                    .. response.CardChallenge,
                    .. response.CardCryptogram,
                ],
                KeyDiversificationData: [.. response.KeyDiversificationData],
                KeyVersion: response.KeyVersion,
                ScpId: response.ScpId,
                ImplementationParameter: response.ImplementationParameter,
                SequenceCounter: response.SequenceCounter,
                CardChallenge: [.. response.CardChallenge],
                CardCryptogram: [.. response.CardCryptogram],
                SEnc: [.. context.SessionKeys.SEnc],
                SMac: [.. context.SessionKeys.SMac],
                SRMac: [.. context.SessionKeys.SrMac],
                HostCryptogram: [.. material.Command.HostCryptogram],
                ExternalAuthenticateMac: [.. material.Command.Mac],
                ExternalAuthenticateChainingMac: [.. material.ChainingMac],
                ExternalAuthenticateCommand: material.Command.ToBytes()
            );
        }
    }
}
