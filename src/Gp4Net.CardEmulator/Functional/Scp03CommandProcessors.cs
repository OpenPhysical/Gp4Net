using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Domain;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using static Gp4Net.CardEmulator.Domain.CommandRequests;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// SCP03-specific command processors for the virtual card emulator.
/// Implements the SCP03 protocol flow according to GlobalPlatform Card Specification v2.3.1.
/// </summary>
[PublicAPI]
public static class Scp03CommandProcessors
{
    /// <summary>
    /// Processes an INITIALIZE UPDATE command for SCP03.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessScp03InitializeUpdate(
        byte[] command,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext,
        Maybe<ILogger> logger = default
    )
    {
        logger.Match(l => l.LogDebug("Processing SCP03 INITIALIZE UPDATE command"), () => { });

        var result = ParseInitializeUpdateCommand(command)
            .Bind(request =>
            {
                logger.Match(l => l.LogDebug("ParseInitializeUpdateCommand succeeded"), () => { });
                return ValidateScp03Preconditions(request, state, config, logger);
            })
            .Bind(request =>
            {
                logger.Match(l => l.LogDebug("ValidateScp03Preconditions succeeded"), () => { });
                return GenerateScp03CardChallenge(request, state, config, rngContext);
            })
            .Bind(data =>
            {
                logger.Match(l => l.LogDebug("GenerateScp03CardChallenge succeeded"), () => { });
                return CalculateScp03CardCryptogram(data, state, config, rngContext);
            })
            .Map(response =>
            {
                logger.Match(
                    l => l.LogDebug("CalculateScp03CardCryptogram succeeded, creating response"),
                    () => { }
                );
                return CreateScp03InitializeUpdateResponse(response, state, config);
            });

        if (result.IsFailure)
        {
            logger.Match(
                l =>
                    l.LogError(
                        "ProcessScp03InitializeUpdate failed: {ErrorMessage}",
                        result.Error.Message
                    ),
                () => { }
            );
        }

        return result;
    }

    /// <summary>
    /// Processes an EXTERNAL AUTHENTICATE command for SCP03.
    /// </summary>
    public static Result<
        (ApduResponse, CardState),
        SmartCardError
    > ProcessScp03ExternalAuthenticate(
        byte[] command,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext,
        LoggingService logging
    )
    {
        logging.LogDebug("Processing SCP03 EXTERNAL AUTHENTICATE command");
        logging.LogDebug("SCP03 PROCESSOR ENTRY: Starting ProcessScp03ExternalAuthenticate");
        logging.LogDebug("SCP03 Command: {Command}", Convert.ToHexString(command));
        return ParseExternalAuthenticateCommand(command)
            .Tap(request => logging.LogDebug("ParseExternalAuthenticateCommand: SUCCESS"))
            .TapError(error =>
                logging.LogDebug(
                    "ParseExternalAuthenticateCommand: FAILED - {Error}",
                    error.Message
                )
            )
            .Bind(request => ValidateScp03ExternalAuthPreconditions(request, state))
            .Tap(request => logging.LogDebug("ValidateScp03ExternalAuthPreconditions: SUCCESS"))
            .TapError(error =>
                logging.LogDebug(
                    "ValidateScp03ExternalAuthPreconditions: FAILED - {Error}",
                    error.Message
                )
            )
            .Bind(request => VerifyScp03HostCryptogram(request, state, rngContext))
            .Tap(request => logging.LogDebug("VerifyScp03HostCryptogram: SUCCESS"))
            .TapError(error =>
                logging.LogDebug("VerifyScp03HostCryptogram: FAILED - {Error}", error.Message)
            )
            .Bind(request => DeriveScp03SessionKeys(request, state, rngContext))
            .Bind(result =>
                VerifyScp03ExternalAuthenticateMac(result.request, result.sessionKeys)
                    .Map(fullMac => (result.sessionKeys, result.request, fullMac))
            )
            .Map(result =>
                CreateScp03ExternalAuthResponse(
                    result.sessionKeys,
                    result.request,
                    result.fullMac,
                    state
                )
            );
    }

    // Helper methods and data structures

    private record Scp03ChallengeData(
        CommandRequests.InitializeUpdateRequest Request,
        byte[] CardChallenge
    );

    private record Scp03CryptogramData(
        byte KeyVersion,
        ScpImplementation Implementation,
        byte[] HostChallenge,
        byte[] CardChallenge,
        byte[] CardCryptogram,
        byte[] SequenceCounter,
        IKeySet Keys
    );

    private static Result<InitializeUpdateRequest, SmartCardError> ParseInitializeUpdateCommand(
        byte[] command
    )
    {
        if (command.Length < 13) // CLA INS P1 P2 LC + 8 bytes challenge
            return SmartCardError.WrongLength();

        if (command[0] != 0x80 || command[1] != 0x50)
            return SmartCardError.InstructionNotSupported();

        byte keyVersion = command[2];
        byte keyIdentifier = command[3];
        byte lc = command[4];

        // Accept either 13 bytes (no Le) or 14 bytes (with Le)
        if (lc != 8 || command.Length != 13 && command.Length != 14)
            return SmartCardError.WrongLength();

        // For SCP03, key identifier must be 0x00
        if (keyIdentifier != 0x00)
            return SmartCardError.InvalidArgument("SCP03 requires key identifier 0x00");

        byte[] hostChallenge = command.Skip(5).Take(8).ToArray();

        return Result.Success<InitializeUpdateRequest, SmartCardError>(
            new InitializeUpdateRequest(keyVersion, keyIdentifier, hostChallenge)
        );
    }

    private static Result<InitializeUpdateRequest, SmartCardError> ValidateScp03Preconditions(
        InitializeUpdateRequest request,
        CardState state,
        CardConfiguration config,
        Maybe<ILogger> logger = default
    )
    {
        logger.Match(
            l =>
                l.LogDebug(
                    "SCP03 validation - IsSelected: {IsSelected}, ScpVersion: 0x{ScpVersion:X2}, ScpImpl: 0x{ScpImpl:X2}",
                    state.IsSelected,
                    state.ScpVersion,
                    (byte)state.ScpImplementation
                ),
            () => { }
        );

        if (!state.IsSelected)
        {
            logger.Match(l => l.LogError("SCP03 validation failed - card not selected"), () => { });
            return SmartCardError.ConditionsNotSatisfied();
        }

        // Verify SCP03 is configured
        if (state.ScpVersion != 0x03)
        {
            logger.Match(
                l =>
                    l.LogError(
                        "SCP03 validation failed - wrong SCP version: 0x{ScpVersion:X2}",
                        state.ScpVersion
                    ),
                () => { }
            );
            return SmartCardError.InvalidArgument("Card is not configured for SCP03");
        }

        // Validate implementation parameter
        byte[] validImplementations = [0x00, 0x10, 0x20, 0x60, 0x70];
        if (!validImplementations.Any(v => v == (byte)state.ScpImplementation))
        {
            logger.Match(
                l =>
                    l.LogError(
                        "SCP03 validation failed - invalid implementation: 0x{ScpImpl:X2}",
                        (byte)state.ScpImplementation
                    ),
                () => { }
            );
            return SmartCardError.InvalidArgument(
                $"Invalid SCP03 implementation: {state.ScpImplementation:X2}"
            );
        }

        logger.Match(l => l.LogDebug("SCP03 validation passed"), () => { });
        return Result.Success<InitializeUpdateRequest, SmartCardError>(request);
    }

    private static Result<Scp03ChallengeData, SmartCardError> GenerateScp03CardChallenge(
        InitializeUpdateRequest request,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        // Generate SCP03 card challenge per GlobalPlatform Card Specification v2.3.1 Section 6.2.2.1

        // SCP03 Amendment D v1.1.2, Table 5-1: b5 selects pseudo-random challenge generation.
        if (state.ScpImplementation.UsesScp03PseudoRandomChallenge())
        {
            // Using pseudo-random challenge generation (i=70)

            // Get the key set for pseudo-random generation
            if (!TryGetKeySet(request.KeyVersion, state, config, out var keySet) || keySet == null)
            {
                // Key set not found for requested version
                return SmartCardError.ReferencedDataNotFound();
            }

            // Key set found and validated

            if (keySet is not Scp03KeySet scp03Keys)
            {
                // Key set type validation failed
                return SmartCardError.InvalidArgument("SCP03 requires SCP03 key set");
            }

            // SCP03 key set validated successfully

            // Get sequence counter
            byte[] sequenceCounter = state.GetSequenceCounter(request.KeyVersion);

            // Derive pseudo-random challenge per GP SCP03 Amendment D using S-ENC KDF
            byte[] context = sequenceCounter.Concat(config.IsdAid).ToArray();
            return CryptoService
                .KeyDerivation.DeriveScp03Data(scp03Keys.EncKey, 0x02, context, 64)
                .Map(challenge => new Scp03ChallengeData(request, challenge));
        }

        // Using standard random challenge generation
        // Standard random challenge generation
        return rngContext
            .GenerateBytes(8)
            .Map(challenge => new Scp03ChallengeData(request, challenge));
    }

    private static Result<Scp03CryptogramData, SmartCardError> CalculateScp03CardCryptogram(
        Scp03ChallengeData data,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        // Calculate SCP03 card cryptogram per GP Card Specification v2.3.1

        // Determine effective key version
        byte effectiveKeyVersion = data.Request.KeyVersion;
        if (effectiveKeyVersion == 0x00)
        {
            // Key version is 0x00, using state.DefaultKeyVersion
            effectiveKeyVersion = state.DefaultKeyVersion;
            if (effectiveKeyVersion == 0xFF)
            {
                // DefaultKeyVersion is 0xFF, finding SCP03 key
                // For SCP03 context, prefer SCP03 key versions
                var scp03Key = config.StaticKeys.FirstOrDefault(kvp => kvp.Value is Scp03KeySet);
                effectiveKeyVersion =
                    scp03Key.Key != 0 ? scp03Key.Key : config.StaticKeys.Keys.FirstOrDefault();
            }
        }

        // Effective key version determined

        // Get the appropriate keys
        if (!TryGetKeySet(effectiveKeyVersion, state, config, out var keys) || keys == null)
        {
            // TryGetKeySet failed for key version
            return SmartCardError.ReferencedDataNotFound();
        }

        // Found key set for effective key version

        if (keys is not Scp03KeySet)
        {
            // Key set type mismatch - not SCP03KeySet
            return SmartCardError.InvalidArgument("SCP03 requires SCP03 key set");
        }

        // Get sequence counter
        byte[] sequenceCounter = state.GetSequenceCounter(effectiveKeyVersion);

        // CRITICAL FIX: Derive session keys BEFORE calculating cryptogram
        // Per GP Card Spec v2.3.1 Amendment D Section 6.2.2.2:
        // "The card cryptogram is calculated using the session key S-MAC"
        var scp03Keys = (Scp03KeySet)keys;

        return KeyDerivationContext
            .CreateForScp03(
                scp03Keys,
                data.Request.HostChallenge,
                data.CardChallenge,
                Maybe<ScpImplementation>.From(state.ScpImplementation)
            )
            .Bind(context => CryptoService.KeyDerivation.DeriveSessionKeys(context))
            .Bind(sessionKeys =>
                // Calculate cryptogram using SESSION S-MAC key (not static MAC key)
                CryptoService
                    .Cryptogram.CalculateScp03CardCryptogram(
                        sessionKeys.SMac,
                        data.Request.HostChallenge,
                        data.CardChallenge
                    )
                    .Map(cryptogram => new Scp03CryptogramData(
                        effectiveKeyVersion,
                        state.ScpImplementation,
                        data.Request.HostChallenge,
                        data.CardChallenge,
                        cryptogram,
                        sequenceCounter,
                        keys
                    ))
            );
    }

    private static (ApduResponse, CardState) CreateScp03InitializeUpdateResponse(
        Scp03CryptogramData data,
        CardState state,
        CardConfiguration config
    )
    {
        // Build SCP03 INITIALIZE UPDATE response
        byte[] response = new byte[32]; // Fixed size for SCP03
        int offset = 0;

        // Key diversification data (10 bytes)
        Array.Fill<byte>(response, 0x00, offset, 10);
        offset += 10;

        // Key information (3 bytes)
        response[offset++] = data.KeyVersion; // Byte 0: Key version
        response[offset++] = 0x03; // Byte 1: SCP version (always 0x03 for SCP03)
        response[offset++] = (byte)data.Implementation; // Byte 2: Implementation parameter (e.g., 0x70)

        // Card challenge (8 bytes)
        Array.Copy(data.CardChallenge, 0, response, offset, 8);
        offset += 8;

        // Card cryptogram (8 bytes)
        Array.Copy(data.CardCryptogram, 0, response, offset, 8);
        offset += 8;

        // Sequence counter (3 bytes)
        Array.Copy(data.SequenceCounter, 0, response, offset, 3);

        // Update state
        var newState = state
            .WithChallenges(
                Maybe<byte[]>.From(data.HostChallenge),
                Maybe<byte[]>.From(data.CardChallenge)
            )
            .WithKeys(data.Keys);

        // Increment sequence counter if pseudo-random challenges are used (i=70)
        if (data.Implementation == ScpImplementation.Scp03I70)
        {
            newState = newState.WithIncrementedSequenceCounter(data.KeyVersion);
        }

        // SCP03 INITIALIZE UPDATE response created successfully

        return (
            new ApduResponse(response, Gp4Net.Constants.Constants.StatusWords.Success),
            newState
        );
    }

    private static Result<
        ExternalAuthenticateRequest,
        SmartCardError
    > ParseExternalAuthenticateCommand(byte[] command, Maybe<ILogger> logger = default)
    {
        if (command.Length < 5)
        {
            logger.Match(
                l =>
                    l.LogError(
                        "SCP03 EXTERNAL AUTHENTICATE: Command too short: {Length} bytes",
                        command.Length
                    ),
                () => { }
            );
            return SmartCardError.WrongLength();
        }

        // SCP03 Amendment D v1.1.2, Sections 6.2.3 and 7.1.2.
        if (command[0] is < 0x84 or > 0x87)
            return SmartCardError.FromStatusWord(0x6E00);

        if (command[1] != 0x82)
        {
            logger.Match(
                l =>
                    l.LogError(
                        "SCP03 EXTERNAL AUTHENTICATE: Invalid CLA/INS: {CLA:X2} {INS:X2}",
                        command[0],
                        command[1]
                    ),
                () => { }
            );
            return SmartCardError.InstructionNotSupported();
        }

        byte securityLevel = command[2];
        byte p2 = command[3];
        byte lc = command[4];

        if (p2 != 0x00)
            return SmartCardError.IncorrectP1P2("EXTERNAL AUTHENTICATE P2 must be 00");

        logger.Match(
            l =>
                l.LogDebug(
                    "SCP03 EXTERNAL AUTHENTICATE: Security Level=0x{SecurityLevel:X2}, P2=0x{P2:X2}, Lc={Lc}",
                    securityLevel,
                    p2,
                    lc
                ),
            () => { }
        );
        logger.Match(
            l => l.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Command length={Length}", command.Length),
            () => { }
        );

        if (lc != 16 || command.Length != 21)
        {
            logger.Match(
                l =>
                    l.LogDebug(
                        "SCP03 EXTERNAL AUTHENTICATE: Wrong length - Lc={Lc}, command.Length={Length}",
                        lc,
                        command.Length
                    ),
                () => { }
            );
            return SmartCardError.WrongLength();
        }

        byte[] hostCryptogram = command.Skip(5).Take(8).ToArray();
        byte[] hostMac = command.Skip(13).Take(8).ToArray();
        return Result.Success<ExternalAuthenticateRequest, SmartCardError>(
            new ExternalAuthenticateRequest(securityLevel, hostCryptogram, hostMac, command[0])
        );
    }

    private static Result<
        ExternalAuthenticateRequest,
        SmartCardError
    > ValidateScp03ExternalAuthPreconditions(
        ExternalAuthenticateRequest request,
        CardState state,
        Maybe<ILogger> logger = default
    )
    {
        if (!state.IsSelected)
        {
            logger.Match(
                l => l.LogError("SCP03 EXTERNAL AUTHENTICATE: Card not selected"),
                () => { }
            );
            return SmartCardError.ConditionsNotSatisfied();
        }

        if (state.HostChallenge.HasNoValue || state.CardChallenge.HasNoValue)
        {
            logger.Match(
                l =>
                    l.LogError(
                        "SCP03 EXTERNAL AUTHENTICATE: Missing challenges - HostChallenge={HasHost}, CardChallenge={HasCard}",
                        state.HostChallenge.HasValue,
                        state.CardChallenge.HasValue
                    ),
                () => { }
            );
            return SmartCardError.ConditionsNotSatisfied();
        }

        if (state.CurrentKeys.HasNoValue)
        {
            logger.Match(
                l => l.LogError("SCP03 EXTERNAL AUTHENTICATE: No current keys set"),
                () => { }
            );
            return SmartCardError.ConditionsNotSatisfied();
        }

        // Validate security level for SCP03
        // Valid levels: 0x01 (C-MAC), 0x03 (C-DECRYPTION), 0x10 (R-MAC), 0x11 (C-MAC + R-MAC), 0x30 (R-MAC + R-ENC), 0x33 (C-DECRYPTION + R-MAC + R-ENC)
        // SCP03 Amendment D v1.1.2, Section 7.1.2.3, Table 7-6.
        int[] validLevels = [0x00, 0x01, 0x03, 0x11, 0x13, 0x33];
        if (!validLevels.Contains(request.SecurityLevel))
        {
            logger.Match(
                l =>
                    l.LogError(
                        "SCP03 EXTERNAL AUTHENTICATE: Invalid security level 0x{SecurityLevel:X2}",
                        request.SecurityLevel
                    ),
                () => { }
            );
            logger.Match(
                l =>
                    l.LogError(
                        "SCP03 Valid levels: {ValidLevels}",
                        string.Join(", ", validLevels.Select(l => $"0x{l:X2}"))
                    ),
                () => { }
            );
            return SmartCardError.InvalidArgument(
                $"Invalid security level for SCP03: {request.SecurityLevel:X2}"
            );
        }

        logger.Match(
            l =>
                l.LogDebug(
                    "SCP03 EXTERNAL AUTHENTICATE: Security level 0x{SecurityLevel:X2} is valid",
                    request.SecurityLevel
                ),
            () => { }
        );
        return Result.Success<ExternalAuthenticateRequest, SmartCardError>(request);
    }

    private static Result<ExternalAuthenticateRequest, SmartCardError> VerifyScp03HostCryptogram(
        ExternalAuthenticateRequest request,
        CardState state,
        IRngContext rngContext,
        Maybe<ILogger> logger = default
    )
    {
        if (
            state.HostChallenge.HasNoValue
            || state.CardChallenge.HasNoValue
            || state.CurrentKeys.HasNoValue
        )
        {
            logger.Match(
                l =>
                    l.LogError(
                        "SCP03 EXTERNAL AUTHENTICATE: Missing data for cryptogram verification"
                    ),
                () => { }
            );
            return SmartCardError.ConditionsNotSatisfied();
        }

        logger.Match(
            l => l.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Calculating expected host cryptogram"),
            () => { }
        );
        return state.HostChallenge.Match(
            hostChallenge =>
                state.CardChallenge.Match(
                    cardChallenge =>
                        state.CurrentKeys.Match(
                            currentKeys =>
                            {
                                logger.Match(
                                    l =>
                                        l.LogDebug(
                                            "Host Challenge: {HostChallenge}",
                                            Convert.ToHexString(hostChallenge)
                                        ),
                                    () => { }
                                );
                                logger.Match(
                                    l =>
                                        l.LogDebug(
                                            "Card Challenge: {CardChallenge}",
                                            Convert.ToHexString(cardChallenge)
                                        ),
                                    () => { }
                                );

                                // Ensure we have SCP03 keys
                                if (currentKeys is not Scp03KeySet scp03Keys)
                                {
                                    logger.Match(
                                        l =>
                                            l.LogError(
                                                "SCP03 EXTERNAL AUTHENTICATE: Current keys are not SCP03 keys"
                                            ),
                                        () => { }
                                    );
                                    return Result.Failure<
                                        ExternalAuthenticateRequest,
                                        SmartCardError
                                    >(
                                        SmartCardError.InvalidArgument(
                                            "SCP03 requires SCP03 key set"
                                        )
                                    );
                                }

                                // SCP03 Amendment D v1.1.2, Section 6.2.2.3.
                                return KeyDerivationContext
                                    .CreateForScp03(
                                        scp03Keys,
                                        hostChallenge,
                                        cardChallenge,
                                        Maybe<ScpImplementation>.From(state.ScpImplementation)
                                    )
                                    .Bind(context =>
                                        CryptoService.KeyDerivation.DeriveSessionKeys(context)
                                    )
                                    .Bind(sessionKeys =>
                                        // Calculate expected cryptogram using SESSION S-MAC key
                                        CryptoService
                                            .Cryptogram.CalculateScp03HostCryptogram(
                                                sessionKeys.SMac,
                                                hostChallenge,
                                                cardChallenge
                                            )
                                            .Bind(expectedCryptogram =>
                                            {
                                                if (
                                                    !CryptoService.Utils.CompareBytes(
                                                        request.HostCryptogram,
                                                        expectedCryptogram
                                                    )
                                                )
                                                {
                                                    logger.Match(
                                                        l =>
                                                            l.LogError(
                                                                "SCP03 EXTERNAL AUTHENTICATE: Host cryptogram verification failed"
                                                            ),
                                                        () => { }
                                                    );
                                                    return Result.Failure<
                                                        ExternalAuthenticateRequest,
                                                        SmartCardError
                                                    >(SmartCardError.SecurityStatusNotSatisfied());
                                                }

                                                logger.Match(
                                                    l =>
                                                        l.LogDebug(
                                                            "SCP03 EXTERNAL AUTHENTICATE: Host cryptogram verified successfully"
                                                        ),
                                                    () => { }
                                                );
                                                return Result.Success<
                                                    ExternalAuthenticateRequest,
                                                    SmartCardError
                                                >(request);
                                            })
                                    );
                            },
                            () =>
                                Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                                    SmartCardError.ConditionsNotSatisfied()
                                )
                        ),
                    () =>
                        Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                            SmartCardError.ConditionsNotSatisfied()
                        )
                ),
            () =>
                Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                    SmartCardError.ConditionsNotSatisfied()
                )
        );
    }

    private static Result<
        (SessionKeys sessionKeys, ExternalAuthenticateRequest request),
        SmartCardError
    > DeriveScp03SessionKeys(
        ExternalAuthenticateRequest request,
        CardState state,
        IRngContext rngContext,
        Maybe<ILogger> logger = default
    )
    {
        if (
            state.HostChallenge.HasNoValue
            || state.CardChallenge.HasNoValue
            || state.CurrentKeys.HasNoValue
        )
        {
            logger.Match(
                l =>
                    l.LogError(
                        "SCP03 EXTERNAL AUTHENTICATE: Missing data for session key derivation"
                    ),
                () => { }
            );
            return SmartCardError.ConditionsNotSatisfied();
        }

        logger.Match(
            l => l.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Deriving session keys"),
            () => { }
        );

        return state.HostChallenge.Match(
            hostChallenge =>
                state.CardChallenge.Match(
                    cardChallenge =>
                        state.CurrentKeys.Match(
                            currentKeys =>
                                KeyDerivationContext
                                    .CreateForScp03(
                                        currentKeys,
                                        hostChallenge,
                                        cardChallenge,
                                        state.ScpImplementation
                                    )
                                    .Bind(context =>
                                        CryptoService.KeyDerivation.DeriveSessionKeys(context)
                                    )
                                    .Tap(keys =>
                                        logger.Match(
                                            l =>
                                                l.LogDebug(
                                                    "SCP03 EXTERNAL AUTHENTICATE: Session keys derived successfully"
                                                ),
                                            () => { }
                                        )
                                    )
                                    .Map(sessionKeys => (sessionKeys, request)),
                            () =>
                                Result.Failure<
                                    (SessionKeys, ExternalAuthenticateRequest),
                                    SmartCardError
                                >(SmartCardError.ConditionsNotSatisfied())
                        ),
                    () =>
                        Result.Failure<(SessionKeys, ExternalAuthenticateRequest), SmartCardError>(
                            SmartCardError.ConditionsNotSatisfied()
                        )
                ),
            () =>
                Result.Failure<(SessionKeys, ExternalAuthenticateRequest), SmartCardError>(
                    SmartCardError.ConditionsNotSatisfied()
                )
        );
    }

    private static (ApduResponse, CardState) CreateScp03ExternalAuthResponse(
        SessionKeys sessionKeys,
        ExternalAuthenticateRequest request,
        byte[] fullMac,
        CardState state,
        Maybe<ILogger> logger = default
    )
    {
        logger.Match(l => l.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Creating response"), () => { });

        var securityLevel = (SecurityLevel)request.SecurityLevel;

        var secureChannelStateResult = SecureChannelState.Create(
            sessionKeys: sessionKeys,
            securityLevel: securityLevel,
            protocolVersion: (CryptoService.ScpVersion)
                Gp4Net.Constants.Constants.GlobalPlatform.Protocols.SCP03,
            initialMacChainingValue: fullMac,
            implementationParameter: (byte)state.ScpImplementation
        );

        if (secureChannelStateResult.IsFailure)
        {
            logger.Match(
                l =>
                    l.LogError(
                        "Failed to create secure channel state: {Error}",
                        secureChannelStateResult.Error
                    ),
                () => { }
            );
            return (
                new ApduResponse(
                    [],
                    Gp4Net
                        .Constants
                        .Constants
                        .StatusWords
                        .CheckingErrors
                        .AuthenticationMethodBlocked
                ),
                state
            );
        }

        var secureChannelState = secureChannelStateResult.Value;

        var newState = state.WithSecureChannel(secureChannelState);

        logger.Match(
            l =>
                l.LogDebug(
                    "SCP03 EXTERNAL AUTHENTICATE: Secure channel established with security level 0x{SecurityLevel:X2}",
                    request.SecurityLevel
                ),
            () => { }
        );

        // SCP03 EXTERNAL AUTHENTICATE response is typically empty on success
        return (new ApduResponse([], Gp4Net.Constants.Constants.StatusWords.Success), newState);
    }

    /// <summary>
    /// Calculates the full MAC chaining value from the EXTERNAL AUTHENTICATE command.
    /// Per SCP03 specification, the MAC chaining value for subsequent operations
    /// is the full 16-byte MAC of the EXTERNAL AUTHENTICATE command.
    /// </summary>
    // SCP03 Amendment D v1.1.2, Sections 6.2.3 and 6.2.4.
    private static Result<byte[], SmartCardError> VerifyScp03ExternalAuthenticateMac(
        ExternalAuthenticateRequest request,
        SessionKeys sessionKeys
    )
    {
        byte[] macInput =
        [
            request.Cla,
            0x82,
            request.SecurityLevel,
            0x00,
            0x10,
            .. request.HostCryptogram,
        ];

        return CryptoService
            .ScpOperations.Scp03.CalculateCommandMac(
                macInput,
                sessionKeys.SMac,
                Gp4Net.Constants.Constants.Scp.Common.ZeroChaining16
            )
            .Bind(fullMac =>
                System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    fullMac.AsSpan(0, 8),
                    request.HostMac
                )
                    ? Result.Success<byte[], SmartCardError>(fullMac)
                    : Result.Failure<byte[], SmartCardError>(
                        SmartCardError.SecurityStatusNotSatisfied()
                    )
            );
    }

    // Utility methods

    private static bool TryGetKeySet(
        byte keyVersion,
        CardState state,
        CardConfiguration config,
        out IKeySet? keySet
    )
    {
        keySet = null;

        // Check installed keys first
        if (
            state.InstalledKeys.TryGetValue(keyVersion, out IKeySet? installedKeys)
            && installedKeys is not null
        )
        {
            keySet = installedKeys;
            return true;
        }

        // Then check static keys
        if (
            config.StaticKeys.TryGetValue(keyVersion, out IKeySet? staticKeys)
            && staticKeys is not null
        )
        {
            keySet = staticKeys;
            return true;
        }

        // If key version is 0x00 or 0xFF, try to find any available key
        if (keyVersion is 0x00 or 0xFF)
        {
            // For SCP03 context, prefer SCP03 key sets
            keySet =
                config.StaticKeys.Values.OfType<Scp03KeySet>().FirstOrDefault()
                ?? config.StaticKeys.Values.FirstOrDefault();
            return keySet != null;
        }

        return false;
    }

    /// <summary>
    /// Checks if a command should be processed as SCP03.
    /// </summary>
    public static bool IsScp03Command(byte[] command, CardState state)
    {
        if (command.Length < 2)
            return false;

        // Check if it's INITIALIZE UPDATE or EXTERNAL AUTHENTICATE
        byte cla = command[0];
        byte ins = command[1];

        if (cla == 0x80 && ins == 0x50 || cla == 0x84 && ins == 0x82)
        {
            // Check if card is configured for SCP03
            return state.ScpVersion == 0x03;
        }

        // Check if secure channel is established with SCP03
        return state is { IsSecureChannelEstablished: true, ScpVersion: 0x03 };
    }
}
