using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using static Gp4Net.CardEmulator.Domain.CommandRequests;
using static Gp4Net.Cryptography.CryptoService;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Pure functional command processors that transform card state.
/// Each processor is a pure function: (command, state, config, services) -> Result&lt;(response, newState)&gt;
/// </summary>
[PublicAPI]
public static class CommandProcessors
{
    /// <summary>
    /// Processes a SELECT command to select the ISD or an application.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessSelect(
        byte[] command,
        CardState state,
        CardConfiguration config,
        LoggingService logging
    )
    {
        logging.LogDebug("Processing SELECT command");
        logging.LogDebug(
            "Virtual card processing SELECT, current IsSelected: {IsSelected}",
            state.IsSelected
        );

        return ParseSelectCommand(command)
            .Bind(aid =>
            {
                logging.LogDebug("Virtual card SELECT parsed AID: {Aid}", Convert.ToHexString(aid));
                return ValidateSelectAid(aid, config);
            })
            .Map(aid => CreateSelectResponse(aid, config))
            .Map(response =>
            {
                var newState = state.WithSelected();
                logging.LogDebug("Virtual card SELECT success, setting IsSelected to true");
                return (response, newState);
            })
            .TapError(error =>
                logging.LogDebug("Virtual card SELECT failed: {Error}", error.Message)
            );
    }

    /// <summary>
    /// Processes an INITIALIZE UPDATE command to start secure channel establishment.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessInitializeUpdate(
        byte[] command,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext,
        LoggingService logging
    )
    {
        logging.LogDebug(
            "Processing INITIALIZE UPDATE - Card SCP version: 0x{Scp:X2}",
            state.ScpVersion
        );

        // Delegate to protocol-specific processors
        var logger = logging.Logger.Match(
            l => l,
            () => Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance
        );
        if (Scp02CommandProcessors.IsScp02Command(command, state, logger))
        {
            logging.LogDebug("Routing to SCP02 processor");
            return Scp02CommandProcessors.ProcessScp02InitializeUpdate(
                command,
                state,
                config,
                rngContext,
                logging
            );
        }
        if (Scp03CommandProcessors.IsScp03Command(command, state))
        {
            logging.LogDebug("Routing to SCP03 processor");
            return Scp03CommandProcessors.ProcessScp03InitializeUpdate(
                command,
                state,
                config,
                rngContext,
                logging.Logger
            );
        }

        // Fallback to generic implementation
        logging.LogDebug("Using generic INITIALIZE UPDATE processor");
        return ParseInitializeUpdateCommand(command)
            .Bind(request => ValidateInitializeUpdatePreconditions(request, state))
            .Bind(request => GenerateCardChallengeForRequest(request, state, config, rngContext))
            .Bind(data => CalculateInitializeUpdateCryptogram(data, state, config, rngContext))
            .Map(result => CreateInitializeUpdateResult(result, state, config));
    }

    /// <summary>
    /// Processes an EXTERNAL AUTHENTICATE command to complete secure channel establishment.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessExternalAuthenticate(
        byte[] command,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext,
        LoggingService logging
    )
    {
        logging.LogDebug("Processing EXTERNAL AUTHENTICATE");
        logging.LogDebug("MAIN ProcessExternalAuthenticate called");
        logging.LogDebug("Command: {Command}", Convert.ToHexString(command));
        logging.LogDebug("State SCP Version: 0x{ScpVersion:X2}", state.ScpVersion);

        // Delegate to protocol-specific processors
        var logger = logging.Logger.Match(
            l => l,
            () => Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance
        );
        bool isScp02 = Scp02CommandProcessors.IsScp02Command(command, state, logger);
        bool isScp03 = Scp03CommandProcessors.IsScp03Command(command, state);

        logging.LogDebug("IsScp02Command: {IsScp02}", isScp02);
        logging.LogDebug("IsScp03Command: {IsScp03}", isScp03);

        if (isScp02)
        {
            logging.LogDebug("Routing to SCP02 external authenticate processor");
            logging.LogDebug("Routing to SCP02 external authenticate processor");
            return Scp02CommandProcessors.ProcessScp02ExternalAuthenticate(
                command,
                state,
                config,
                rngContext,
                logging
            );
        }
        if (isScp03)
        {
            logging.LogDebug("Routing to SCP03 external authenticate processor");
            logging.LogDebug("Routing to SCP03 external authenticate processor");
            return Scp03CommandProcessors.ProcessScp03ExternalAuthenticate(
                command,
                state,
                config,
                rngContext,
                logging
            );
        }

        // Fallback to generic implementation
        return ParseExternalAuthenticateCommand(command)
            .Bind(request => ValidateExternalAuthenticatePreconditions(request, state))
            .Bind(request => VerifyHostCryptogram(request, state, config, rngContext))
            .Bind(request => DeriveSessionKeys(request, state, config, rngContext))
            .Map(sessionKeys => CreateExternalAuthenticateResult(sessionKeys, state));
    }

    /// <summary>
    /// Processes a GET DATA command to retrieve card data objects.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessGetData(
        byte[] command,
        CardState state,
        CardConfiguration config,
        LoggingService logging
    )
    {
        logging.LogDebug("Processing GET DATA command");
        return ParseGetDataCommand(command)
            .Bind(tag => ValidateGetDataAccess(tag, state))
            .Bind(tag => RetrieveDataObject(tag, state, config))
            .Map(data =>
                (new ApduResponse(data, Gp4Net.Constants.Constants.StatusWords.Success), state)
            );
    }

    /// <summary>
    /// Processes a GET STATUS command to retrieve application/load file status.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessGetStatus(
        byte[] command,
        CardState state,
        CardConfiguration config,
        LoggingService logging
    )
    {
        logging.LogDebug("Processing GET STATUS command");
        return ParseGetStatusCommand(command)
            .Bind(request => ValidateGetStatusAccess(request, state))
            .Bind(request => RetrieveStatusData(request, state, config))
            .Map(data =>
                (new ApduResponse(data, Gp4Net.Constants.Constants.StatusWords.Success), state)
            );
    }

    // Helper methods for command parsing and validation

    /// <summary>
    /// Parses SELECT command per GlobalPlatform Card Specification v2.3.1 Section 11.1.1.
    /// Command format: CLA INS P1 P2 [Lc [AID] [Le]]
    /// </summary>
    private static Result<byte[], SmartCardError> ParseSelectCommand(byte[] command)
    {
        if (command.Length < 4)
        {
            return Result.Failure<byte[], SmartCardError>(SmartCardError.WrongLength());
        }

        // GlobalPlatform Card Specification v2.3.1 Section 11.1.4, Table 11-11
        // Accept CLA '00'-'03' (ISO) and '40'-'4F' (GP)
        byte cla = command[0];
        byte ins = command[1];

        if (ins != 0xA4)
        {
            return Result.Failure<byte[], SmartCardError>(SmartCardError.InstructionNotSupported());
        }

        if (!IsValidSelectCla(cla))
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.Unsupported("Class not supported")
            );
        }

        switch (command.Length)
        {
            // Handle SELECT with no data (select by default)
            case 4:
                return Result.Success<byte[], SmartCardError>([]);
            case < 5:
                return Result.Failure<byte[], SmartCardError>(SmartCardError.WrongLength());
        }

        byte lc = command[4];

        // Command can be 5+Lc (no Le) or 5+Lc+1 (with Le)
        if (command.Length != 5 + lc && command.Length != 5 + lc + 1)
        {
            return Result.Failure<byte[], SmartCardError>(SmartCardError.WrongLength());
        }

        byte[] aid = command.Skip(5).Take(lc).ToArray();
        return Result.Success<byte[], SmartCardError>(aid);
    }

    private static Result<byte[], SmartCardError> ValidateSelectAid(
        byte[] aid,
        CardConfiguration config
    )
    {
        // Empty AID means select default (ISD)
        if (aid.Length == 0)
        {
            return Result.Success<byte[], SmartCardError>(config.IsdAid);
        }

        // Check if it's the configured ISD AID
        if (aid.SequenceEqual(config.IsdAid))
        {
            return Result.Success<byte[], SmartCardError>(aid);
        }

        // Also accept standard GlobalPlatform ISD AIDs for compatibility per GP Card Specification v2.3.1
        byte[][] standardIsdAids =
        [
            Convert.FromHexString("A000000003000000"), // Standard GP ISD
            Convert.FromHexString("A000000151000000"), // Common alternative
            Convert.FromHexString("A000000018434D00"), // Another common variant
        ];

        return standardIsdAids.Any(standardAid => aid.SequenceEqual(standardAid))
            ? Result.Success<byte[], SmartCardError>(aid)
            : Result.Failure<byte[], SmartCardError>(SmartCardError.FileNotFound());
    }

    private static ApduResponse CreateSelectResponse(byte[] aid, CardConfiguration config)
    {
        // GlobalPlatform Card Specification v2.3.1 Table 11-82: FCI must reflect actual selected AID
        // Create FCI template with dynamic AID per GP specification requirements
        byte aidLength = (byte)aid.Length;
        byte[] fciData = new byte[6 + aidLength + 6];
        int offset = 0;

        // FCI Template (tag 6F)
        fciData[offset++] = 0x6F;
        fciData[offset++] = (byte)(4 + aidLength + 6); // Length of FCI content

        // DF Name (tag 84) - Contains the actual selected AID
        fciData[offset++] = 0x84;
        fciData[offset++] = aidLength;
        Array.Copy(aid, 0, fciData, offset, aidLength);
        offset += aidLength;

        // FCI Proprietary Template (tag A5) - Contains application-specific data
        fciData[offset++] = 0xA5;
        fciData[offset++] = 0x04; // Length of proprietary template
        fciData[offset++] = 0x9F;
        fciData[offset++] = 0x65;
        fciData[offset++] = 0x01;
        fciData[offset++] = 0x00; // Maximum length of data field in command message

        return new ApduResponse(fciData, Gp4Net.Constants.Constants.StatusWords.Success);
    }

    private static Result<InitializeUpdateRequest, SmartCardError> ParseInitializeUpdateCommand(
        byte[] command
    )
    {
        if (command.Length < 13) // CLA INS P1 P2 LC + 8 bytes challenge
            return Result.Failure<InitializeUpdateRequest, SmartCardError>(
                SmartCardError.WrongLength()
            );

        if (command[0] != 0x80 || command[1] != 0x50)
            return Result.Failure<InitializeUpdateRequest, SmartCardError>(
                SmartCardError.InstructionNotSupported()
            );

        byte keyVersion = command[2];
        byte keyIdentifier = command[3];
        byte lc = command[4];

        if (lc != 8)
            return Result.Failure<InitializeUpdateRequest, SmartCardError>(
                SmartCardError.WrongLength()
            );

        // Accept both Case 3 (13 bytes: CLA INS P1 P2 LC + 8 bytes) and Case 4 (14 bytes: + Le)
        if (command.Length != 13 && command.Length != 14)
            return Result.Failure<InitializeUpdateRequest, SmartCardError>(
                SmartCardError.WrongLength()
            );

        byte[] hostChallenge = command.Skip(5).Take(8).ToArray();

        return Result.Success<InitializeUpdateRequest, SmartCardError>(
            new InitializeUpdateRequest(keyVersion, keyIdentifier, hostChallenge)
        );
    }

    private static Result<
        InitializeUpdateRequest,
        SmartCardError
    > ValidateInitializeUpdatePreconditions(InitializeUpdateRequest request, CardState state)
    {
        if (!state.IsSelected)
            return Result.Failure<InitializeUpdateRequest, SmartCardError>(
                SmartCardError.ConditionsNotSatisfied()
            );

        return Result.Success<InitializeUpdateRequest, SmartCardError>(request);
    }

    private static Result<
        (InitializeUpdateRequest, byte[]),
        SmartCardError
    > GenerateCardChallengeForRequest(
        InitializeUpdateRequest request,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        if (!rngContext.HasEnoughEntropy(16))
        {
            return Result.Failure<(InitializeUpdateRequest, byte[]), SmartCardError>(
                SmartCardError.SecurityError("Insufficient entropy for card challenge")
            );
        }

        switch (state.ScpVersion)
        {
            // SCP03 Amendment D v1.1.2, Table 5-1: b5 selects pseudo-random challenge generation.
            case 0x03 when state.ScpImplementation.UsesScp03PseudoRandomChallenge():
                return GeneratePseudoRandomChallenge(request, state, config, rngContext);
            case 0x02:
            {
                // SCP02: Generate 6-byte random challenge and combine with 2-byte sequence counter
                byte[] sequenceCounter = state.GetSequenceCounter(request.KeyVersion);
                return rngContext
                    .GenerateBytes(6)
                    .Map(randomChallenge =>
                    {
                        // Combine sequence counter + random challenge for 8-byte total
                        byte[] fullChallenge = new byte[8];
                        Array.Copy(sequenceCounter, 0, fullChallenge, 0, 2);
                        Array.Copy(randomChallenge, 0, fullChallenge, 2, 6);
                        return (request, fullChallenge);
                    });
            }
            default:
                // SCP03: Standard 8-byte random challenge generation
                return rngContext.GenerateBytes(8).Map(challenge => (request, challenge));
        }
    }

    private static Result<
        (InitializeUpdateRequest, byte[]),
        SmartCardError
    > GeneratePseudoRandomChallenge(
        InitializeUpdateRequest request,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        // Get the keyset for the requested key version
        var keySet = state.InstalledKeys.TryGetValue(request.KeyVersion, out var keys)
            ? keys
            : config.StaticKeys.TryGetValue(request.KeyVersion, out var staticKeys)
                ? staticKeys
                : config.StaticKeys.Values.FirstOrDefault();

        if (keySet is not Scp03KeySet scp03Keys)
        {
            return SmartCardError.InvalidArgument(
                "SCP03 pseudo-random challenge requires SCP03 keys"
            );
        }

        // Get sequence counter for this key version
        byte[] sequenceCounter = state.GetSequenceCounter(request.KeyVersion);

        // Use the ISD AID for challenge generation
        byte[] aid = config.IsdAid;

        // SCP03 pseudo-random challenge derivation per GP SCP03 Amendment D
        // KDF context: sequence counter || ISD AID, derived using S-ENC and derivation constant 0x02
        byte[] context = sequenceCounter.Concat(aid).ToArray();

        return CryptoService
            .KeyDerivation.DeriveScp03Data(scp03Keys.EncKey, 0x02, context, 64)
            .Map(challenge => (request, challenge));
    }

    private static Result<InitializeUpdateData, SmartCardError> CalculateInitializeUpdateCryptogram(
        (InitializeUpdateRequest request, byte[] cardChallenge) data,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        (var request, byte[] cardChallenge) = data;

        // Determine the effective key version to use
        byte effectiveKeyVersion = request.KeyVersion;
        if (effectiveKeyVersion == 0x00)
        {
            // Use default key version when 0x00 is specified
            effectiveKeyVersion = state.DefaultKeyVersion;
            if (effectiveKeyVersion == 0xFF) // No default set, use first available
            {
                effectiveKeyVersion = config.StaticKeys.Keys.Any()
                    ? config.StaticKeys.Keys.First()
                    : (byte)0xFF;
            }
        }

        // Get the appropriate keys
        var installedKeySet = state.InstalledKeys.ContainsKey(effectiveKeyVersion)
            ? Maybe<IKeySet>.From(state.InstalledKeys[effectiveKeyVersion])
            : Maybe<IKeySet>.None;
        var staticKeySet = config.StaticKeys.ContainsKey(effectiveKeyVersion)
            ? Maybe<IKeySet>.From(config.StaticKeys[effectiveKeyVersion])
            : Maybe<IKeySet>.None;

        var fallbackKeySet = config.StaticKeys.Values.Any()
            ? Maybe<IKeySet>.From(config.StaticKeys.Values.First())
            : Maybe<IKeySet>.None;

        var keySetResult = installedKeySet
            .ToResult(SmartCardError.ReferencedDataNotFound())
            .Match(
                success => Result.Success<IKeySet, SmartCardError>(success),
                _ =>
                    staticKeySet
                        .ToResult(SmartCardError.ReferencedDataNotFound())
                        .Match(
                            success => Result.Success<IKeySet, SmartCardError>(success),
                            _ => fallbackKeySet.ToResult(SmartCardError.ReferencedDataNotFound())
                        )
            );

        if (keySetResult.IsFailure)
            return Result.Failure<InitializeUpdateData, SmartCardError>(keySetResult.Error);

        var keys = keySetResult.Value;
        if (installedKeySet.HasNoValue && staticKeySet.HasNoValue && fallbackKeySet.HasValue)
        {
            effectiveKeyVersion = keys.KeyVersion;
        }

        // For SCP02, we need to pass the sequence counter separately
        var sequenceCounter = Maybe<byte[]>.None;
        if (state.ScpVersion == 0x02)
        {
            // SCP02: cardChallenge should be 8 bytes (2 byte seq + 6 byte random)
            // Extract the sequence counter
            if (cardChallenge.Length == 8)
            {
                sequenceCounter = Maybe<byte[]>.From(cardChallenge.Take(2).ToArray());
                byte[] randomPart = cardChallenge.Skip(2).Take(6).ToArray();

                // Calculate card cryptogram using unified crypto service
                return Cryptogram
                    .CalculateCardCryptogram(
                        request.HostChallenge,
                        randomPart,
                        keys,
                        state.ScpVersion,
                        (byte)state.ScpImplementation,
                        sequenceCounter
                    )
                    .Map(cryptogram => new InitializeUpdateData(
                        effectiveKeyVersion,
                        state.ScpVersion,
                        (byte)state.ScpImplementation,
                        cardChallenge, // Store the full 8-byte challenge
                        cryptogram,
                        request.HostChallenge,
                        keys
                    ));
            }
            return SmartCardError.InvalidArgument(
                $"SCP02 requires 8-byte card challenge, got {cardChallenge.Length}"
            );
        }

        // SCP03: cardChallenge is 8 bytes of random data
        // Calculate card cryptogram using unified crypto service
        return Cryptogram
            .CalculateCardCryptogram(
                request.HostChallenge,
                cardChallenge,
                keys,
                state.ScpVersion,
                (byte)state.ScpImplementation,
                Maybe<byte[]>.None
            )
            .Map(cryptogram => new InitializeUpdateData(
                effectiveKeyVersion,
                state.ScpVersion,
                (byte)state.ScpImplementation,
                cardChallenge,
                cryptogram,
                request.HostChallenge,
                keys
            ));
    }

    private static (ApduResponse, CardState) CreateInitializeUpdateResult(
        InitializeUpdateData data,
        CardState state,
        CardConfiguration config
    )
    {
        // Build INITIALIZE UPDATE response
        byte[] response = new byte[32]; // Typical SCP response length
        int offset = 0;

        // Key diversification data (10 bytes)
        Array.Fill<byte>(response, 0x00, offset, 10);
        offset += 10;

        // Key information (3 bytes)
        response[offset++] = data.KeyVersion;

        // For SCP03, combine version and implementation into single byte
        if (data.ScpVersion == 0x03)
        {
            response[offset++] = (byte)(data.ScpVersion | data.ScpImplementation); // e.g., 0x03 | 0x70 = 0x73
            response[offset++] = 0x00; // Padding for SCP03
        }
        else
        {
            // For SCP02, use separate bytes
            response[offset++] = data.ScpVersion;
            response[offset++] = data.ScpImplementation;
        }

        // Card challenge (8 bytes)
        Array.Copy(data.CardChallenge, 0, response, offset, 8);
        offset += 8;

        // Card cryptogram (8 bytes)
        Array.Copy(data.CardCryptogram, 0, response, offset, 8);
        offset += 8;

        // Sequence counter for SCP03 (3 bytes)
        var newState = state;
        if (data.ScpVersion == 0x03)
        {
            byte[] sequenceCounter = state.GetSequenceCounter(data.KeyVersion);
            Array.Copy(sequenceCounter, 0, response, offset, 3);
            offset += 3;

            // Increment sequence counter if pseudo-random challenges are used (i=70)
            if ((data.ScpImplementation & 0xF0) == 0x70)
            {
                newState = newState.WithIncrementedSequenceCounter(data.KeyVersion);
            }
        }

        byte[] actualResponse = new byte[offset];
        Array.Copy(response, actualResponse, offset);

        newState = newState
            .WithChallenges(
                Maybe<byte[]>.From(data.HostChallenge),
                Maybe<byte[]>.From(data.CardChallenge)
            )
            .WithKeys(data.Keys);

        return (
            new ApduResponse(actualResponse, Gp4Net.Constants.Constants.StatusWords.Success),
            newState
        );
    }

    // Additional helper records for command data

    private record InitializeUpdateData(
        byte KeyVersion,
        byte ScpVersion,
        byte ScpImplementation,
        byte[] CardChallenge,
        byte[] CardCryptogram,
        byte[] HostChallenge,
        IKeySet Keys
    );

    // External Authenticate command implementation
    private static Result<
        ExternalAuthenticateRequest,
        SmartCardError
    > ParseExternalAuthenticateCommand(byte[] command)
    {
        if (command.Length < 5)
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                SmartCardError.WrongLength()
            );

        if (command[0] != 0x84 || command[1] != 0x82)
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                SmartCardError.InstructionNotSupported()
            );

        byte securityLevel = command[2];
        byte p2 = command[3];
        byte lc = command[4];

        // For SCP02, expect 16 bytes (8 byte cryptogram + 8 byte MAC)
        // For SCP03, expect 16 bytes (8 byte cryptogram + 8 byte MAC)
        if (lc != 16 || command.Length != 21)
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                SmartCardError.WrongLength()
            );

        byte[] hostCryptogram = command.Skip(5).Take(8).ToArray();
        byte[] hostMac = command.Skip(13).Take(8).ToArray();

        return Result.Success<ExternalAuthenticateRequest, SmartCardError>(
            new ExternalAuthenticateRequest(securityLevel, hostCryptogram, hostMac)
        );
    }

    private static Result<
        ExternalAuthenticateRequest,
        SmartCardError
    > ValidateExternalAuthenticatePreconditions(
        ExternalAuthenticateRequest request,
        CardState state
    )
    {
        if (!state.IsSelected)
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                SmartCardError.ConditionsNotSatisfied()
            );

        if (state.HostChallenge.HasNoValue || state.CardChallenge.HasNoValue)
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                SmartCardError.ConditionsNotSatisfied()
            );

        if (state.CurrentKeys.HasNoValue)
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                SmartCardError.ConditionsNotSatisfied()
            );

        return Result.Success<ExternalAuthenticateRequest, SmartCardError>(request);
    }

    private static Result<ExternalAuthenticateRequest, SmartCardError> VerifyHostCryptogram(
        ExternalAuthenticateRequest request,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        if (
            state.HostChallenge.HasNoValue
            || state.CardChallenge.HasNoValue
            || state.CurrentKeys.HasNoValue
        )
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                SmartCardError.ConditionsNotSatisfied()
            );

        return state.HostChallenge.Match(
            hostChallenge =>
                state.CardChallenge.Match(
                    cardChallenge =>
                        state.CurrentKeys.Match(
                            currentKeys =>
                                PerformCryptogramVerification(
                                    request,
                                    hostChallenge,
                                    cardChallenge,
                                    currentKeys,
                                    state,
                                    rngContext
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
                ),
            () =>
                Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                    SmartCardError.ConditionsNotSatisfied()
                )
        );
    }

    private static Result<
        ExternalAuthenticateRequest,
        SmartCardError
    > PerformCryptogramVerification(
        ExternalAuthenticateRequest request,
        byte[] hostChallenge,
        byte[] cardChallenge,
        IKeySet currentKeys,
        CardState state,
        IRngContext rngContext
    )
    {
        // For SCP02, extract sequence counter from card challenge
        (var sequenceCounter, byte[] cardChallengeForCrypto) =
            state.ScpVersion == 0x02
                ? ExtractScp02Components(cardChallenge)
                : (Maybe<byte[]>.None, cardChallenge);

        if (state.ScpVersion == 0x02 && cardChallenge.Length != 8)
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                SmartCardError.InvalidArgument(
                    $"SCP02 requires 8-byte card challenge, got {cardChallenge.Length}"
                )
            );

        return Cryptogram
            .CalculateHostCryptogram(
                hostChallenge,
                cardChallengeForCrypto,
                currentKeys,
                state.ScpVersion,
                (byte)state.ScpImplementation,
                sequenceCounter
            )
            .Bind(expectedCryptogram =>
                CryptoService.Utils.CompareBytes(request.HostCryptogram, expectedCryptogram)
                    ? Result.Success<bool, SmartCardError>(true)
                    : Result.Failure<bool, SmartCardError>(
                        SmartCardError.AuthenticationFailed("Host cryptogram verification failed")
                    )
            )
            .Bind(verified =>
                verified
                    ? Result.Success<ExternalAuthenticateRequest, SmartCardError>(request)
                    : Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                        SmartCardError.SecurityStatusNotSatisfied()
                    )
            );
    }

    private static (
        Maybe<byte[]> sequenceCounter,
        byte[] cardChallengeForCrypto
    ) ExtractScp02Components(byte[] cardChallenge)
    {
        if (cardChallenge.Length == 8)
        {
            var sequenceCounter = Maybe<byte[]>.From(cardChallenge.Take(2).ToArray());
            byte[] cardChallengeForCrypto = cardChallenge.Skip(2).Take(6).ToArray();
            return (sequenceCounter, cardChallengeForCrypto);
        }
        return (Maybe<byte[]>.None, cardChallenge);
    }

    private static Result<SessionKeys, SmartCardError> DeriveSessionKeys(
        ExternalAuthenticateRequest request,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        return state
            .HostChallenge.ToResult(SmartCardError.ConditionsNotSatisfied())
            .Bind(hostChallenge =>
                state
                    .CardChallenge.ToResult(SmartCardError.ConditionsNotSatisfied())
                    .Bind(cardChallenge =>
                        state
                            .CurrentKeys.ToResult(SmartCardError.ConditionsNotSatisfied())
                            .Bind(currentKeys =>
                                CreateKeyDerivationContext(
                                        currentKeys,
                                        hostChallenge,
                                        cardChallenge,
                                        state.ScpVersion,
                                        state.ScpImplementation
                                    )
                                    .Bind(CryptoService.KeyDerivation.DeriveSessionKeys)
                            )
                    )
            );
    }

    private static Result<IKeyDerivationContext, SmartCardError> CreateKeyDerivationContext(
        IKeySet keys,
        byte[] hostChallenge,
        byte[] cardChallenge,
        byte scpVersion,
        ScpImplementation implementation
    )
    {
        return scpVersion == 0x02
            ? KeyDerivationContext
                .CreateForScp02(
                    keys,
                    hostChallenge,
                    cardChallenge,
                    cardChallenge.Take(2).ToArray(), // sequence counter from card challenge
                    implementation
                )
                .Map(context => (IKeyDerivationContext)context)
            : KeyDerivationContext
                .CreateForScp03(keys, hostChallenge, cardChallenge, implementation)
                .Map(context => (IKeyDerivationContext)context);
    }

    private static (ApduResponse, CardState) CreateExternalAuthenticateResult(
        SessionKeys sessionKeys,
        CardState state
    )
    {
        // Create functional secure channel state
        var securityLevel = (SecurityLevel)0x01; // Basic security level
        var secureChannelStateResult = SecureChannelState.Create(
            sessionKeys: sessionKeys,
            securityLevel: securityLevel,
            protocolVersion: ScpVersion.Scp02, // Default to SCP02
            initialMacChainingValue: new byte[8], // Initialize with zeros
            implementationParameter: 0x00
        );

        if (secureChannelStateResult.IsFailure)
        {
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

        // Update state with established secure channel
        var newState = state.WithSecureChannel(secureChannelState);

        // EXTERNAL AUTHENTICATE response is typically empty on success
        return (new ApduResponse([], Gp4Net.Constants.Constants.StatusWords.Success), newState);
    }

    // Placeholder implementations for other commands
    private static Result<ushort, SmartCardError> ParseGetDataCommand(byte[] command)
    {
        // GET DATA command format: CLA INS P1 P2 [Le]
        // P1P2 contains the tag (2 bytes)
        if (command.Length < 4)
            return Result.Failure<ushort, SmartCardError>(SmartCardError.WrongLength());

        ushort tag = (ushort)(command[2] << 8 | command[3]);
        return Result.Success<ushort, SmartCardError>(tag);
    }

    private static Result<ushort, SmartCardError> ValidateGetDataAccess(ushort tag, CardState state)
    {
        // For now, allow access to all data objects regardless of authentication state
        // In a real implementation, some objects might require secure channel
        return Result.Success<ushort, SmartCardError>(tag);
    }

    private static Result<byte[], SmartCardError> RetrieveDataObject(
        ushort tag,
        CardState state,
        CardConfiguration config
    )
    {
        // Check if this tag exists in the card configuration
        if (config.DefaultDataObjects.TryGetValue(tag, out byte[]? data) && data is not null)
        {
            return Result.Success<byte[], SmartCardError>(data);
        }

        // Check if this tag exists in the card state
        if (state.DataObjects.TryGetValue(tag, out byte[]? stateData) && stateData is not null)
        {
            return Result.Success<byte[], SmartCardError>(stateData);
        }

        return Result.Failure<byte[], SmartCardError>(SmartCardError.ReferencedDataNotFound());
    }

    /// <summary>
    /// Parses GET STATUS command per GlobalPlatform Card Specification v2.3.1 Section 11.4.
    /// </summary>
    private static Result<GetStatusRequest, SmartCardError> ParseGetStatusCommand(byte[] command)
    {
        // GlobalPlatform Card Specification v2.3.1 Table 11-32: GET STATUS Command Message
        if (command.Length < 4)
            return Result.Failure<GetStatusRequest, SmartCardError>(SmartCardError.WrongLength());

        byte p1 = command[2]; // Reference control parameter - Table 11-33
        byte p2 = command[3]; // Reference control parameter - Table 11-34

        // Validate P1 parameter per Table 11-33
        var requestType = p1 switch
        {
            0x80 => StatusRequestType.IssuerSecurityDomain,
            0x40 => StatusRequestType.Applications,
            0x20 => StatusRequestType.ExecutableLoadFiles,
            0x10 => StatusRequestType.ExecutableModules,
            _ => StatusRequestType.Applications, // Default for invalid P1
        };

        // P2 contains format and criteria information per Table 11-34
        bool includeTaggedFormat = (p2 & 0x02) != 0;

        return Result.Success<GetStatusRequest, SmartCardError>(
            new GetStatusRequest(requestType, p2, includeTaggedFormat)
        );
    }

    /// <summary>
    /// Validates GET STATUS access per GlobalPlatform Card Specification v2.3.1 Table 11-2.
    /// GET STATUS requires AUTHENTICATED security level.
    /// </summary>
    private static Result<GetStatusRequest, SmartCardError> ValidateGetStatusAccess(
        GetStatusRequest request,
        CardState state
    )
    {
        // Per GP Table 11-2: GET STATUS requires AUTHENTICATED security level
        if (state.SecurityLevel < 0x01) // AUTHENTICATED = 0x01
            return Result.Failure<GetStatusRequest, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied()
            );

        return Result.Success<GetStatusRequest, SmartCardError>(request);
    }

    /// <summary>
    /// Retrieves status data per GlobalPlatform Card Specification v2.3.1 Section 11.4.
    /// </summary>
    private static Result<byte[], SmartCardError> RetrieveStatusData(
        GetStatusRequest request,
        CardState state,
        CardConfiguration config
    )
    {
        // GlobalPlatform Card Specification v2.3.1 Table 11-36: GET STATUS Response Data Field
        return request.RequestType switch
        {
            StatusRequestType.IssuerSecurityDomain => RetrieveIsdStatus(state, config),
            StatusRequestType.Applications => RetrieveApplicationStatus(state, config),
            StatusRequestType.ExecutableLoadFiles => RetrieveLoadFileStatus(state, config),
            StatusRequestType.ExecutableModules => RetrieveModuleStatus(state, config),
            _ => Result.Failure<byte[], SmartCardError>(SmartCardError.IncorrectP1P2()),
        };
    }

    /// <summary>
    /// Retrieves Issuer Security Domain status per GP specification.
    /// </summary>
    private static Result<byte[], SmartCardError> RetrieveIsdStatus(
        CardState state,
        CardConfiguration config
    )
    {
        // ISD status: AID (5-16 bytes) + Life Cycle State (1 byte) + Privileges (1 byte)
        byte[] isdAid = config.IsdAid;
        byte lifecycleState = 0x07; // SELECTABLE per GP Card Specification Table 11-1
        byte privileges = 0x81; // Security Domain + Authorized Management + Personalized per Table 8-1

        byte[] statusData = isdAid.Concat([lifecycleState, privileges]).ToArray();

        return Result.Success<byte[], SmartCardError>(statusData);
    }

    /// <summary>
    /// Retrieves installed applications status per GP specification.
    /// </summary>
    private static Result<byte[], SmartCardError> RetrieveApplicationStatus(
        CardState state,
        CardConfiguration config
    )
    {
        // Return applications in TLV format per GP Table 11-36
        byte[] responseData = state
            .Applications.Values.SelectMany(app =>
                app.Aid.Concat([app.LifecycleState, (byte)app.Privileges])
            )
            .ToArray();

        return Result.Success<byte[], SmartCardError>(responseData);
    }

    /// <summary>
    /// Retrieves load file status per GP specification.
    /// </summary>
    private static Result<byte[], SmartCardError> RetrieveLoadFileStatus(
        CardState state,
        CardConfiguration config
    )
    {
        byte[] responseData = state
            .LoadFiles.SelectMany(loadFile =>
                loadFile
                    .Aid.Concat([loadFile.LifecycleState])
                    .Concat(loadFile.AssociatedSecurityDomainAid)
            )
            .ToArray();

        return Result.Success<byte[], SmartCardError>(responseData);
    }

    /// <summary>
    /// Retrieves executable modules status per GP specification.
    /// </summary>
    private static Result<byte[], SmartCardError> RetrieveModuleStatus(
        CardState state,
        CardConfiguration config
    )
    {
        byte[] responseData = state
            .LoadFiles.SelectMany(loadFile =>
                loadFile.ExecutableModules.SelectMany(module =>
                    module.Aid.Concat([module.LifecycleState])
                )
            )
            .ToArray();

        return Result.Success<byte[], SmartCardError>(responseData);
    }

    /// <summary>
    /// Validates SELECT command CLA per GlobalPlatform Card Specification v2.3.1 Section 11.1.4.
    /// </summary>
    private static bool IsValidSelectCla(byte cla)
    {
        // ISO CLAs: 00-03
        if (cla >= 0x00 && cla <= 0x03)
            return true;

        // GlobalPlatform CLAs: 40-4F
        if (cla >= 0x40 && cla <= 0x4F)
            return true;

        return false;
    }

    /// <summary>
    /// Status request types per GlobalPlatform Card Specification v2.3.1 Table 11-33.
    /// </summary>
    private enum StatusRequestType
    {
        IssuerSecurityDomain = 0x80,
        Applications = 0x40,
        ExecutableLoadFiles = 0x20,
        ExecutableModules = 0x10,
    }

    /// <summary>
    /// GET STATUS request parameters per GlobalPlatform Card Specification v2.3.1.
    /// </summary>
    private record GetStatusRequest(
        StatusRequestType RequestType,
        byte P2Parameter,
        bool IncludeTaggedFormat
    );
}
