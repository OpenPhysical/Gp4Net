using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Constants;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
using Gp4Net.CardEmulator.Core;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

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
        LoggingService logging)
    {
        logging.LogDebug("Processing SELECT command");
        logging.LogDebug("Virtual card processing SELECT, current IsSelected: {IsSelected}", state.IsSelected);
        
        Result<(ApduResponse, CardState), SmartCardError> result = ParseSelectCommand(command)
            .Bind(aid => 
            {
                logging.LogDebug("Virtual card SELECT parsed AID: {Aid}", Convert.ToHexString(aid));
                return ValidateSelectAid(aid, config);
            })
            .Map(aid => CreateSelectResponse(aid, config))
            .Map(response => 
            {
                CardState newState = state.WithSelected(true);
                logging.LogDebug("Virtual card SELECT success, setting IsSelected to true");
                return (response, newState);
            });
            
        if (result.IsFailure)
        {
            logging.LogDebug("Virtual card SELECT failed: {Error}", result.Error.Message);
        }
        
        return result;
    }

    /// <summary>
    /// Processes an INITIALIZE UPDATE command to start secure channel establishment.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessInitializeUpdate(
        byte[] command,
        CardState state,
        CardConfiguration config,
        CryptographicService crypto,
        LoggingService logging)
    {
        logging.LogDebug("Processing INITIALIZE UPDATE - Card SCP version: 0x{Scp:X2}", (byte)state.ScpVersion);
        
        // Delegate to protocol-specific processors
        ILogger? legacyLogger = logging.Logger.Match(l => l, () => (ILogger?)null);
        if (Scp02CommandProcessors.IsScp02Command(command, state, legacyLogger))
        {
            logging.LogDebug("Routing to SCP02 processor");
            return Scp02CommandProcessors.ProcessScp02InitializeUpdate(command, state, config, crypto, legacyLogger);
        }
        else if (Scp03CommandProcessors.IsScp03Command(command, state))
        {
            logging.LogDebug("Routing to SCP03 processor");
            return Scp03CommandProcessors.ProcessScp03InitializeUpdate(command, state, config, crypto, legacyLogger);
        }
        
        // Fallback to generic implementation
        logging.LogDebug("Using generic INITIALIZE UPDATE processor");
        return ParseInitializeUpdateCommand(command)
            .Bind(request => ValidateInitializeUpdatePreconditions(request, state))
            .Bind(request => GenerateCardChallengeForRequest(request, state, config, crypto))
            .Bind(data => CalculateInitializeUpdateCryptogram(data, state, config, crypto))
            .Map(result => CreateInitializeUpdateResult(result, state, config));
    }

    /// <summary>
    /// Processes an EXTERNAL AUTHENTICATE command to complete secure channel establishment.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessExternalAuthenticate(
        byte[] command,
        CardState state,
        CardConfiguration config,
        CryptographicService crypto,
        LoggingService logging)
    {
        logging.LogDebug("Processing EXTERNAL AUTHENTICATE");
        logging.LogDebug("MAIN ProcessExternalAuthenticate called");
        logging.LogDebug("Command: {Command}", Convert.ToHexString(command));
        logging.LogDebug("State SCP Version: 0x{ScpVersion:X2}", state.ScpVersion);
        
        // Delegate to protocol-specific processors
        bool isScp02 = Scp02CommandProcessors.IsScp02Command(command, state);
        bool isScp03 = Scp03CommandProcessors.IsScp03Command(command, state);
        
        logging.LogDebug("IsScp02Command: {IsScp02}", isScp02);
        logging.LogDebug("IsScp03Command: {IsScp03}", isScp03);
        
        if (isScp02)
        {
            logging.LogDebug("Routing to SCP02 external authenticate processor");
            logging.LogDebug("Routing to SCP02 external authenticate processor");
            return Scp02CommandProcessors.ProcessScp02ExternalAuthenticate(command, state, config, crypto, logging);
        }
        else if (isScp03)
        {
            logging.LogDebug("Routing to SCP03 external authenticate processor");
            logging.LogDebug("Routing to SCP03 external authenticate processor");
            return Scp03CommandProcessors.ProcessScp03ExternalAuthenticate(command, state, config, crypto, logging);
        }
        
        // Fallback to generic implementation
        return ParseExternalAuthenticateCommand(command)
            .Bind(request => ValidateExternalAuthenticatePreconditions(request, state))
            .Bind(request => VerifyHostCryptogram(request, state, config, crypto))
            .Bind(request => DeriveSessionKeys(request, state, config, crypto))
            .Map(sessionKeys => CreateExternalAuthenticateResult(sessionKeys, state));
    }

    /// <summary>
    /// Processes a GET DATA command to retrieve card data objects.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessGetData(
        byte[] command,
        CardState state,
        CardConfiguration config,
        LoggingService logging)
    {
        logging.LogDebug("Processing GET DATA command");
        return ParseGetDataCommand(command)
            .Bind(tag => ValidateGetDataAccess(tag, state))
            .Bind(tag => RetrieveDataObject(tag, state, config))
            .Map(data => (new ApduResponse(data, StatusWords.Success), state));
    }

    /// <summary>
    /// Processes a GET STATUS command to retrieve application/load file status.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessGetStatus(
        byte[] command,
        CardState state,
        CardConfiguration config,
        LoggingService logging)
    {
        logging.LogDebug("Processing GET STATUS command");
        return ParseGetStatusCommand(command)
            .Bind(request => ValidateGetStatusAccess(request, state))
            .Bind(request => RetrieveStatusData(request, state, config))
            .Map(data => (new ApduResponse(data, StatusWords.Success), state));
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

        if (command[0] != 0x00 || command[1] != 0xA4)
        {
            return Result.Failure<byte[], SmartCardError>(SmartCardError.InstructionNotSupported());
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

    private static Result<byte[], SmartCardError> ValidateSelectAid(byte[] aid, CardConfiguration config)
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
            Convert.FromHexString("A000000003000000"),  // Standard GP ISD
            Convert.FromHexString("A000000151000000"),  // Common alternative
            Convert.FromHexString("A000000018434D00")   // Another common variant
        ];

        return standardIsdAids.Any(standardAid => aid.SequenceEqual(standardAid))
            ? Result.Success<byte[], SmartCardError>(aid)
            : Result.Failure<byte[], SmartCardError>(SmartCardError.FileNotFound());
    }

    private static ApduResponse CreateSelectResponse(byte[] aid, CardConfiguration config)
    {
        // Return FCI template for ISD
        byte[] fciData =
        [
            0x6F, 0x10, // FCI Template
            0x84, 0x08, // DF Name
            0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, // ISD AID
            0xA5, 0x04, // FCI Proprietary Template
            0x9F, 0x65, 0x01, 0x00 // Maximum length of data field in command message
        ];
        return new ApduResponse(fciData, StatusWords.Success);
    }

    private static Result<InitializeUpdateRequest, SmartCardError> ParseInitializeUpdateCommand(byte[] command)
    {
        if (command.Length < 13) // CLA INS P1 P2 LC + 8 bytes challenge
            return Result.Failure<InitializeUpdateRequest, SmartCardError>(SmartCardError.WrongLength());

        if (command[0] != 0x80 || command[1] != 0x50)
            return Result.Failure<InitializeUpdateRequest, SmartCardError>(SmartCardError.InstructionNotSupported());

        byte keyVersion = command[2];
        byte keyIdentifier = command[3];
        byte lc = command[4];

        if (lc != 8)
            return Result.Failure<InitializeUpdateRequest, SmartCardError>(SmartCardError.WrongLength());

        // Accept both Case 3 (13 bytes: CLA INS P1 P2 LC + 8 bytes) and Case 4 (14 bytes: + Le)
        if (command.Length != 13 && command.Length != 14)
            return Result.Failure<InitializeUpdateRequest, SmartCardError>(SmartCardError.WrongLength());

        byte[] hostChallenge = command.Skip(5).Take(8).ToArray();

        return Result.Success<InitializeUpdateRequest, SmartCardError>(
            new InitializeUpdateRequest(keyVersion, keyIdentifier, hostChallenge));
    }

    private static Result<InitializeUpdateRequest, SmartCardError> ValidateInitializeUpdatePreconditions(
        InitializeUpdateRequest request, 
        CardState state)
    {
        if (!state.IsSelected)
            return Result.Failure<InitializeUpdateRequest, SmartCardError>(
                SmartCardError.ConditionsNotSatisfied());

        return Result.Success<InitializeUpdateRequest, SmartCardError>(request);
    }

    private static Result<(InitializeUpdateRequest, byte[]), SmartCardError> GenerateCardChallengeForRequest(
        InitializeUpdateRequest request,
        CardState state,
        CardConfiguration config,
        CryptographicService crypto)
    {
        switch (state.ScpVersion)
        {
            // Check if pseudo-random challenge generation is required (SCP03 i=70)
            case 0x03 when state.ScpImplementation == ScpImplementation.Scp03I70:
                // SCP03 i=70: Use pseudo-random challenge generation
                return GeneratePseudoRandomChallenge(request, state, config, crypto);
            case 0x02:
            {
                // SCP02: Generate 6-byte random challenge and combine with 2-byte sequence counter
                byte[] sequenceCounter = state.GetSequenceCounter(request.KeyVersion);
                return crypto.GenerateChallenge(6)
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
                return crypto.GenerateChallenge(8)
                    .Map(challenge => (request, challenge));
        }
    }

    private static Result<(InitializeUpdateRequest, byte[]), SmartCardError> GeneratePseudoRandomChallenge(
        InitializeUpdateRequest request,
        CardState state,
        CardConfiguration config,
        CryptographicService crypto)
    {
        // Get the keyset for the requested key version
        IKeySet? keySet = state.InstalledKeys.TryGetValue(request.KeyVersion, out IKeySet? keys) 
            ? keys 
            : config.StaticKeys.TryGetValue(request.KeyVersion, out IKeySet? staticKeys)
                ? staticKeys 
                : config.StaticKeys.Values.FirstOrDefault();

        if (keySet is not Domain.Keys.Scp03KeySet scp03Keys)
        {
            return SmartCardError.InvalidArgument("SCP03 pseudo-random challenge requires SCP03 keys");
        }

        // Get sequence counter for this key version
        byte[] sequenceCounter = state.GetSequenceCounter(request.KeyVersion);

        // Use the ISD AID for challenge generation
        byte[] aid = config.IsdAid;

        return crypto.GeneratePseudoRandomChallenge(scp03Keys.EncKey, sequenceCounter, aid, 8)
            .Map(challenge => (request, challenge));
    }

    private static Result<InitializeUpdateData, SmartCardError> CalculateInitializeUpdateCryptogram(
        (InitializeUpdateRequest request, byte[] cardChallenge) data,
        CardState state,
        CardConfiguration config,
        CryptographicService crypto)
    {
        (InitializeUpdateRequest request, byte[] cardChallenge) = data;

        // Determine the effective key version to use
        byte effectiveKeyVersion = request.KeyVersion;
        if (effectiveKeyVersion == 0x00)
        {
            // Use default key version when 0x00 is specified
            effectiveKeyVersion = state.DefaultKeyVersion;
            if (effectiveKeyVersion == 0xFF) // No default set, use first available
            {
                effectiveKeyVersion = config.StaticKeys.Keys.FirstOrDefault();
            }
        }

        // Get the appropriate keys - check installed keys first, then static keys
        Domain.Keys.IKeySet? keys = null;
        if (state.InstalledKeys.TryGetValue(effectiveKeyVersion, out IKeySet? installedKeys))
        {
            keys = installedKeys;
        }
        else if (!config.StaticKeys.TryGetValue(effectiveKeyVersion, out IKeySet? staticKeys))
        {
            // Not found in either, try to get any available key
            keys = config.StaticKeys.Values.FirstOrDefault();
            if (keys is null)
                return Result.Failure<InitializeUpdateData, SmartCardError>(
                    SmartCardError.ReferencedDataNotFound());
            effectiveKeyVersion = keys.KeyVersion;
        }
        else
        {
            keys = staticKeys;
        }

        if (keys is null)
            return Result.Failure<InitializeUpdateData, SmartCardError>(
                SmartCardError.ReferencedDataNotFound());

        // For SCP02, we need to pass the sequence counter separately
        byte[]? sequenceCounter = null;
        if (state.ScpVersion == 0x02)
        {
            // SCP02: cardChallenge should be 8 bytes (2 byte seq + 6 byte random)
            // Extract the sequence counter
            if (cardChallenge.Length == 8)
            {
                sequenceCounter = cardChallenge.Take(2).ToArray();
                byte[] randomPart = cardChallenge.Skip(2).Take(6).ToArray();
                
                return crypto.CalculateCardCryptogram(
                        request.HostChallenge, 
                        randomPart,  // 6-byte random part
                        keys, 
                        state.ScpVersion,
                        (byte)state.ScpImplementation,
                        sequenceCounter)  // 2-byte sequence counter
                    .Map(cryptogram => new InitializeUpdateData(
                        effectiveKeyVersion,
                        state.ScpVersion,
                        (byte)state.ScpImplementation,
                        cardChallenge,  // Store the full 8-byte challenge
                        cryptogram,
                        request.HostChallenge,
                        keys));
            }
            else
            {
                return SmartCardError.InvalidArgument($"SCP02 requires 8-byte card challenge, got {cardChallenge.Length}");
            }
        }
        else
        {
            // SCP03: cardChallenge is 8 bytes of random data
            return crypto.CalculateCardCryptogram(
                    request.HostChallenge, 
                    cardChallenge, 
                    keys, 
                    state.ScpVersion,
                    (byte)state.ScpImplementation,
                    null)  // No sequence counter for SCP03
                .Map(cryptogram => new InitializeUpdateData(
                    effectiveKeyVersion,
                    state.ScpVersion,
                    (byte)state.ScpImplementation,
                    cardChallenge,
                    cryptogram,
                    request.HostChallenge,
                    keys));
        }
    }

    private static (ApduResponse, CardState) CreateInitializeUpdateResult(
        InitializeUpdateData data,
        CardState state,
        CardConfiguration config)
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
        CardState newState = state;
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
            .WithChallenges(data.HostChallenge, data.CardChallenge)
            .WithKeys(data.Keys);

        return (new ApduResponse(actualResponse, StatusWords.Success), newState);
    }

    // Additional helper records for command data
    private record InitializeUpdateRequest(byte KeyVersion, byte KeyIdentifier, byte[] HostChallenge);
    private record InitializeUpdateData(
        byte KeyVersion, 
        byte ScpVersion, 
        byte ScpImplementation,
        byte[] CardChallenge, 
        byte[] CardCryptogram,
        byte[] HostChallenge,
        Domain.Keys.IKeySet Keys);

    // External Authenticate command implementation
    private static Result<ExternalAuthenticateRequest, SmartCardError> ParseExternalAuthenticateCommand(byte[] command)
    {
        if (command.Length < 5)
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(SmartCardError.WrongLength());

        if (command[0] != 0x84 || command[1] != 0x82)
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(SmartCardError.InstructionNotSupported());

        byte securityLevel = command[2];
        byte p2 = command[3];
        byte lc = command[4];

        // For SCP02, expect 16 bytes (8 byte cryptogram + 8 byte MAC)
        // For SCP03, expect 16 bytes (8 byte cryptogram + 8 byte MAC)
        if (lc != 16 || command.Length != 21)
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(SmartCardError.WrongLength());

        byte[] hostCryptogram = command.Skip(5).Take(8).ToArray();
        byte[] hostMac = command.Skip(13).Take(8).ToArray();

        return Result.Success<ExternalAuthenticateRequest, SmartCardError>(
            new ExternalAuthenticateRequest(securityLevel, hostCryptogram, hostMac));
    }

    private static Result<ExternalAuthenticateRequest, SmartCardError> ValidateExternalAuthenticatePreconditions(
        ExternalAuthenticateRequest request, CardState state)
    {
        if (!state.IsSelected)
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                SmartCardError.ConditionsNotSatisfied());

        if (state.HostChallenge.HasNoValue || state.CardChallenge.HasNoValue)
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                SmartCardError.ConditionsNotSatisfied());

        if (state.CurrentKeys.HasNoValue)
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                SmartCardError.ConditionsNotSatisfied());

        return Result.Success<ExternalAuthenticateRequest, SmartCardError>(request);
    }

    private static Result<ExternalAuthenticateRequest, SmartCardError> VerifyHostCryptogram(
        ExternalAuthenticateRequest request, CardState state, CardConfiguration config, CryptographicService crypto)
    {
        if (state.HostChallenge.HasNoValue || state.CardChallenge.HasNoValue || state.CurrentKeys.HasNoValue)
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                SmartCardError.ConditionsNotSatisfied());

        return state.HostChallenge.Match(
            hostChallenge => state.CardChallenge.Match(
                cardChallenge => state.CurrentKeys.Match(
                    currentKeys => PerformCryptogramVerification(request, hostChallenge, cardChallenge, currentKeys, state, crypto),
                    () => Result.Failure<ExternalAuthenticateRequest, SmartCardError>(SmartCardError.ConditionsNotSatisfied())
                ),
                () => Result.Failure<ExternalAuthenticateRequest, SmartCardError>(SmartCardError.ConditionsNotSatisfied())
            ),
            () => Result.Failure<ExternalAuthenticateRequest, SmartCardError>(SmartCardError.ConditionsNotSatisfied())
        );
    }

    private static Result<ExternalAuthenticateRequest, SmartCardError> PerformCryptogramVerification(
        ExternalAuthenticateRequest request, 
        byte[] hostChallenge,
        byte[] cardChallenge,
        IKeySet currentKeys,
        CardState state,
        CryptographicService crypto)
    {
        // For SCP02, extract sequence counter from card challenge
        (Maybe<byte[]> sequenceCounter, byte[] cardChallengeForCrypto) = state.ScpVersion == 0x02
            ? ExtractScp02Components(cardChallenge)
            : (Maybe<byte[]>.None, cardChallenge);

        if (state.ScpVersion == 0x02 && cardChallenge.Length != 8)
            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                SmartCardError.InvalidArgument($"SCP02 requires 8-byte card challenge, got {cardChallenge.Length}"));

        return crypto.CalculateHostCryptogram(
                hostChallenge, 
                cardChallengeForCrypto, 
                currentKeys, 
                state.ScpVersion,
                (byte)state.ScpImplementation,
                sequenceCounter.GetValueOrDefault(null))
            .Bind(expectedCryptogram => crypto.VerifyCryptogram(request.HostCryptogram, expectedCryptogram))
            .Bind(verified => verified
                ? Result.Success<ExternalAuthenticateRequest, SmartCardError>(request)
                : Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                    SmartCardError.SecurityStatusNotSatisfied()));
    }

    private static (Maybe<byte[]> sequenceCounter, byte[] cardChallengeForCrypto) ExtractScp02Components(byte[] cardChallenge)
    {
        if (cardChallenge.Length == 8)
        {
            Maybe<byte[]> sequenceCounter = Maybe<byte[]>.From(cardChallenge.Take(2).ToArray());
            byte[] cardChallengeForCrypto = cardChallenge.Skip(2).Take(6).ToArray();
            return (sequenceCounter, cardChallengeForCrypto);
        }
        return (Maybe<byte[]>.None, cardChallenge);
    }

    private static Result<Domain.Keys.SessionKeys, SmartCardError> DeriveSessionKeys(
        ExternalAuthenticateRequest request, CardState state, CardConfiguration config, CryptographicService crypto)
    {
        if (state.HostChallenge.HasNoValue || state.CardChallenge.HasNoValue || state.CurrentKeys.HasNoValue)
            return Result.Failure<Domain.Keys.SessionKeys, SmartCardError>(
                SmartCardError.ConditionsNotSatisfied());

        return state.HostChallenge.Match(
            hostChallenge => state.CardChallenge.Match(
                cardChallenge => state.CurrentKeys.Match(
                    currentKeys => crypto.DeriveSessionKeys(currentKeys, hostChallenge, cardChallenge, state.ScpVersion),
                    () => Result.Failure<Domain.Keys.SessionKeys, SmartCardError>(SmartCardError.ConditionsNotSatisfied())
                ),
                () => Result.Failure<Domain.Keys.SessionKeys, SmartCardError>(SmartCardError.ConditionsNotSatisfied())
            ),
            () => Result.Failure<Domain.Keys.SessionKeys, SmartCardError>(SmartCardError.ConditionsNotSatisfied())
        );
    }

    private static (ApduResponse, CardState) CreateExternalAuthenticateResult(
        Domain.Keys.SessionKeys sessionKeys, CardState state)
    {
        // Create functional secure channel state
        SecurityLevel securityLevel = (SecurityLevel)0x01; // Basic security level
        Result<SecureChannelState, SmartCardError> secureChannelStateResult = SecureChannelState.Create(
            sessionKeys: sessionKeys,
            securityLevel: securityLevel,
            protocolVersion: 0x02, // Default to SCP02
            initialMacChainingValue: new byte[8], // Initialize with zeros
            implementationParameter: 0x00
        );
        
        if (secureChannelStateResult.IsFailure)
        {
            return (new ApduResponse([], StatusWords.AuthenticationMethodBlocked), state);
        }
        
        SecureChannelState? secureChannelState = secureChannelStateResult.Value;

        // Update state with established secure channel using functional approach
        CardState newState = state.WithSecureChannel(secureChannelState);

        // EXTERNAL AUTHENTICATE response is typically empty on success
        return (new ApduResponse([], StatusWords.Success), newState);
    }

    // Placeholder implementations for other commands
    private static Result<ushort, SmartCardError> ParseGetDataCommand(byte[] command)
    {
        // GET DATA command format: CLA INS P1 P2 [Le]
        // P1P2 contains the tag (2 bytes)
        if (command.Length < 4)
            return Result.Failure<ushort, SmartCardError>(SmartCardError.WrongLength());
            
        ushort tag = (ushort)((command[2] << 8) | command[3]);
        return Result.Success<ushort, SmartCardError>(tag);
    }

    private static Result<ushort, SmartCardError> ValidateGetDataAccess(ushort tag, CardState state)
    {
        // For now, allow access to all data objects regardless of authentication state
        // In a real implementation, some objects might require secure channel
        return Result.Success<ushort, SmartCardError>(tag);
    }

    private static Result<byte[], SmartCardError> RetrieveDataObject(
        ushort tag, CardState state, CardConfiguration config)
    {
        // Check if this tag exists in the card configuration
        if (config.DefaultDataObjects.TryGetValue(tag, out byte[]? data))
        {
            return Result.Success<byte[], SmartCardError>(data);
        }
            
        // Check if this tag exists in the card state
        if (state.DataObjects.TryGetValue(tag, out byte[]? stateData))
        {
            return Result.Success<byte[], SmartCardError>(stateData);
        }
            
        return Result.Failure<byte[], SmartCardError>(SmartCardError.ReferencedDataNotFound());
    }

    private static Result<GetStatusRequest, SmartCardError> ParseGetStatusCommand(byte[] command) =>
        Result.Failure<GetStatusRequest, SmartCardError>(SmartCardError.InstructionNotSupported());

    private static Result<GetStatusRequest, SmartCardError> ValidateGetStatusAccess(
        GetStatusRequest request, CardState state) =>
        Result.Failure<GetStatusRequest, SmartCardError>(SmartCardError.InstructionNotSupported());

    private static Result<byte[], SmartCardError> RetrieveStatusData(
        GetStatusRequest request, CardState state, CardConfiguration config) =>
        Result.Failure<byte[], SmartCardError>(SmartCardError.InstructionNotSupported());

    private record ExternalAuthenticateRequest(byte SecurityLevel, byte[] HostCryptogram, byte[] HostMac);
    private record GetStatusRequest();
}