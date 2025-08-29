using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

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
        CryptographicService crypto,
        ILogger? logger = null)
    {
        logger?.LogDebug("Processing SCP03 INITIALIZE UPDATE command");
        
        Result<(ApduResponse, CardState), SmartCardError> result = ParseInitializeUpdateCommand(command)
            .Bind(request => 
            {
                logger?.LogDebug("ParseInitializeUpdateCommand succeeded");
                return ValidateScp03Preconditions(request, state, config, logger);
            })
            .Bind(request => 
            {
                logger?.LogDebug("ValidateScp03Preconditions succeeded");
                return GenerateScp03CardChallenge(request, state, config, crypto);
            })
            .Bind(data => 
            {
                logger?.LogDebug("GenerateScp03CardChallenge succeeded");
                return CalculateScp03CardCryptogram(data, state, config, crypto);
            })
            .Map(response => 
            {
                logger?.LogDebug("CalculateScp03CardCryptogram succeeded, creating response");
                return CreateScp03InitializeUpdateResponse(response, state, config);
            });
            
        if (result.IsFailure)
        {
            logger?.LogError("ProcessScp03InitializeUpdate failed: {ErrorMessage}", result.Error.Message);
        }
        
        return result;
    }

    /// <summary>
    /// Processes an EXTERNAL AUTHENTICATE command for SCP03.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessScp03ExternalAuthenticate(
        byte[] command,
        CardState state,
        CardConfiguration config,
        CryptographicService crypto,
        LoggingService logging)
    {
        logging.LogDebug("Processing SCP03 EXTERNAL AUTHENTICATE command");
        logging.LogDebug("SCP03 PROCESSOR ENTRY: Starting ProcessScp03ExternalAuthenticate");
        logging.LogDebug("SCP03 Command: {Command}", Convert.ToHexString(command));
        return ParseExternalAuthenticateCommand(command)
            .Tap(request => logging.LogDebug("ParseExternalAuthenticateCommand: SUCCESS"))
            .TapError(error => logging.LogDebug("ParseExternalAuthenticateCommand: FAILED - {Error}", error.Message))
            .Bind(request => ValidateScp03ExternalAuthPreconditions(request, state))
            .Tap(request => logging.LogDebug("ValidateScp03ExternalAuthPreconditions: SUCCESS"))
            .TapError(error => logging.LogDebug("ValidateScp03ExternalAuthPreconditions: FAILED - {Error}", error.Message))
            .Bind(request => VerifyScp03HostCryptogram(request, state, crypto))
            .Tap(request => logging.LogDebug("VerifyScp03HostCryptogram: SUCCESS"))
            .TapError(error => logging.LogDebug("VerifyScp03HostCryptogram: FAILED - {Error}", error.Message))
            .Bind(request => DeriveScp03SessionKeys(request, state, crypto))
            .Map(result => CreateScp03ExternalAuthResponse(result.sessionKeys, result.request, state));
    }

    // Helper methods and data structures

    private record InitializeUpdateRequest(byte KeyVersion, byte KeyIdentifier, byte[] HostChallenge);
    private record Scp03ChallengeData(InitializeUpdateRequest Request, byte[] CardChallenge);
    private record Scp03CryptogramData(
        byte KeyVersion,
        ScpImplementation Implementation,
        byte[] HostChallenge,
        byte[] CardChallenge,
        byte[] CardCryptogram,
        byte[] SequenceCounter,
        IKeySet Keys);
    private record ExternalAuthenticateRequest(byte SecurityLevel, byte[] HostCryptogram, byte[] HostMac);

    private static Result<InitializeUpdateRequest, SmartCardError> ParseInitializeUpdateCommand(byte[] command)
    {
        if (command.Length < 13) // CLA INS P1 P2 LC + 8 bytes challenge
            return SmartCardError.WrongLength();

        if (command[0] != 0x80 || command[1] != 0x50)
            return SmartCardError.InstructionNotSupported();

        byte keyVersion = command[2];
        byte keyIdentifier = command[3];
        byte lc = command[4];

        // Accept either 13 bytes (no Le) or 14 bytes (with Le)
        if (lc != 8 || (command.Length != 13 && command.Length != 14))
            return SmartCardError.WrongLength();

        // For SCP03, key identifier must be 0x00
        if (keyIdentifier != 0x00)
            return SmartCardError.InvalidArgument("SCP03 requires key identifier 0x00");

        byte[] hostChallenge = command.Skip(5).Take(8).ToArray();

        return Result.Success<InitializeUpdateRequest, SmartCardError>(
            new InitializeUpdateRequest(keyVersion, keyIdentifier, hostChallenge));
    }

    private static Result<InitializeUpdateRequest, SmartCardError> ValidateScp03Preconditions(
        InitializeUpdateRequest request,
        CardState state,
        CardConfiguration config,
        ILogger? logger = null)
    {
        logger?.LogDebug("SCP03 validation - IsSelected: {IsSelected}, ScpVersion: 0x{ScpVersion:X2}, ScpImpl: 0x{ScpImpl:X2}",
            state.IsSelected, (byte)state.ScpVersion, (byte)state.ScpImplementation);
        
        if (!state.IsSelected)
        {
            logger?.LogError("SCP03 validation failed - card not selected");
            return SmartCardError.ConditionsNotSatisfied();
        }

        // Verify SCP03 is configured
        if (state.ScpVersion != 0x03)
        {
            logger?.LogError("SCP03 validation failed - wrong SCP version: 0x{ScpVersion:X2}", (byte)state.ScpVersion);
            return SmartCardError.InvalidArgument("Card is not configured for SCP03");
        }

        // Validate implementation parameter
        byte[] validImplementations = [0x00, 0x10, 0x20, 0x60, 0x70];
        if (!validImplementations.Any(v => v == (byte)state.ScpImplementation))
        {
            logger?.LogError("SCP03 validation failed - invalid implementation: 0x{ScpImpl:X2}", (byte)state.ScpImplementation);
            return SmartCardError.InvalidArgument($"Invalid SCP03 implementation: {state.ScpImplementation:X2}");
        }

        logger?.LogDebug("SCP03 validation passed");
        return Result.Success<InitializeUpdateRequest, SmartCardError>(request);
    }

    private static Result<Scp03ChallengeData, SmartCardError> GenerateScp03CardChallenge(
        InitializeUpdateRequest request,
        CardState state,
        CardConfiguration config,
        CryptographicService crypto)
    {
        // Generate SCP03 card challenge per GlobalPlatform Card Specification v2.3.1 Section 6.2.2.1
        
        // Check if pseudo-random challenge generation is required (i=70)
        if (state.ScpImplementation == ScpImplementation.Scp03I70)
        {
            // Using pseudo-random challenge generation (i=70)
            
            // Get the key set for pseudo-random generation
            if (!TryGetKeySet(request.KeyVersion, state, config, out IKeySet? keySet) || keySet == null)
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

            // Generate pseudo-random challenge
            return crypto.GeneratePseudoRandomChallenge(
                    scp03Keys.EncKey,
                    sequenceCounter,
                    config.IsdAid,
                    8)
                .Map(challenge => new Scp03ChallengeData(request, challenge));
        }
        else
        {
            // Using standard random challenge generation
            // Standard random challenge generation
            return crypto.GenerateChallenge(8)
                .Map(challenge => new Scp03ChallengeData(request, challenge));
        }
    }

    private static Result<Scp03CryptogramData, SmartCardError> CalculateScp03CardCryptogram(
        Scp03ChallengeData data,
        CardState state,
        CardConfiguration config,
        CryptographicService crypto)
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
                KeyValuePair<byte, IKeySet> scp03Key = config.StaticKeys.FirstOrDefault(kvp => kvp.Value is Scp03KeySet);
                effectiveKeyVersion = scp03Key.Key != 0 ? scp03Key.Key : config.StaticKeys.Keys.FirstOrDefault();
            }
        }

        // Effective key version determined

        // Get the appropriate keys
        if (!TryGetKeySet(effectiveKeyVersion, state, config, out IKeySet? keys) || keys == null)
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

        // Calculate card cryptogram using AES-CMAC
        return crypto.CalculateCardCryptogram(
                data.Request.HostChallenge,
                data.CardChallenge,
                keys,
                0x03,
                (byte)state.ScpImplementation,
                Maybe<byte[]>.None)
            .Map(cryptogram => new Scp03CryptogramData(
                effectiveKeyVersion,
                state.ScpImplementation,
                data.Request.HostChallenge,
                data.CardChallenge,
                cryptogram,
                sequenceCounter,
                keys));
    }

    private static (ApduResponse, CardState) CreateScp03InitializeUpdateResponse(
        Scp03CryptogramData data,
        CardState state,
        CardConfiguration config)
    {
        // Build SCP03 INITIALIZE UPDATE response
        byte[] response = new byte[32]; // Fixed size for SCP03
        int offset = 0;

        // Key diversification data (10 bytes)
        Array.Fill<byte>(response, 0x00, offset, 10);
        offset += 10;

        // Key information (3 bytes)
        response[offset++] = data.KeyVersion;  // Byte 0: Key version
        response[offset++] = 0x03;             // Byte 1: SCP version (always 0x03 for SCP03)
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
        CardState newState = state
            .WithChallenges(data.HostChallenge, data.CardChallenge)
            .WithKeys(data.Keys);

        // Increment sequence counter if pseudo-random challenges are used (i=70)
        if (data.Implementation == ScpImplementation.Scp03I70)
        {
            newState = newState.WithIncrementedSequenceCounter(data.KeyVersion);
        }

        // SCP03 INITIALIZE UPDATE response created successfully
        
        return (new ApduResponse(response, StatusWords.Success), newState);
    }

    private static Result<ExternalAuthenticateRequest, SmartCardError> ParseExternalAuthenticateCommand(byte[] command, ILogger? logger = null)
    {
        if (command.Length < 5)
        {
            logger?.LogError("SCP03 EXTERNAL AUTHENTICATE: Command too short: {Length} bytes", command.Length);
            return SmartCardError.WrongLength();
        }

        if (command[0] != 0x84 || command[1] != 0x82)
        {
            logger?.LogError("SCP03 EXTERNAL AUTHENTICATE: Invalid CLA/INS: {CLA:X2} {INS:X2}", command[0], command[1]);
            return SmartCardError.InstructionNotSupported();
        }

        byte securityLevel = command[2];
        byte p2 = command[3];
        byte lc = command[4];

        logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Security Level=0x{SecurityLevel:X2}, P2=0x{P2:X2}, Lc={Lc}", securityLevel, p2, lc);
        logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Command length={Length}, Expected=21 (5 header + 16 data)", command.Length);

        // For SCP03, expect 16 bytes (8 byte cryptogram + 8 byte MAC)
        if (lc != 16 || command.Length != 21)
        {
            logger?.LogError("SCP03 EXTERNAL AUTHENTICATE: Wrong length - Lc={Lc}, command.Length={Length}", lc, command.Length);
            return SmartCardError.WrongLength();
        }

        byte[] hostCryptogram = command.Skip(5).Take(8).ToArray();
        byte[] hostMac = command.Skip(13).Take(8).ToArray();

        logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Host Cryptogram={HostCryptogram}", Convert.ToHexString(hostCryptogram));
        logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Host MAC={HostMac}", Convert.ToHexString(hostMac));

        return Result.Success<ExternalAuthenticateRequest, SmartCardError>(
            new ExternalAuthenticateRequest(securityLevel, hostCryptogram, hostMac));
    }

    private static Result<ExternalAuthenticateRequest, SmartCardError> ValidateScp03ExternalAuthPreconditions(
        ExternalAuthenticateRequest request,
        CardState state,
        ILogger? logger = null)
    {
        if (!state.IsSelected)
        {
            logger?.LogError("SCP03 EXTERNAL AUTHENTICATE: Card not selected");
            return SmartCardError.ConditionsNotSatisfied();
        }

        if (state.HostChallenge.HasNoValue || state.CardChallenge.HasNoValue)
        {
            logger?.LogError("SCP03 EXTERNAL AUTHENTICATE: Missing challenges - HostChallenge={HasHost}, CardChallenge={HasCard}",
                state.HostChallenge.HasValue, state.CardChallenge.HasValue);
            return SmartCardError.ConditionsNotSatisfied();
        }

        if (state.CurrentKeys.HasNoValue)
        {
            logger?.LogError("SCP03 EXTERNAL AUTHENTICATE: No current keys set");
            return SmartCardError.ConditionsNotSatisfied();
        }

        // Validate security level for SCP03
        // Valid levels: 0x01 (C-MAC), 0x03 (C-DECRYPTION), 0x10 (R-MAC), 0x11 (C-MAC + R-MAC), 0x30 (R-MAC + R-ENC), 0x33 (C-DECRYPTION + R-MAC + R-ENC)
        int[] validLevels = [0x01, 0x03, 0x10, 0x11, 0x30, 0x33];
        if (!validLevels.Contains(request.SecurityLevel))
        {
            logger?.LogError("SCP03 EXTERNAL AUTHENTICATE: Invalid security level 0x{SecurityLevel:X2}", request.SecurityLevel);
            logger?.LogError("SCP03 Valid levels: {ValidLevels}", string.Join(", ", validLevels.Select(l => $"0x{l:X2}")));
            return SmartCardError.InvalidArgument($"Invalid security level for SCP03: {request.SecurityLevel:X2}");
        }

        logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Security level 0x{SecurityLevel:X2} is valid", request.SecurityLevel);
        return Result.Success<ExternalAuthenticateRequest, SmartCardError>(request);
    }

    private static Result<ExternalAuthenticateRequest, SmartCardError> VerifyScp03HostCryptogram(
        ExternalAuthenticateRequest request,
        CardState state,
        CryptographicService crypto,
        ILogger? logger = null)
    {
        if (state.HostChallenge.HasNoValue || state.CardChallenge.HasNoValue || state.CurrentKeys.HasNoValue)
        {
            logger?.LogError("SCP03 EXTERNAL AUTHENTICATE: Missing data for cryptogram verification");
            return SmartCardError.ConditionsNotSatisfied();
        }

        logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Calculating expected host cryptogram");
        return state.HostChallenge.Match(
            hostChallenge => state.CardChallenge.Match(
                cardChallenge => state.CurrentKeys.Match(
                    currentKeys => {
                        logger?.LogDebug("Host Challenge: {HostChallenge}", Convert.ToHexString(hostChallenge));
                        logger?.LogDebug("Card Challenge: {CardChallenge}", Convert.ToHexString(cardChallenge));

                        return crypto.CalculateHostCryptogram(
                                hostChallenge,
                                cardChallenge,
                                currentKeys,
                                0x03,
                                (byte)state.ScpImplementation,
                                Maybe<byte[]>.None)
                            .Bind(expectedCryptogram =>
                            {
                                logger?.LogDebug("Expected Host Cryptogram: {Expected}", Convert.ToHexString(expectedCryptogram));
                                logger?.LogDebug("Received Host Cryptogram: {Received}", Convert.ToHexString(request.HostCryptogram));

                                if (!request.HostCryptogram.SequenceEqual(expectedCryptogram))
                                {
                                    logger?.LogError("SCP03 EXTERNAL AUTHENTICATE: Host cryptogram verification failed");
                                    return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(SmartCardError.SecurityStatusNotSatisfied());
                                }

                                logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Host cryptogram verified successfully");
                                return Result.Success<ExternalAuthenticateRequest, SmartCardError>(request);
                            });
                    },
                    () => Result.Failure<ExternalAuthenticateRequest, SmartCardError>(SmartCardError.ConditionsNotSatisfied())
                ),
                () => Result.Failure<ExternalAuthenticateRequest, SmartCardError>(SmartCardError.ConditionsNotSatisfied())
            ),
            () => Result.Failure<ExternalAuthenticateRequest, SmartCardError>(SmartCardError.ConditionsNotSatisfied())
        );
    }

    private static Result<(SessionKeys sessionKeys, ExternalAuthenticateRequest request), SmartCardError> DeriveScp03SessionKeys(
        ExternalAuthenticateRequest request,
        CardState state,
        CryptographicService crypto,
        ILogger? logger = null)
    {
        if (state.HostChallenge.HasNoValue || state.CardChallenge.HasNoValue || state.CurrentKeys.HasNoValue)
        {
            logger?.LogError("SCP03 EXTERNAL AUTHENTICATE: Missing data for session key derivation");
            return SmartCardError.ConditionsNotSatisfied();
        }

        logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Deriving session keys");
        
        return state.HostChallenge.Match(
            hostChallenge => state.CardChallenge.Match(
                cardChallenge => state.CurrentKeys.Match(
                    currentKeys => crypto.DeriveSessionKeys(currentKeys, hostChallenge, cardChallenge, 0x03)
                        .Tap(keys => logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Session keys derived successfully"))
                        .Map(sessionKeys => (sessionKeys, request)),
                    () => Result.Failure<(SessionKeys, ExternalAuthenticateRequest), SmartCardError>(SmartCardError.ConditionsNotSatisfied())
                ),
                () => Result.Failure<(SessionKeys, ExternalAuthenticateRequest), SmartCardError>(SmartCardError.ConditionsNotSatisfied())
            ),
            () => Result.Failure<(SessionKeys, ExternalAuthenticateRequest), SmartCardError>(SmartCardError.ConditionsNotSatisfied())
        );
    }

    private static (ApduResponse, CardState) CreateScp03ExternalAuthResponse(
        SessionKeys sessionKeys,
        ExternalAuthenticateRequest request,
        CardState state,
        ILogger? logger = null)
    {
        logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Creating response");

        // Map requested security level to internal representation
        byte securityLevelByte = request.SecurityLevel switch
        {
            0x01 => (byte)0x01, // C-MAC
            0x03 => (byte)0x03, // C-DECRYPTION
            0x10 => (byte)0x10, // R-MAC only
            0x11 => (byte)0x11, // C-MAC + R-MAC
            0x30 => (byte)0x30, // R-MAC + R-ENC
            0x33 => (byte)0x33, // C-DECRYPTION + R-MAC + R-ENC
            _ => (byte)0x01     // Default C-MAC
        };

        SecurityLevel securityLevel = (SecurityLevel)securityLevelByte;

        // Calculate the MAC chaining value from the EXTERNAL AUTHENTICATE MAC
        // Per SCP03 spec, this becomes the chaining value for subsequent operations
        ImmutableArray<byte> initialMacChaining = CalculateExternalAuthenticateMacChaining(request, state);

        // Create functional secure channel state
        Result<SecureChannelState, SmartCardError> secureChannelStateResult = SecureChannelState.Create(
            sessionKeys: sessionKeys,
            securityLevel: securityLevel,
            protocolVersion: 0x03,
            initialMacChainingValue: initialMacChaining.ToArray(),
            implementationParameter: 0x00
        );

        if (secureChannelStateResult.IsFailure)
        {
            logger?.LogError("Failed to create secure channel state: {Error}", secureChannelStateResult.Error);
            return (new ApduResponse([], StatusWords.AuthenticationMethodBlocked), state);
        }

        SecureChannelState? secureChannelState = secureChannelStateResult.Value;

        // Update state with established secure channel using functional approach
        CardState newState = state.WithSecureChannel(secureChannelState);

        logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Secure channel established with security level 0x{SecurityLevel:X2}", securityLevelByte);

        // SCP03 EXTERNAL AUTHENTICATE response is typically empty on success
        return (new ApduResponse([], StatusWords.Success), newState);
    }

    /// <summary>
    /// Calculates the full MAC chaining value from the EXTERNAL AUTHENTICATE command.
    /// Per SCP03 specification, the MAC chaining value for subsequent operations
    /// is the full 16-byte MAC of the EXTERNAL AUTHENTICATE command.
    /// </summary>
    private static ImmutableArray<byte> CalculateExternalAuthenticateMacChaining(
        ExternalAuthenticateRequest request,
        CardState state)
    {
        if (state.HostChallenge.HasNoValue || state.CurrentKeys.HasNoValue)
        {
            // Fallback to padded version if we can't calculate properly
            byte[] fallbackMac = new byte[16];
            Array.Copy(request.HostMac, 0, fallbackMac, 0, 8);
            return [..fallbackMac];
        }

        // Create EXTERNAL AUTHENTICATE command for MAC calculation
        Result<ExternalAuthenticateCommand, SmartCardError> externalAuthCommandResult = ExternalAuthenticateCommand.CreateWithoutMac(
            (SecurityLevel)request.SecurityLevel,
            request.HostCryptogram
        );

        if (externalAuthCommandResult.IsFailure)
        {
            // Fallback to padded version on error
            byte[] fallbackMac = new byte[16];
            Array.Copy(request.HostMac, 0, fallbackMac, 0, 8);
            return [..fallbackMac];
        }

        ExternalAuthenticateCommand? externalAuthCommand = externalAuthCommandResult.Value;

        // Use the new static protocol service to calculate the initial MAC chaining value
        return state.CurrentKeys.Match(
            currentKeys => Scp03ProtocolService.CalculateInitialMacChainingValue(externalAuthCommand, currentKeys.MacKey)
                .Match(
                    mac => [..mac],
                    error =>
                    {
                        // Fallback to padded version on error
                        byte[] fallbackMac = new byte[16];
                        Array.Copy(request.HostMac, 0, fallbackMac, 0, 8);
                        return ImmutableArray.Create(fallbackMac);
                    }),
            () =>
            {
                // Fallback to padded version if no current keys
                byte[] fallbackMac = new byte[16];
                Array.Copy(request.HostMac, 0, fallbackMac, 0, 8);
                return ImmutableArray.Create(fallbackMac);
            });
    }

    // Utility methods

    private static bool TryGetKeySet(byte keyVersion, CardState state, CardConfiguration config, out IKeySet? keySet)
    {
        keySet = null;

        // Check installed keys first
        if (state.InstalledKeys.TryGetValue(keyVersion, out IKeySet? installedKeys))
        {
            keySet = installedKeys;
            return true;
        }

        // Then check static keys
        if (config.StaticKeys.TryGetValue(keyVersion, out IKeySet? staticKeys))
        {
            keySet = staticKeys;
            return true;
        }

        // If key version is 0x00 or 0xFF, try to find any available key
        if (keyVersion is 0x00 or 0xFF)
        {
            // For SCP03 context, prefer SCP03 key sets
            keySet = config.StaticKeys.Values.OfType<Scp03KeySet>().FirstOrDefault() 
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

        if ((cla == 0x80 && ins == 0x50) || (cla == 0x84 && ins == 0x82))
        {
            // Check if card is configured for SCP03
            return state.ScpVersion == 0x03;
        }

        // Check if secure channel is established with SCP03
        return state is { IsSecureChannelEstablished: true, ScpVersion: 0x03 };
    }

}
