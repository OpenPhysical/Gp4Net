using System;
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
using Gp4Net.Utils;
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
        ICryptographicService crypto,
        ILogger? logger = null)
    {
        logger?.LogDebug("Processing SCP03 INITIALIZE UPDATE command");
        return ParseInitializeUpdateCommand(command)
            .Bind(request => ValidateScp03Preconditions(request, state, config))
            .Bind(request => GenerateScp03CardChallenge(request, state, config, crypto))
            .Bind(data => CalculateScp03CardCryptogram(data, state, config, crypto))
            .Map(result => CreateScp03InitializeUpdateResponse(result, state, config));
    }

    /// <summary>
    /// Processes an EXTERNAL AUTHENTICATE command for SCP03.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessScp03ExternalAuthenticate(
        byte[] command,
        CardState state,
        CardConfiguration config,
        ICryptographicService crypto,
        ILogger? logger = null)
    {
        logger?.LogDebug("Processing SCP03 EXTERNAL AUTHENTICATE command");
        return ParseExternalAuthenticateCommand(command, logger)
            .Bind(request => ValidateScp03ExternalAuthPreconditions(request, state, logger))
            .Bind(request => VerifyScp03HostCryptogram(request, state, crypto, logger))
            .Bind(request => DeriveScp03SessionKeys(request, state, crypto, logger))
            .Map(result => CreateScp03ExternalAuthResponse(result.sessionKeys, result.request, state, logger));
    }

    // Helper methods and data structures

    private record InitializeUpdateRequest(byte KeyVersion, byte KeyIdentifier, byte[] HostChallenge);
    private record Scp03ChallengeData(InitializeUpdateRequest Request, byte[] CardChallenge);
    private record Scp03CryptogramData(
        byte KeyVersion,
        Gp4Net.Domain.Protocol.ScpImplementation Implementation,
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

        var keyVersion = command[2];
        var keyIdentifier = command[3];
        var lc = command[4];

        // Accept either 13 bytes (no Le) or 14 bytes (with Le)
        if (lc != 8 || (command.Length != 13 && command.Length != 14))
            return SmartCardError.WrongLength();

        // For SCP03, key identifier must be 0x00
        if (keyIdentifier != 0x00)
            return SmartCardError.InvalidArgument("SCP03 requires key identifier 0x00");

        var hostChallenge = command.Skip(5).Take(8).ToArray();

        return Result.Success<InitializeUpdateRequest, SmartCardError>(
            new InitializeUpdateRequest(keyVersion, keyIdentifier, hostChallenge));
    }

    private static Result<InitializeUpdateRequest, SmartCardError> ValidateScp03Preconditions(
        InitializeUpdateRequest request,
        CardState state,
        CardConfiguration config)
    {
        if (!state.IsSelected)
            return SmartCardError.ConditionsNotSatisfied();

        // Verify SCP03 is configured
        if (state.ScpVersion != 0x03)
            return SmartCardError.InvalidArgument("Card is not configured for SCP03");

        // Validate implementation parameter
        var validImplementations = new byte[] { 0x00, 0x10, 0x20, 0x60, 0x70 };
        if (!validImplementations.Any(v => v == (byte)state.ScpImplementation))
            return SmartCardError.InvalidArgument($"Invalid SCP03 implementation: {state.ScpImplementation:X2}");

        return Result.Success<InitializeUpdateRequest, SmartCardError>(request);
    }

    private static Result<Scp03ChallengeData, SmartCardError> GenerateScp03CardChallenge(
        InitializeUpdateRequest request,
        CardState state,
        CardConfiguration config,
        ICryptographicService crypto)
    {
        // Check if pseudo-random challenge generation is required (i=70)
        if (state.ScpImplementation.UsesPseudoRandom())
        {
            // Get the key set for pseudo-random generation
            if (!TryGetKeySet(request.KeyVersion, state, config, out var keySet) || keySet == null)
                return SmartCardError.ReferencedDataNotFound();

            if (keySet is not Scp03KeySet scp03Keys)
                return SmartCardError.InvalidArgument("SCP03 requires SCP03 key set");

            // Get sequence counter
            var sequenceCounter = state.GetSequenceCounter(request.KeyVersion);

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
            // Standard random challenge generation
            return crypto.GenerateChallenge(8)
                .Map(challenge => new Scp03ChallengeData(request, challenge));
        }
    }

    private static Result<Scp03CryptogramData, SmartCardError> CalculateScp03CardCryptogram(
        Scp03ChallengeData data,
        CardState state,
        CardConfiguration config,
        ICryptographicService crypto)
    {
        // Determine effective key version
        var effectiveKeyVersion = data.Request.KeyVersion;
        if (effectiveKeyVersion == 0x00)
        {
            effectiveKeyVersion = state.DefaultKeyVersion;
            if (effectiveKeyVersion == 0xFF)
            {
                effectiveKeyVersion = config.StaticKeys.Keys.FirstOrDefault();
            }
        }

        // Get the appropriate keys
        if (!TryGetKeySet(effectiveKeyVersion, state, config, out var keys) || keys == null)
            return SmartCardError.ReferencedDataNotFound();

        // Get sequence counter
        var sequenceCounter = state.GetSequenceCounter(effectiveKeyVersion);

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
        var response = new byte[32]; // Fixed size for SCP03
        var offset = 0;

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
        var newState = state
            .WithChallenges(data.HostChallenge, data.CardChallenge)
            .WithKeys(data.Keys);

        // Increment sequence counter if pseudo-random challenges are used (i=70)
        if (data.Implementation.UsesPseudoRandom())
        {
            newState = newState.WithIncrementedSequenceCounter(data.KeyVersion);
        }

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

        var securityLevel = command[2];
        var p2 = command[3];
        var lc = command[4];

        logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Security Level=0x{SecurityLevel:X2}, P2=0x{P2:X2}, Lc={Lc}", securityLevel, p2, lc);
        logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Command length={Length}, Expected=21 (5 header + 16 data)", command.Length);

        // For SCP03, expect 16 bytes (8 byte cryptogram + 8 byte MAC)
        if (lc != 16 || command.Length != 21)
        {
            logger?.LogError("SCP03 EXTERNAL AUTHENTICATE: Wrong length - Lc={Lc}, command.Length={Length}", lc, command.Length);
            return SmartCardError.WrongLength();
        }

        var hostCryptogram = command.Skip(5).Take(8).ToArray();
        var hostMac = command.Skip(13).Take(8).ToArray();

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

        if (state.HostChallenge == null || state.CardChallenge == null)
        {
            logger?.LogError("SCP03 EXTERNAL AUTHENTICATE: Missing challenges - HostChallenge={HasHost}, CardChallenge={HasCard}",
                state.HostChallenge != null, state.CardChallenge != null);
            return SmartCardError.ConditionsNotSatisfied();
        }

        if (state.CurrentKeys == null)
        {
            logger?.LogError("SCP03 EXTERNAL AUTHENTICATE: No current keys set");
            return SmartCardError.ConditionsNotSatisfied();
        }

        // Validate security level for SCP03
        // Valid levels: 0x01 (C-MAC), 0x03 (C-DECRYPTION), 0x10 (R-MAC), 0x11 (C-MAC + R-MAC), 0x30 (R-MAC + R-ENC), 0x33 (C-DECRYPTION + R-MAC + R-ENC)
        var validLevels = new[] { 0x01, 0x03, 0x10, 0x11, 0x30, 0x33 };
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
        ICryptographicService crypto,
        ILogger? logger = null)
    {
        if (state.HostChallenge == null || state.CardChallenge == null || state.CurrentKeys == null)
        {
            logger?.LogError("SCP03 EXTERNAL AUTHENTICATE: Missing data for cryptogram verification");
            return SmartCardError.ConditionsNotSatisfied();
        }

        logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Calculating expected host cryptogram");
        logger?.LogDebug("Host Challenge: {HostChallenge}", Convert.ToHexString(state.HostChallenge));
        logger?.LogDebug("Card Challenge: {CardChallenge}", Convert.ToHexString(state.CardChallenge));

        // Calculate expected host cryptogram
        return crypto.CalculateHostCryptogram(
                state.HostChallenge,
                state.CardChallenge,
                state.CurrentKeys,
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
                    return SmartCardError.SecurityStatusNotSatisfied();
                }

                logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Host cryptogram verified successfully");
                logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: MAC verification completed");
                return Result.Success<ExternalAuthenticateRequest, SmartCardError>(request);
            });
    }

    private static Result<(SessionKeys sessionKeys, ExternalAuthenticateRequest request), SmartCardError> DeriveScp03SessionKeys(
        ExternalAuthenticateRequest request,
        CardState state,
        ICryptographicService crypto,
        ILogger? logger = null)
    {
        if (state.HostChallenge == null || state.CardChallenge == null || state.CurrentKeys == null)
        {
            logger?.LogError("SCP03 EXTERNAL AUTHENTICATE: Missing data for session key derivation");
            return SmartCardError.ConditionsNotSatisfied();
        }

        logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Deriving session keys");
        // SCP03 always derives all session keys using NIST SP 800-108 KDF
        return crypto.DeriveSessionKeys(
            state.CurrentKeys,
            state.HostChallenge,
            state.CardChallenge,
            0x03)
            .Tap(keys => logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Session keys derived successfully"))
            .Map(sessionKeys => (sessionKeys, request));
    }

    private static (ApduResponse, CardState) CreateScp03ExternalAuthResponse(
        SessionKeys sessionKeys,
        ExternalAuthenticateRequest request,
        CardState state,
        ILogger? logger = null)
    {
        logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Creating response");

        // Map requested security level to internal representation
        var securityLevelByte = request.SecurityLevel switch
        {
            0x01 => (byte)0x01, // C-MAC
            0x03 => (byte)0x03, // C-DECRYPTION
            0x10 => (byte)0x10, // R-MAC only
            0x11 => (byte)0x11, // C-MAC + R-MAC
            0x30 => (byte)0x30, // R-MAC + R-ENC
            0x33 => (byte)0x33, // C-DECRYPTION + R-MAC + R-ENC
            _ => (byte)0x01     // Default C-MAC
        };

        var securityLevel = (SecurityLevel)securityLevelByte;

        // Calculate the MAC chaining value from the EXTERNAL AUTHENTICATE MAC
        // Per SCP03 spec, this becomes the chaining value for subsequent operations
        var initialMacChaining = CalculateExternalAuthenticateMacChaining(request, state);

        // Create functional secure channel state
        var secureChannelStateResult = SecureChannelState.Create(
            sessionKeys: sessionKeys,
            securityLevel: securityLevel,
            protocolVersion: 0x03,
            initialMacChainingValue: initialMacChaining.ToArray(),
            implementationParameter: 0x00
        );

        if (secureChannelStateResult.IsFailure)
        {
            logger?.LogError("Failed to create secure channel state: {Error}", secureChannelStateResult.Error);
            return (new ApduResponse(Array.Empty<byte>(), StatusWords.AuthenticationMethodBlocked), state);
        }

        var secureChannelState = secureChannelStateResult.Value;

        // Update state with established secure channel using functional approach
        var newState = state.WithSecureChannel(secureChannelState);

        logger?.LogDebug("SCP03 EXTERNAL AUTHENTICATE: Secure channel established with security level 0x{SecurityLevel:X2}", securityLevelByte);

        // SCP03 EXTERNAL AUTHENTICATE response is typically empty on success
        return (new ApduResponse(Array.Empty<byte>(), StatusWords.Success), newState);
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
        if (state.HostChallenge == null || state.CurrentKeys == null)
        {
            // Fallback to padded version if we can't calculate properly
            var fallbackMac = new byte[16];
            Array.Copy(request.HostMac, 0, fallbackMac, 0, 8);
            return ImmutableArray.Create(fallbackMac);
        }

        // Create EXTERNAL AUTHENTICATE command for MAC calculation
        var externalAuthCommandResult = ExternalAuthenticateCommand.CreateWithoutMac(
            (SecurityLevel)request.SecurityLevel,
            request.HostCryptogram
        );

        if (externalAuthCommandResult.IsFailure)
        {
            // Fallback to padded version on error
            var fallbackMac = new byte[16];
            Array.Copy(request.HostMac, 0, fallbackMac, 0, 8);
            return ImmutableArray.Create(fallbackMac);
        }

        var externalAuthCommand = externalAuthCommandResult.Value;

        // Use the new static protocol service to calculate the initial MAC chaining value
        return Scp03ProtocolService.CalculateInitialMacChainingValue(externalAuthCommand, state.CurrentKeys.MacKey)
            .Match(
                mac => ImmutableArray.Create(mac),
                error =>
                {
                    // Fallback to padded version on error
                    var fallbackMac = new byte[16];
                    Array.Copy(request.HostMac, 0, fallbackMac, 0, 8);
                    return ImmutableArray.Create(fallbackMac);
                }
            );
    }

    // Utility methods

    private static bool TryGetKeySet(byte keyVersion, CardState state, CardConfiguration config, out IKeySet? keySet)
    {
        keySet = null;

        // Check installed keys first
        if (state.InstalledKeys.TryGetValue(keyVersion, out var installedKeys))
        {
            keySet = installedKeys;
            return true;
        }

        // Then check static keys
        if (config.StaticKeys.TryGetValue(keyVersion, out var staticKeys))
        {
            keySet = staticKeys;
            return true;
        }

        // If key version is 0x00 or 0xFF, try to find any available key
        if (keyVersion == 0x00 || keyVersion == 0xFF)
        {
            keySet = config.StaticKeys.Values.FirstOrDefault();
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
        var cla = command[0];
        var ins = command[1];

        if ((cla == 0x80 && ins == 0x50) || (cla == 0x84 && ins == 0x82))
        {
            // Check if card is configured for SCP03
            return state.ScpVersion == 0x03;
        }

        // Check if secure channel is established with SCP03
        return state is { IsSecureChannelEstablished: true, ScpVersion: 0x03 };
    }

}
