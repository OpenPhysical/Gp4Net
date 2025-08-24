using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// SCP02-specific command processors for the virtual card emulator.
/// Implements the SCP02 protocol flow according to GlobalPlatform Card Specification v2.2.1.
/// </summary>
[PublicAPI]
public static class Scp02CommandProcessors
{
    /// <summary>
    /// Processes an INITIALIZE UPDATE command for SCP02.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessScp02InitializeUpdate(
        byte[] command,
        CardState state,
        CardConfiguration config,
        ICryptographicService crypto,
        ILogger? logger = null)
    {
        logger?.LogDebug("=== Starting ProcessScp02InitializeUpdate ===");
        logger?.LogDebug("Command length: {Length}", command.Length);
        logger?.LogDebug("Command hex: {Command}", Convert.ToHexString(command));
        logger?.LogDebug("Card state - SCP version: 0x{Scp:X2}", (byte)state.ScpVersion);
        logger?.LogDebug("Card state - SCP implementation: {Impl}", state.ScpImplementation);
        logger?.LogDebug("Card selected: {Selected}", state.IsSelected);
        logger?.LogDebug("Secure channel established: {Established}", state.IsSecureChannelEstablished);

        try
        {
            logger?.LogDebug("About to parse INITIALIZE UPDATE command");
            var parseResult = ParseInitializeUpdateCommand(command);

            if (parseResult.IsFailure)
            {
                logger?.LogError("Failed to parse command: {Error}", parseResult.Error.Message);
                return parseResult.Error;
            }

            logger?.LogDebug("Command parsed successfully");

            var result = Result.Success<InitializeUpdateRequest, SmartCardError>(parseResult.Value)
            .Tap(request => logger?.LogDebug("Parsed INITIALIZE UPDATE - KeyVersion: 0x{KeyVersion:X2}, KeyId: 0x{KeyId:X2}, HostChallenge: {Challenge}",
                request.KeyVersion, request.KeyIdentifier, Convert.ToHexString(request.HostChallenge)))
            .TapError(error => logger?.LogError("Failed to parse INITIALIZE UPDATE command: {Error}", error.Message))
            .Bind(request => ValidateScp02Preconditions(request, state, config, logger))
            .Tap(_ => logger?.LogDebug("Preconditions validated successfully"))
            .TapError(error => logger?.LogError("Precondition validation failed: {Error}", error.Message))
            .Bind(request => GenerateScp02CardChallenge(request, state, config, crypto, logger))
            .Tap(data => logger?.LogDebug("Card challenge generated - CardChallenge: {Challenge}, SequenceCounter: {Counter}",
                Convert.ToHexString(data.CardChallenge), Convert.ToHexString(data.SequenceCounter)))
            .TapError(error => logger?.LogError("Failed to generate card challenge: {Error}", error.Message))
            .Bind(data => CalculateScp02CardCryptogram(data, state, config, crypto, logger))
            .Tap(result => logger?.LogDebug("Card cryptogram calculated - Cryptogram: {Cryptogram}",
                Convert.ToHexString(result.CardCryptogram)))
            .TapError(error => logger?.LogError("Failed to calculate card cryptogram: {Error}", error.Message))
            .Map(result => {
                logger?.LogDebug("About to create SCP02 INITIALIZE UPDATE response");
                return CreateScp02InitializeUpdateResponse(result, state, config, logger);
            })
            .TapError(error => logger?.LogError("SCP02 INITIALIZE UPDATE failed: {Error}", error.Message));

            logger?.LogDebug("=== ProcessScp02InitializeUpdate completed with {Status} ===",
                result.IsSuccess ? "SUCCESS" : "FAILURE");

            return result;
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Unhandled exception in ProcessScp02InitializeUpdate");
            return SmartCardError.CryptographicError($"Unhandled exception: {ex.Message}");
        }
    }

    /// <summary>
    /// Processes an EXTERNAL AUTHENTICATE command for SCP02.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessScp02ExternalAuthenticate(
        byte[] command,
        CardState state,
        CardConfiguration config,
        ICryptographicService crypto,
        ILogger? logger = null)
    {
        logger?.LogDebug("Processing SCP02 EXTERNAL AUTHENTICATE command");
        return ParseExternalAuthenticateCommand(command)
            .Bind(request => ValidateScp02ExternalAuthPreconditions(request, state))
            .Bind(request => VerifyScp02HostCryptogram(request, state, crypto))
            .Bind(request => DeriveScp02SessionKeys(request, state, crypto))
            .Map(sessionKeys => CreateScp02ExternalAuthResponse(sessionKeys, state));
    }

    // Helper methods and data structures

    private record InitializeUpdateRequest(byte KeyVersion, byte KeyIdentifier, byte[] HostChallenge);
    private record Scp02ChallengeData(InitializeUpdateRequest Request, byte[] CardChallenge, byte[] SequenceCounter);
    private record Scp02CryptogramData(
        byte KeyVersion,
        Gp4Net.Domain.Protocol.ScpImplementation Implementation,
        byte[] HostChallenge,
        byte[] CardChallenge,
        byte[] SequenceCounter,
        byte[] CardCryptogram,
        IKeySet Keys);
    private record ExternalAuthenticateRequest(byte SecurityLevel, byte[] HostCryptogram, byte[] HostMac);

    private static Result<InitializeUpdateRequest, SmartCardError> ParseInitializeUpdateCommand(byte[] command)
    {
        if (command.Length < 13) // CLA INS P1 P2 LC + 8 bytes challenge
        {
            return SmartCardError.WrongLength();
        }

        if (command[0] != 0x80 || command[1] != 0x50)
        {
            return SmartCardError.InstructionNotSupported();
        }

        var keyVersion = command[2];
        var keyIdentifier = command[3];
        var lc = command[4];

        // Accept either 13 bytes (no Le) or 14 bytes (with Le)
        if (lc != 8 || (command.Length != 13 && command.Length != 14))
        {
            return SmartCardError.WrongLength();
        }

        var hostChallenge = command.Skip(5).Take(8).ToArray();

        return Result.Success<InitializeUpdateRequest, SmartCardError>(
            new InitializeUpdateRequest(keyVersion, keyIdentifier, hostChallenge));
    }

    private static Result<InitializeUpdateRequest, SmartCardError> ValidateScp02Preconditions(
        InitializeUpdateRequest request,
        CardState state,
        CardConfiguration config,
        ILogger? logger = null)
    {
        logger?.LogDebug("Validating SCP02 preconditions - Selected: {Selected}, SCP: 0x{Scp:X2}",
            state.IsSelected, (byte)state.ScpVersion);

        if (!state.IsSelected)
        {
            logger?.LogWarning("Card not selected");
            return SmartCardError.ConditionsNotSatisfied();
        }

        // Verify SCP02 is configured
        if (state.ScpVersion != 0x02)
        {
            logger?.LogWarning("Card not configured for SCP02 - current version: {Scp:X2}", state.ScpVersion);
            return SmartCardError.InvalidArgument("Card is not configured for SCP02");
        }

        logger?.LogDebug("SCP02 preconditions validated successfully");
        return Result.Success<InitializeUpdateRequest, SmartCardError>(request);
    }

    private static Result<Scp02ChallengeData, SmartCardError> GenerateScp02CardChallenge(
        InitializeUpdateRequest request,
        CardState state,
        CardConfiguration config,
        ICryptographicService crypto,
        ILogger? logger = null)
    {
        logger?.LogDebug("=== GenerateScp02CardChallenge ===");
        logger?.LogDebug("Generating SCP02 card challenge for key version 0x{KeyVersion:X2}", request.KeyVersion);

        // Get sequence counter for the key version
        var sequenceCounter = state.GetSequenceCounter(request.KeyVersion);
        logger?.LogDebug("Sequence counter: {SequenceCounter}", Convert.ToHexString(sequenceCounter));

        // SCP02 card challenge is 6 random bytes (sequence counter is separate)
        logger?.LogDebug("Calling crypto.GenerateChallenge(6)");
        var challengeResult = crypto.GenerateChallenge(6);

        if (challengeResult.IsFailure)
        {
            logger?.LogError("Failed to generate card challenge: {Error}", challengeResult.Error.Message);
            return challengeResult.Error;
        }

        var cardChallenge = challengeResult.Value;
        logger?.LogDebug("Generated card challenge: {Challenge}", Convert.ToHexString(cardChallenge));

        var result = new Scp02ChallengeData(request, cardChallenge, sequenceCounter);
        logger?.LogDebug("=== GenerateScp02CardChallenge completed successfully ===");
        return Result.Success<Scp02ChallengeData, SmartCardError>(result);
    }

    private static Result<Scp02CryptogramData, SmartCardError> CalculateScp02CardCryptogram(
        Scp02ChallengeData data,
        CardState state,
        CardConfiguration config,
        ICryptographicService crypto,
        ILogger? logger = null)
    {
        logger?.LogDebug("=== CalculateScp02CardCryptogram ===");
        logger?.LogDebug("Calculating SCP02 card cryptogram");
        // Determine effective key version
        var effectiveKeyVersion = data.Request.KeyVersion;
        logger?.LogDebug("Requested key version: 0x{KeyVersion:X2}", data.Request.KeyVersion);

        if (effectiveKeyVersion == 0x00)
        {
            logger?.LogDebug("Key version 0x00 requested - looking for default key");
            effectiveKeyVersion = state.DefaultKeyVersion;
            logger?.LogDebug("State default key version: 0x{KeyVersion:X2}", effectiveKeyVersion);

            if (effectiveKeyVersion == 0xFF)
            {
                logger?.LogDebug("No default key version set - using first available static key");
                effectiveKeyVersion = config.StaticKeys.Keys.FirstOrDefault();
                logger?.LogDebug("First available static key version: 0x{KeyVersion:X2}", effectiveKeyVersion);
            }
        }

        logger?.LogDebug("Looking up key set for version: 0x{KeyVersion:X2}", effectiveKeyVersion);
        // Get the appropriate keys
        if (!TryGetKeySet(effectiveKeyVersion, state, config, out var keys, logger) || keys == null)
        {
            logger?.LogError("Failed to find key set for version 0x{KeyVersion:X2}", effectiveKeyVersion);
            logger?.LogError("Available installed keys: {InstalledKeys}", string.Join(", ", state.InstalledKeys.Keys.Select(k => $"0x{k:X2}")));
            logger?.LogError("Available static keys: {StaticKeys}", string.Join(", ", config.StaticKeys.Keys.Select(k => $"0x{k:X2}")));
            return SmartCardError.ReferencedDataNotFound();
        }

        logger?.LogDebug("Found key set for version 0x{KeyVersion:X2}, type: {KeyType}", effectiveKeyVersion, keys.GetType().Name);

        // Build SCP02 card cryptogram data
        // Format: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6) || Padding
        var cryptogramData = new byte[24]; // Will be padded to 3DES block size
        Array.Copy(data.Request.HostChallenge, 0, cryptogramData, 0, 8);
        Array.Copy(data.SequenceCounter, 0, cryptogramData, 8, 2);
        Array.Copy(data.CardChallenge, 0, cryptogramData, 10, 6);
        // Apply ISO 7816-4 padding
        cryptogramData[16] = 0x80;
        // Rest is already zeros

        logger?.LogDebug("Calling crypto.CalculateCardCryptogram with SCP version 0x02, implementation: {Impl}",
            state.ScpImplementation);

        logger?.LogDebug("Cryptogram calculation parameters:");
        logger?.LogDebug("  Host challenge: {HostChallenge}", Convert.ToHexString(data.Request.HostChallenge));
        logger?.LogDebug("  Card challenge (6 bytes random): {CardChallenge}", Convert.ToHexString(data.CardChallenge));
        logger?.LogDebug("  Sequence counter: {SeqCounter}", Convert.ToHexString(data.SequenceCounter));
        logger?.LogDebug("  SCP version: 0x02");
        logger?.LogDebug("  Implementation: 0x{Impl:X2}", (byte)state.ScpImplementation);

        // Pass the card challenge and sequence counter separately for proper separation of concerns
        var cryptogramResult = crypto.CalculateCardCryptogram(
                data.Request.HostChallenge,
                data.CardChallenge,  // 6-byte random challenge
                keys,
                0x02,
                (byte)state.ScpImplementation,
                data.SequenceCounter);  // 2-byte sequence counter

        if (cryptogramResult.IsFailure)
        {
            logger?.LogError("Cryptogram calculation failed: {Error}", cryptogramResult.Error.Message);
            return cryptogramResult.Error;
        }

        var cryptogram = cryptogramResult.Value;
        logger?.LogDebug("Cryptogram calculation successful: {Cryptogram}", Convert.ToHexString(cryptogram));

        var result = new Scp02CryptogramData(
            effectiveKeyVersion,
            state.ScpImplementation,
            data.Request.HostChallenge,
            data.CardChallenge,
            data.SequenceCounter,
            cryptogram,
            keys);

        logger?.LogDebug("=== CalculateScp02CardCryptogram completed successfully ===");
        return Result.Success<Scp02CryptogramData, SmartCardError>(result);
    }

    private static (ApduResponse, CardState) CreateScp02InitializeUpdateResponse(
        Scp02CryptogramData data,
        CardState state,
        CardConfiguration config,
        ILogger? logger = null)
    {
        logger?.LogDebug("=== CreateScp02InitializeUpdateResponse ===");
        logger?.LogDebug("Creating SCP02 INITIALIZE UPDATE response");
        logger?.LogDebug("Response data - KeyVersion: 0x{KeyVersion:X2}, Implementation: 0x{Impl:X2}",
            data.KeyVersion, (byte)data.Implementation);
        logger?.LogDebug("Sequence counter: {SeqCounter}, Card challenge: {CardChallenge}, Card cryptogram: {Cryptogram}",
            Convert.ToHexString(data.SequenceCounter),
            Convert.ToHexString(data.CardChallenge),
            Convert.ToHexString(data.CardCryptogram));

        // Build SCP02 INITIALIZE UPDATE response per GP spec Table E-8
        var response = new byte[28]; // Fixed size for SCP02
        var offset = 0;

        logger?.LogDebug("Creating response with {Length} bytes", response.Length);

        // Key diversification data (10 bytes)
        Array.Fill<byte>(response, 0x00, offset, 10);
        logger?.LogDebug("Added key diversification data (10 bytes of 0x00) at offset {Offset}", offset);
        offset += 10;

        // Key information (2 bytes) - Key version and SCP ID only
        response[offset++] = data.KeyVersion;
        response[offset++] = 0x02; // SCP02
        logger?.LogDebug("Added key info - version: 0x{KeyVersion:X2}, SCP: 0x02 at offset {Offset}",
            data.KeyVersion, offset - 2);
        // Note: Implementation parameter is NOT part of the response

        // Sequence counter (2 bytes)
        Array.Copy(data.SequenceCounter, 0, response, offset, 2);
        logger?.LogDebug("Added sequence counter at offset {Offset}", offset);
        offset += 2;

        // Card challenge (6 bytes)
        Array.Copy(data.CardChallenge, 0, response, offset, 6);
        logger?.LogDebug("Added card challenge at offset {Offset}", offset);
        offset += 6;

        // Card cryptogram (8 bytes)
        Array.Copy(data.CardCryptogram, 0, response, offset, 8);
        logger?.LogDebug("Added card cryptogram at offset {Offset}", offset);

        logger?.LogDebug("Response constructed - Final length: {Length}", response.Length);
        logger?.LogDebug("Full response data: {Response}", Convert.ToHexString(response));

        // Update state with challenge data
        var fullCardChallenge = CombineSequenceAndChallenge(data.SequenceCounter, data.CardChallenge);
        var newState = state
            .WithChallenges(data.HostChallenge, fullCardChallenge)
            .WithKeys(data.Keys)
            .WithIncrementedSequenceCounter(data.KeyVersion); // Increment for next use

        logger?.LogDebug("State updated with challenges and keys");
        logger?.LogDebug("=== CreateScp02InitializeUpdateResponse completed ===");
        logger?.LogDebug("Returning SCP02 response with SW 9000");
        return (new ApduResponse(response, StatusWords.Success), newState);
    }

    private static Result<ExternalAuthenticateRequest, SmartCardError> ParseExternalAuthenticateCommand(byte[] command)
    {
        if (command.Length < 5)
            return SmartCardError.WrongLength();

        if (command[0] != 0x84 || command[1] != 0x82)
            return SmartCardError.InstructionNotSupported();

        var securityLevel = command[2];
        var p2 = command[3];
        var lc = command[4];

        // For SCP02, expect 16 bytes (8 byte cryptogram + 8 byte MAC)
        if (lc != 16 || command.Length != 21)
            return SmartCardError.WrongLength();

        var hostCryptogram = command.Skip(5).Take(8).ToArray();
        var hostMac = command.Skip(13).Take(8).ToArray();

        return Result.Success<ExternalAuthenticateRequest, SmartCardError>(
            new ExternalAuthenticateRequest(securityLevel, hostCryptogram, hostMac));
    }

    private static Result<ExternalAuthenticateRequest, SmartCardError> ValidateScp02ExternalAuthPreconditions(
        ExternalAuthenticateRequest request,
        CardState state)
    {
        if (!state.IsSelected)
            return SmartCardError.ConditionsNotSatisfied();

        if (state.HostChallenge == null || state.CardChallenge == null)
            return SmartCardError.ConditionsNotSatisfied();

        if (state.CurrentKeys == null)
            return SmartCardError.ConditionsNotSatisfied();

        // Validate security level for SCP02
        var validLevels = new[] { 0x00, 0x01, 0x03 }; // None, C-MAC, C-DECRYPTION
        if (!validLevels.Contains(request.SecurityLevel))
            return SmartCardError.InvalidArgument($"Invalid security level for SCP02: {request.SecurityLevel:X2}");

        return Result.Success<ExternalAuthenticateRequest, SmartCardError>(request);
    }

    private static Result<ExternalAuthenticateRequest, SmartCardError> VerifyScp02HostCryptogram(
        ExternalAuthenticateRequest request,
        CardState state,
        ICryptographicService crypto)
    {
        if (state.HostChallenge == null || state.CardChallenge == null || state.CurrentKeys == null)
            return SmartCardError.ConditionsNotSatisfied();

        // Extract sequence counter from the card challenge (first 2 bytes)
        var sequenceCounter = state.CardChallenge.Take(2).ToArray();
        var cardChallengeRandom = state.CardChallenge.Skip(2).Take(6).ToArray();

        // Calculate expected host cryptogram
        return crypto.CalculateHostCryptogram(
                state.HostChallenge,
                cardChallengeRandom,  // 6-byte random part only
                state.CurrentKeys,
                0x02,
                (byte)state.ScpImplementation,
                sequenceCounter)     // 2-byte sequence counter
            .Bind(expectedCryptogram =>
            {
                if (!request.HostCryptogram.SequenceEqual(expectedCryptogram))
                    return SmartCardError.SecurityStatusNotSatisfied();

                // Verify the MAC on the EXTERNAL AUTHENTICATE command if security level requires it
                if (request.SecurityLevel != 0x00)
                {
                    // For SCP02 with C-MAC, we need to verify the command MAC
                    // The MAC should be calculated over the command header + data
                    // Command structure: CLA=84 INS=82 P1=SecurityLevel P2=00 LC=10 Data=HostCryptogram
                    return VerifyScp02CommandMac(request, state, crypto);
                }

                return Result.Success<ExternalAuthenticateRequest, SmartCardError>(request);
            });
    }

    private static Result<ExternalAuthenticateRequest, SmartCardError> VerifyScp02CommandMac(
        ExternalAuthenticateRequest request,
        CardState state,
        ICryptographicService crypto)
    {
        // Derive session keys first to get the MAC key
        return DeriveScp02SessionKeys(request, state, crypto)
            .Bind(sessionKeys =>
            {
                // Construct the command data that was MACed
                // CLA=84 INS=82 P1=SecurityLevel P2=00 LC=10 Data=HostCryptogram
                byte[] commandHeader = [0x84, 0x82, request.SecurityLevel, 0x00, 0x10];
                byte[] macInput = commandHeader.Concat(request.HostCryptogram).ToArray();

                // Emulator: use AES-CMAC over the input with S-MAC (simplified)
                return crypto.CalculateAesCmac(sessionKeys.SMac, macInput)
                    .Bind(expectedMac =>
                    {
                        // Compare first 8 bytes
                        byte[] truncated = expectedMac.Take(8).ToArray();
                        if (!request.HostMac.SequenceEqual(truncated))
                        {
                            return Result.Failure<ExternalAuthenticateRequest, SmartCardError>(
                                SmartCardError.SecurityStatusNotSatisfied());
                        }
                        return Result.Success<ExternalAuthenticateRequest, SmartCardError>(request);
                    });
            });
    }

    private static Result<SessionKeys, SmartCardError> DeriveScp02SessionKeys(
        ExternalAuthenticateRequest request,
        CardState state,
        ICryptographicService crypto)
    {
        if (state.HostChallenge == null || state.CardChallenge == null || state.CurrentKeys == null)
            return SmartCardError.ConditionsNotSatisfied();

        // Derive session keys based on implementation option
        if (state.CurrentKeys is not Scp02KeySet scp02Keys)
            return SmartCardError.InvalidArgument("SCP02 requires SCP02 key set");

        // Check implementation option for static vs dynamic MAC
        var useStaticMac = state.ScpImplementation.HasIcvEncryption();

        return crypto.DeriveSessionKeys(
            state.CurrentKeys,
            state.HostChallenge,
            state.CardChallenge,
            0x02)
            .Map(sessionKeys =>
            {
                // For static MAC implementations, override MAC key with static key
                if (useStaticMac)
                {
                    return new Gp4Net.Domain.Keys.SessionKeys(
                        sessionKeys.SEnc,
                        scp02Keys.MacKey, // Use static MAC key
                        scp02Keys.MacKey, // R-MAC also uses static MAC key
                        sessionKeys.Dek
                    );
                }
                return sessionKeys;
            });
    }

    private static (ApduResponse, CardState) CreateScp02ExternalAuthResponse(
        SessionKeys sessionKeys,
        CardState state)
    {
        // Create functional secure channel state for SCP02
        var securityLevel = (SecurityLevel)0x01; // Basic C-MAC
        var secureChannelStateResult = SecureChannelState.Create(
            sessionKeys: sessionKeys,
            securityLevel: securityLevel,
            protocolVersion: 0x02,
            initialMacChainingValue: new byte[8], // Initialize with zeros for SCP02
            implementationParameter: (byte)state.ScpImplementation
        );

        if (secureChannelStateResult.IsFailure)
        {
            return (new ApduResponse([], StatusWords.AuthenticationMethodBlocked), state);
        }

        var secureChannelState = secureChannelStateResult.Value;

        // Update state with established secure channel using functional approach
        var newState = state.WithSecureChannel(secureChannelState);

        // SCP02 EXTERNAL AUTHENTICATE response is typically empty on success
        return (new ApduResponse([], StatusWords.Success), newState);
    }

    // Utility methods

    private static bool TryGetKeySet(byte keyVersion, CardState state, CardConfiguration config, out IKeySet? keySet, ILogger? logger = null)
    {
        keySet = null;

        // Log available keys
        var installedKeyVersions = string.Join(", ", state.InstalledKeys.Keys.Select(k => $"0x{k:X2}"));
        var staticKeyVersions = string.Join(", ", config.StaticKeys.Keys.Select(k => $"0x{k:X2}"));
        logger?.LogDebug("Available keys - Installed: [{InstalledKeys}], Static: [{StaticKeys}]",
            installedKeyVersions, staticKeyVersions);

        // Check installed keys first
        if (state.InstalledKeys.TryGetValue(keyVersion, out var installedKeys))
        {
            logger?.LogDebug("Found key 0x{KeyVersion:X2} in installed keys", keyVersion);
            keySet = installedKeys;
            return true;
        }

        // Then check static keys
        if (config.StaticKeys.TryGetValue(keyVersion, out var staticKeys))
        {
            logger?.LogDebug("Found key 0x{KeyVersion:X2} in static keys", keyVersion);
            keySet = staticKeys;
            return true;
        }

        // If key version is 0x00 or 0xFF, try to find any available key
        if (keyVersion is 0x00 or 0xFF)
        {
            logger?.LogDebug("Key version 0x{KeyVersion:X2} is default marker - searching for any available key", keyVersion);
            keySet = config.StaticKeys.Values.FirstOrDefault();
            if (keySet != null)
            {
                logger?.LogDebug("Using first available static key");
                return true;
            }
            logger?.LogWarning("No keys available at all");
            return false;
        }

        logger?.LogWarning("Key version {KeyVersion:X2} not found in installed or static keys", keyVersion);
        return false;
    }

    private static byte[] CombineSequenceAndChallenge(byte[] sequenceCounter, byte[] cardChallenge)
    {
        // SCP02 full card challenge is sequence counter (2 bytes) + random (6 bytes)
        var fullChallenge = new byte[8];
        Array.Copy(sequenceCounter, 0, fullChallenge, 0, 2);
        Array.Copy(cardChallenge, 0, fullChallenge, 2, 6);
        return fullChallenge;
    }

    /// <summary>
    /// Checks if a command should be processed as SCP02.
    /// </summary>
    public static bool IsScp02Command(byte[] command, CardState state, ILogger? logger = null)
    {
        if (command.Length < 2)
        {
            logger?.LogTrace("Command too short for SCP check");
            return false;
        }

        // Check if it's INITIALIZE UPDATE or EXTERNAL AUTHENTICATE
        var cla = command[0];
        var ins = command[1];

        logger?.LogTrace("Checking SCP02 command: CLA={Cla:X2} INS={Ins:X2}, card SCP={Scp:X2}",
            cla, ins, state.ScpVersion);

        if ((cla == 0x80 && ins == 0x50) || (cla == 0x84 && ins == 0x82))
        {
            // Check if card is configured for SCP02
            var isScp02 = state.ScpVersion == 0x02;
            logger?.LogDebug("INITIALIZE UPDATE/EXTERNAL AUTHENTICATE detected, SCP02 check: {IsScp02}", isScp02);
            return isScp02;
        }

        // Check if secure channel is established with SCP02
        var result = state is { IsSecureChannelEstablished: true, ScpVersion: 0x02 };
        logger?.LogTrace("Other command, SCP02 secure channel check: {Result}", result);
        return result;
    }
}
