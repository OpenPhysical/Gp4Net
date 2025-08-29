// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Core.Functional;
using Gp4Net.Domain.Security;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Unified channel processor that handles command wrapping and response unwrapping for both SCP02 and SCP03.
/// Consolidates all secure messaging operations into a single functional service.
/// Per GlobalPlatform Card Specification v2.3.1 Appendix E "Secure Channel Protocol".
/// </summary>
[PublicAPI]
public sealed class ScpChannelProcessor
{
    /// <summary>
    /// Private constructor for functional creation pattern.
    /// </summary>
    private ScpChannelProcessor()
    {
        // Pure functional processor with no dependencies
    }

    /// <summary>
    /// Creates a new ScpChannelProcessor instance.
    /// </summary>
    /// <returns>A result containing the processor or error.</returns>
    public static Result<ScpChannelProcessor, SmartCardError> Create()
    {
        return Result.Success<ScpChannelProcessor, SmartCardError>(new ScpChannelProcessor());
    }

    /// <summary>
    /// Applies command security (C-MAC, C-ENC) to an APDU command based on the secure channel state.
    /// Handles both SCP02 and SCP03 protocols transparently.
    /// </summary>
    /// <param name="command">The command to secure.</param>
    /// <param name="state">The current secure channel state.</param>
    /// <returns>A result containing the secured command and updated state or error.</returns>
    public Result<(byte[] securedCommand, SecureChannelState newState), SmartCardError> ApplyCommandSecurity(
        IApduCommand command,
        SecureChannelState state)
    {
        return ValidateCommandSecurityInputs(command, state)
            .ToResult()
            .Bind(_ => state.ProtocolVersion switch
            {
                ScpVersion.Scp02 => ApplyScp02CommandSecurity(command, state),
                ScpVersion.Scp03 => ApplyScp03CommandSecurity(command, state),
                _ => SmartCardError.InvalidArgument($"Unsupported protocol version: {state.ProtocolVersion:X2}")
            });
    }

    /// <summary>
    /// Applies response security (R-MAC verification, R-ENC decryption) to an APDU response.
    /// Handles both SCP02 and SCP03 protocols transparently.
    /// </summary>
    /// <param name="response">The response to process.</param>
    /// <param name="state">The current secure channel state.</param>
    /// <returns>A result containing the processed response and updated state or error.</returns>
    public Result<(byte[] processedResponse, SecureChannelState newState), SmartCardError> ApplyResponseSecurity(
        byte[] response,
        SecureChannelState state)
    {
        return ValidateResponseSecurityInputs(response, state)
            .ToResult()
            .Bind(_ => state.ProtocolVersion switch
            {
                ScpVersion.Scp02 => ApplyScp02ResponseSecurity(response, state),
                ScpVersion.Scp03 => ApplyScp03ResponseSecurity(response, state),
                _ => SmartCardError.InvalidArgument($"Unsupported protocol version: {state.ProtocolVersion:X2}")
            });
    }

    // Private implementation methods for SCP02

    private static Result<(byte[], SecureChannelState), SmartCardError> ApplyScp02CommandSecurity(
        IApduCommand command,
        SecureChannelState state)
    {
        byte[] commandBytes = command.ToByteArray();
        
        // Apply SCP02 command security using existing protocol methods
        return Scp02Protocol.ApplyCommandSecurity(
            commandBytes,
            state.SecurityLevel,
            state.SessionKeys,
            state.MacChainingValue)
            .Bind(result =>
                state.UpdateMacChainingValue(result.newChainingValue)
                    .Map(newState => (result.securedCommand, newState)));
    }

    private static Result<(byte[], SecureChannelState), SmartCardError> ApplyScp02ResponseSecurity(
        byte[] response,
        SecureChannelState state)
    {
        // Apply SCP02 response security using existing protocol methods
        return Scp02Protocol.ApplyResponseSecurity(
            response,
            state.SecurityLevel,
            state.SessionKeys,
            state.MacChainingValue,
            state.EncryptionCounter)
            .Bind(result =>
                state.UpdateMacChainingValue(result.newChainingValue)
                    .Map(newState => (result.securedResponse, newState)));
    }

    // Private implementation methods for SCP03

    private static Result<(byte[], SecureChannelState), SmartCardError> ApplyScp03CommandSecurity(
        IApduCommand command,
        SecureChannelState state)
    {
        byte[] commandBytes = command.ToByteArray();
        
        // For SCP03, we need to apply security step by step
        return ApplyScp03CommandMac(commandBytes, state)
            .Bind(macResult => state.SecurityLevel.HasCEncryption()
                ? ApplyScp03CommandEncryption(macResult.commandWithMac, macResult.newState)
                : Result.Success<(byte[], SecureChannelState), SmartCardError>(macResult));
    }

    private static Result<(byte[], SecureChannelState), SmartCardError> ApplyScp03ResponseSecurity(
        byte[] response,
        SecureChannelState state)
    {
        // For SCP03, we need to process security step by step
        return state.SecurityLevel.HasRMac()
            ? VerifyScp03ResponseMac(response, state)
                .Bind(verifyResult => state.SecurityLevel.HasREncryption()
                    ? DecryptScp03Response(verifyResult.verifiedResponse, verifyResult.newState)
                    : Result.Success<(byte[], SecureChannelState), SmartCardError>(verifyResult))
            : state.SecurityLevel.HasREncryption()
                ? DecryptScp03Response(response, state)
                : Result.Success<(byte[], SecureChannelState), SmartCardError>((response, state));
    }

    // Helper methods for SCP03 operations

    private static Result<(byte[] commandWithMac, SecureChannelState newState), SmartCardError> ApplyScp03CommandMac(
        byte[] command,
        SecureChannelState state)
    {
        // Build MAC input per SCP03 specification
        byte[] macInput = BuildScp03MacInput(state.MacChainingValue, command);
        
        return MacCalculations.CalculateScp03CommandMac(state.SessionKeys.SMac, macInput)
            .Bind(mac =>
            {
                // Truncate MAC to 8 bytes for SCP03
                byte[] truncatedMac = mac.Take(8).ToArray();
                
                // Append MAC to command
                byte[] commandWithMac = CryptographicOperations.ConcatenateArrays(command, truncatedMac);
                
                // Set secure messaging bit in CLA
                if (commandWithMac.Length > 0)
                    commandWithMac[0] |= 0x04;
                
                // Update state with new MAC chaining value (full MAC for SCP03)
                return state.UpdateMacChainingValue(mac)
                    .Map(newState => (commandWithMac, newState));
            });
    }

    private static Result<(byte[] commandWithEncryption, SecureChannelState newState), SmartCardError> ApplyScp03CommandEncryption(
        byte[] command,
        SecureChannelState state)
    {
        // Extract command data for encryption (skip header and MAC)
        if (command.Length <= 5 + 8) // No data to encrypt
            return Result.Success<(byte[], SecureChannelState), SmartCardError>((command, state));

        byte lc = command[4];
        if (lc <= 8) // Only MAC present
            return Result.Success<(byte[], SecureChannelState), SmartCardError>((command, state));

        // Extract data portion (excluding MAC)
        byte[] dataToEncrypt = new byte[lc - 8];
        Array.Copy(command, 5, dataToEncrypt, 0, dataToEncrypt.Length);

        // Build SCP03 encryption IV using counter
        byte[] iv = BuildScp03EncryptionIv(state.EncryptionCounter);
        
        return CryptographicOperations.EncryptAesCbc(state.SessionKeys.SEnc, iv, dataToEncrypt)
            .Map(encryptedData =>
            {
                // Rebuild command with encrypted data
                byte[] newCommand = new byte[5 + encryptedData.Length + 8]; // Header + encrypted data + MAC
                Array.Copy(command, 0, newCommand, 0, 4); // CLA INS P1 P2
                newCommand[4] = (byte)(encryptedData.Length + 8); // New Lc
                Array.Copy(encryptedData, 0, newCommand, 5, encryptedData.Length);
                Array.Copy(command, command.Length - 8, newCommand, newCommand.Length - 8, 8); // MAC
                
                // Increment encryption counter
                SecureChannelState newState = state.IncrementEncryptionCounter();
                
                return (newCommand, newState);
            });
    }

    private static Result<(byte[] verifiedResponse, SecureChannelState newState), SmartCardError> VerifyScp03ResponseMac(
        byte[] response,
        SecureChannelState state)
    {
        if (response.Length < 10) // At least status word + MAC
            return SmartCardError.InvalidArgument("Response too short for R-MAC verification");

        // Extract MAC (8 bytes before status word)
        byte[] receivedMac = new byte[8];
        Array.Copy(response, response.Length - 10, receivedMac, 0, 8);
        
        // Extract response data without MAC
        byte[] responseWithoutMac = new byte[response.Length - 8];
        Array.Copy(response, 0, responseWithoutMac, 0, response.Length - 10); // Data
        Array.Copy(response, response.Length - 2, responseWithoutMac, responseWithoutMac.Length - 2, 2); // Status
        
        // Build MAC input
        byte[] macInput = BuildScp03MacInput(state.MacChainingValue, responseWithoutMac);
        
        return MacCalculations.CalculateScp03ResponseMac(state.SessionKeys.SrMac, macInput)
            .Bind(calculatedMac =>
            {
                byte[] expectedMac = calculatedMac.Take(8).ToArray();
                if (!CryptographicOperations.CompareBytes(expectedMac, receivedMac))
                {
                    return SmartCardError.SecurityError("R-MAC verification failed");
                }
                
                // Update state with new MAC chaining value
                return state.UpdateMacChainingValue(calculatedMac)
                    .Map(newState => (responseWithoutMac, newState));
            });
    }

    private static Result<(byte[], SecureChannelState), SmartCardError> DecryptScp03Response(
        byte[] response,
        SecureChannelState state)
    {
        if (response.Length <= 2) // Only status word
            return Result.Success<(byte[], SecureChannelState), SmartCardError>((response, state));

        // Extract encrypted data (everything except status word)
        byte[] encryptedData = new byte[response.Length - 2];
        Array.Copy(response, 0, encryptedData, 0, encryptedData.Length);
        
        // Build decryption IV using counter
        byte[] iv = BuildScp03EncryptionIv(state.EncryptionCounter);
        
        return CryptographicOperations.DecryptAesCbc(state.SessionKeys.SEnc, iv, encryptedData)
            .Map(decryptedData =>
            {
                // Rebuild response with decrypted data
                byte[] newResponse = new byte[decryptedData.Length + 2];
                Array.Copy(decryptedData, 0, newResponse, 0, decryptedData.Length);
                Array.Copy(response, response.Length - 2, newResponse, newResponse.Length - 2, 2); // Status
                
                return (newResponse, state);
            });
    }

    // Helper methods for input validation

    private static UnitResult<SmartCardError> ValidateCommandSecurityInputs(IApduCommand command, SecureChannelState state)
    {
        return Maybe<IApduCommand>.From(command)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Bind(_ => Maybe<SecureChannelState>.From(state)
                .ToResult(SmartCardError.InvalidArgument("State cannot be null")))
            .ToUnitResult();
    }

    private static UnitResult<SmartCardError> ValidateResponseSecurityInputs(byte[] response, SecureChannelState state)
    {
        return Maybe<byte[]>.From(response)
            .ToResult(SmartCardError.InvalidArgument("Response cannot be null"))
            .Bind(_ => Maybe<SecureChannelState>.From(state)
                .ToResult(SmartCardError.InvalidArgument("State cannot be null")))
            .Bind(_ => response.Length >= 2
                ? UnitResult.Success<SmartCardError>()
                : SmartCardError.InvalidArgument("Response must be at least 2 bytes"))
            .ToUnitResult();
    }

    // Helper methods for SCP03 cryptographic operations

    private static byte[] BuildScp03MacInput(byte[] chainingValue, byte[] data)
    {
        byte[] macInput = new byte[chainingValue.Length + data.Length];
        Array.Copy(chainingValue, 0, macInput, 0, chainingValue.Length);
        Array.Copy(data, 0, macInput, chainingValue.Length, data.Length);
        return macInput;
    }

    private static byte[] BuildScp03EncryptionIv(uint counter)
    {
        byte[] iv = new byte[16];
        // Place counter in bytes 12-15 (big-endian)
        iv[12] = (byte)((counter >> 24) & 0xFF);
        iv[13] = (byte)((counter >> 16) & 0xFF);
        iv[14] = (byte)((counter >> 8) & 0xFF);
        iv[15] = (byte)(counter & 0xFF);
        return iv;
    }
}
