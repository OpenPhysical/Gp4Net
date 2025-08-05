using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// SCP02 protocol service implementation using static virtual members.
/// Provides pure functions for all SCP02-specific cryptographic operations.
/// </summary>
[PublicAPI]
public sealed class Scp02ProtocolService : IScpProtocolService<Scp02ProtocolService>
{
    /// <inheritdoc />
    public static byte ProtocolVersion
    {
        get
        {
            return 0x02;
        }
    }

    /// <inheritdoc />
    public static int MacSize
    {
        get
        {
            return 8;

            // Full MAC (not truncated in SCP02)
        }
    }

    /// <inheritdoc />
    public static int ChainingValueSize
    {
        get
        {
            return 8;

            // 3DES block size
        }
    }

    /// <inheritdoc />
    public static Result<byte[], SmartCardError> CalculateCommandMac(
        byte[] command,
        byte[] macKey,
        byte[] chainingValue)
    {
        if (command == null)
        {
            return SmartCardError.InvalidArgument("Command cannot be null");
        }

        if (macKey == null)
        {
            return SmartCardError.InvalidArgument("MAC key cannot be null");
        }

        if (chainingValue == null)
        {
            return SmartCardError.InvalidArgument("Chaining value cannot be null");
        }

        if (chainingValue.Length != ChainingValueSize)
        {
            return SmartCardError.InvalidArgument($"Chaining value must be {ChainingValueSize} bytes for SCP02");
        }

        // SCP02 C-MAC: 3DES-MAC over (chaining_value || command) using ISO 9797-1 Algorithm 3
        var macInput = new byte[chainingValue.Length + command.Length];
        Array.Copy(chainingValue, 0, macInput, 0, chainingValue.Length);
        Array.Copy(command, 0, macInput, chainingValue.Length, command.Length);

        return CryptographicOperations.CalculateRetailMac(macKey, macInput);
    }

    /// <inheritdoc />
    public static Result<byte[], SmartCardError> CalculateResponseMac(
        byte[] response,
        byte[] rMacKey,
        byte[] chainingValue)
    {
        if (response == null)
        {
            return SmartCardError.InvalidArgument("Response cannot be null");
        }

        if (rMacKey == null)
        {
            return SmartCardError.InvalidArgument("R-MAC key cannot be null");
        }

        if (chainingValue == null)
        {
            return SmartCardError.InvalidArgument("Chaining value cannot be null");
        }

        if (chainingValue.Length != ChainingValueSize)
        {
            return SmartCardError.InvalidArgument($"Chaining value must be {ChainingValueSize} bytes for SCP02");
        }

        // SCP02 R-MAC: 3DES-MAC over (chaining_value || response) using ISO 9797-1 Algorithm 3
        var macInput = new byte[chainingValue.Length + response.Length];
        Array.Copy(chainingValue, 0, macInput, 0, chainingValue.Length);
        Array.Copy(response, 0, macInput, chainingValue.Length, response.Length);

        return CryptographicOperations.CalculateRetailMac(rMacKey, macInput);
    }

    /// <inheritdoc />
    public static Result<byte[], SmartCardError> CalculateInitialMacChainingValue(
        ExternalAuthenticateCommand command,
        byte[] macKey)
    {
        if (command == null)
        {
            return SmartCardError.InvalidArgument("Command cannot be null");
        }

        if (macKey == null)
        {
            return SmartCardError.InvalidArgument("MAC key cannot be null");
        }

        // Build the EXTERNAL AUTHENTICATE APDU for MAC calculation
        // This must match exactly what the client calculates MAC over
        var apdu = new byte[5 + command.HostCryptogram.Length];
        apdu[0] = (byte)(command.Cla | 0x04); // CLA with secure messaging bit
        apdu[1] = command.Ins; // 0x82
        apdu[2] = (byte)command.SecurityLevel; // P1 = security level
        apdu[3] = 0x00; // P2
        apdu[4] = (byte)(command.HostCryptogram.Length + MacSize); // Lc = 8 host cryptogram + 8 MAC
        Array.Copy(command.HostCryptogram, 0, apdu, 5, command.HostCryptogram.Length);

        // Calculate 3DES-MAC over (zero_chaining_value || apdu)
        // For EXTERNAL AUTHENTICATE in SCP02, the initial chaining value is zeros
        var zeroChaining = new byte[ChainingValueSize];
        var macInput = new byte[zeroChaining.Length + apdu.Length];
        Array.Copy(zeroChaining, 0, macInput, 0, zeroChaining.Length);
        Array.Copy(apdu, 0, macInput, zeroChaining.Length, apdu.Length);

        // Return the full 8-byte MAC for use as chaining value
        return CryptographicOperations.CalculateRetailMac(macKey, macInput);
    }

    /// <inheritdoc />
    public static Result<(byte[] securedCommand, byte[] newChainingValue), SmartCardError> ApplyCommandSecurity(
        byte[] command,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        byte[] chainingValue)
    {
        if (command == null)
        {
            return SmartCardError.InvalidArgument("Command cannot be null");
        }

        if (sessionKeys == null)
        {
            return SmartCardError.InvalidArgument("Session keys cannot be null");
        }

        if (chainingValue == null)
        {
            return SmartCardError.InvalidArgument("Chaining value cannot be null");
        }

        if (chainingValue.Length != ChainingValueSize)
        {
            return SmartCardError.InvalidArgument($"Chaining value must be {ChainingValueSize} bytes for SCP02");
        }

        var processedCommand = command;
        var newChainingValue = chainingValue;

        // Apply C-ENCRYPTION if required
        if (securityLevel.HasCEncryption())
        {
            var encryptResult = ApplyCommandEncryption(processedCommand, sessionKeys.SEnc);
            if (encryptResult.IsFailure)
            {
                return encryptResult.Error;
            }

            processedCommand = encryptResult.Value;
        }

        // Apply C-MAC if required
        if (!securityLevel.HasCMac())
        {
            return Result.Success<(byte[], byte[]), SmartCardError>((processedCommand, newChainingValue));
        }
        var macResult = CalculateCommandMac(processedCommand, sessionKeys.SMac, chainingValue);
        if (macResult.IsFailure)
        {
            return macResult.Error;
        }

        var mac = macResult.Value;

        // For SCP02, the chaining value is updated with the full MAC result
        newChainingValue = mac;

        // Append MAC to command
        var securedCommand = new byte[processedCommand.Length + MacSize];
        Array.Copy(processedCommand, 0, securedCommand, 0, processedCommand.Length);
        Array.Copy(mac, 0, securedCommand, processedCommand.Length, MacSize);
        processedCommand = securedCommand;

        // Set secure messaging bit in CLA
        processedCommand[0] |= 0x04;

        return Result.Success<(byte[], byte[]), SmartCardError>((processedCommand, newChainingValue));
    }

    /// <inheritdoc />
    public static Result<(byte[] securedResponse, byte[] newChainingValue), SmartCardError> ApplyResponseSecurity(
        byte[] response,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        byte[] chainingValue,
        uint encryptionCounter = 0)
    {
        if (response == null)
        {
            return SmartCardError.InvalidArgument("Response cannot be null");
        }

        if (response.Length < 2)
        {
            return SmartCardError.InvalidArgument("Response must contain at least status word");
        }

        if (sessionKeys == null)
        {
            return SmartCardError.InvalidArgument("Session keys cannot be null");
        }

        if (chainingValue == null)
        {
            return SmartCardError.InvalidArgument("Chaining value cannot be null");
        }

        if (chainingValue.Length != ChainingValueSize)
        {
            return SmartCardError.InvalidArgument($"Chaining value must be {ChainingValueSize} bytes for SCP02");
        }

        var processedResponse = response;
        var newChainingValue = chainingValue;

        // Check if response security should be applied based on status word
        var statusWord = (ushort)((response[response.Length - 2] << 8) | response[response.Length - 1]);
        if (!ShouldApplyResponseSecurity(statusWord))
        {
            return Result.Success<(byte[], byte[]), SmartCardError>((processedResponse, newChainingValue));
        }

        // Apply R-ENCRYPTION if required
        if (securityLevel.HasREncryption() && HasResponseData(response))
        {
            var encryptResult = ApplyResponseEncryption(processedResponse, sessionKeys.SEnc);
            if (encryptResult.IsFailure)
            {
                return encryptResult.Error;
            }

            processedResponse = encryptResult.Value;
        }

        // Apply R-MAC if required
        if (securityLevel.HasRMac())
        {
            var macResult = CalculateResponseMac(processedResponse, sessionKeys.SrMac, chainingValue);
            if (macResult.IsFailure)
            {
                return macResult.Error;
            }

            var mac = macResult.Value;

            // For SCP02, the chaining value is updated with the full MAC result
            newChainingValue = mac;

            // Insert R-MAC before status word
            var statusOffset = processedResponse.Length - 2;
            var securedResponse = new byte[processedResponse.Length + MacSize];
            Array.Copy(processedResponse, 0, securedResponse, 0, statusOffset); // Data
            Array.Copy(mac, 0, securedResponse, statusOffset, MacSize); // R-MAC
            Array.Copy(processedResponse, statusOffset, securedResponse, securedResponse.Length - 2, 2); // Status
            processedResponse = securedResponse;
        }

        return Result.Success<(byte[], byte[]), SmartCardError>((processedResponse, newChainingValue));
    }

    // Helper methods

    private static Result<byte[], SmartCardError> ApplyCommandEncryption(byte[] command, byte[] sEncKey)
    {
        if (command.Length <= 5) // No data to encrypt
        {
            return Result.Success<byte[], SmartCardError>(command);
        }

        var lc = command[4];
        if (lc == 0 || command.Length < 5 + lc)
        {
            return Result.Success<byte[], SmartCardError>(command);
        }

        // Extract data to encrypt
        var dataToEncrypt = new byte[lc];
        Array.Copy(command, 5, dataToEncrypt, 0, lc);

        // Apply PKCS#7 padding for 8-byte blocks (3DES)
        return CryptographicOperations.ApplyPkcs7Padding(dataToEncrypt, 8)
            .Bind(paddedData =>
            {
                // For SCP02 C-ENC, use zero IV
                var iv = new byte[8];
                return CryptographicOperations.Encrypt3DesCbc(sEncKey, iv, paddedData);
            })
            .Map(encryptedData =>
            {
                // Build new command with encrypted data
                var newCommand = new byte[5 + encryptedData.Length + (command.Length > 5 + lc ? 1 : 0)];
                Array.Copy(command, 0, newCommand, 0, 4); // CLA INS P1 P2
                newCommand[0] |= 0x04; // Set secure messaging bit
                newCommand[4] = (byte)(encryptedData.Length + MacSize); // New Lc includes MAC
                Array.Copy(encryptedData, 0, newCommand, 5, encryptedData.Length);

                // Copy Le if present
                if (command.Length > 5 + lc)
                {
                    newCommand[newCommand.Length - 1] = command[command.Length - 1];
                }

                return newCommand;
            });
    }

    private static Result<byte[], SmartCardError> ApplyResponseEncryption(
        byte[] response,
        byte[] sEncKey)
    {
        var statusOffset = response.Length - 2;
        if (statusOffset <= 0) // No data to encrypt
        {
            return Result.Success<byte[], SmartCardError>(response);
        }

        var responseData = new byte[statusOffset];
        Array.Copy(response, 0, responseData, 0, statusOffset);

        // For SCP02 R-ENC, use zero IV
        var iv = new byte[8];

        return CryptographicOperations.ApplyPkcs7Padding(responseData, 8)
            .Bind(paddedData => CryptographicOperations.Encrypt3DesCbc(sEncKey, iv, paddedData))
            .Map(encryptedData =>
            {
                // Combine encrypted data with original status word
                var result = new byte[encryptedData.Length + 2];
                Array.Copy(encryptedData, 0, result, 0, encryptedData.Length);
                Array.Copy(response, statusOffset, result, encryptedData.Length, 2);
                return result;
            });
    }

    private static bool ShouldApplyResponseSecurity(ushort statusWord)
    {
        // Only apply response security for success and warning status words per GP spec
        return statusWord == 0x9000 ||
               (statusWord & 0xFF00) == 0x6200 ||
               (statusWord & 0xFF00) == 0x6300;
    }

    private static bool HasResponseData(byte[] response) => response.Length > 2;

    /// <inheritdoc />
    public static Result<Security.MacChainingState, SmartCardError> UpdateChainingAfterCMac(
        Security.MacChainingState current,
        byte[] commandData,
        byte[] macKey)
    {
        if (current == null)
        {
            return SmartCardError.InvalidArgument("Current chaining state cannot be null");
        }

        if (commandData == null)
        {
            return SmartCardError.InvalidArgument("Command data cannot be null");
        }

        if (macKey == null)
        {
            return SmartCardError.InvalidArgument("MAC key cannot be null");
        }

        // For SCP02, the new chaining value is the 8-byte MAC calculated over
        // (current_chaining_value || command_data)
        var macInput = new byte[current.Value.Length + commandData.Length];
        current.Value.CopyTo(macInput, 0);
        Array.Copy(commandData, 0, macInput, current.Value.Length, commandData.Length);

        return CryptographicOperations.CalculateRetailMac(macKey, macInput)
            .Bind(fullMac => current.UpdateValue(fullMac));
    }

    /// <inheritdoc />
    public static Result<Security.MacChainingState, SmartCardError> UpdateChainingAfterRMac(
        Security.MacChainingState current,
        byte[] responseData,
        byte[] rmacKey)
    {
        if (current == null)
        {
            return SmartCardError.InvalidArgument("Current chaining state cannot be null");
        }

        // Check if this implementation updates chaining after R-MAC
        if (current.ShouldUpdateChainingAfterRMac())
        {
            // For implementations that update (like i=05), calculate new chaining value
            var macInput = new byte[current.Value.Length + responseData.Length];
            current.Value.CopyTo(macInput, 0);
            Array.Copy(responseData, 0, macInput, current.Value.Length, responseData.Length);

            return CryptographicOperations.CalculateRetailMac(rmacKey, macInput)
                .Bind(fullMac => current.UpdateValue(fullMac));
        }

        // For most implementations (i=15, i=55), R-MAC does not update chaining value
        return Result.Success<Security.MacChainingState, SmartCardError>(current);
    }
}
