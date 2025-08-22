using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using JetBrains.Annotations;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Functional processor for applying security to APDU responses.
/// All methods are pure functions with no side effects.
/// </summary>
[PublicAPI]
public static class ResponseSecurityProcessor
{
    /// <summary>
    /// Applies response security processing (R-MAC verification and/or R-DECRYPTION) to a response.
    /// Returns the processed response and updated secure channel state.
    /// This is the main entry point for response security processing.
    /// </summary>
    public static Result<(byte[] processedResponse, SecureChannelState newState), SmartCardError> ApplyResponseSecurity(
        byte[] response,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter,
        byte protocolVersion)
    {
        return SecurityValidation.ValidateResponseInputs(response, sessionKeys, macChainingValue)
            .Bind(_ => ProcessResponse(
                response,
                securityLevel,
                sessionKeys,
                macChainingValue,
                encryptionCounter,
                protocolVersion));
    }

    private static Result<(byte[] processedResponse, SecureChannelState newState), SmartCardError> ProcessResponse(
        byte[] response,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter,
        byte protocolVersion)
    {
        // Extract status word
        if (response.Length < 2)
        {
            return SmartCardError.InvalidData("Response too short");
        }

        var statusWord = (ushort)((response[^2] << 8) | response[^1]);
        var newCounter = encryptionCounter;
        var newMacChainingValue = macChainingValue;

        // Check if response security should be applied based on status word
        if (!ShouldApplyResponseSecurity(statusWord))
        {
            // No security processing needed
            return CreateNewState(response, sessionKeys, securityLevel, protocolVersion, macChainingValue, encryptionCounter);
        }

        // Process R-MAC if present
        var macProcessedResult = securityLevel.HasRMac()
            ? ProcessRMac(response, sessionKeys, macChainingValue, protocolVersion)
            : Result.Success<(byte[] response, ImmutableArray<byte> newChaining), SmartCardError>((response, macChainingValue));

        return macProcessedResult.Bind(macResult =>
        {
            var (macProcessedResponse, updatedMacChaining) = macResult;
            newMacChainingValue = updatedMacChaining;

            // Process R-DECRYPTION if present
            var decryptionResult = securityLevel.HasREncryption() && HasResponseData(macProcessedResponse)
                ? ProcessRDecryption(macProcessedResponse, sessionKeys, encryptionCounter, protocolVersion)
                    .Map(decrypted =>
                    {
                        newCounter = protocolVersion == ProtocolIdentifiers.Scp03 ? encryptionCounter + 1 : encryptionCounter;
                        return decrypted;
                    })
                : Result.Success<byte[], SmartCardError>(macProcessedResponse);

            return decryptionResult.Bind(finalResponse =>
                CreateNewState(finalResponse, sessionKeys, securityLevel, protocolVersion, newMacChainingValue, newCounter));
        });
    }

    private static Result<(byte[] response, ImmutableArray<byte> newChaining), SmartCardError> ProcessRMac(
        byte[] response,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        byte protocolVersion)
    {
        var macSize = protocolVersion == ProtocolIdentifiers.Scp03 ? 8 : 8; // Both use 8-byte MACs

        // Check if response has enough bytes for MAC
        if (response.Length < 2 + macSize)
        {
            return SmartCardError.SecurityError("Response too short for R-MAC");
        }

        // Extract MAC from response (before status word)
        var macOffset = response.Length - 2 - macSize;
        var receivedMac = new byte[macSize];
        Array.Copy(response, macOffset, receivedMac, 0, macSize);

        // Build response without MAC for verification
        var responseWithoutMac = new byte[macOffset + 2];
        Array.Copy(response, 0, responseWithoutMac, 0, macOffset); // Data
        Array.Copy(response, response.Length - 2, responseWithoutMac, macOffset, 2); // Status word

        // Calculate expected MAC
        return CalculateRMac(responseWithoutMac, sessionKeys, macChainingValue, protocolVersion)
            .Bind(calculatedMacResult =>
            {
                var (calculatedMac, newChainingValue) = calculatedMacResult;

                // Verify MAC
                if (!receivedMac.SequenceEqual(calculatedMac.Take(macSize).ToArray()))
                {
                    return Result.Failure<(byte[], ImmutableArray<byte>), SmartCardError>(
                        SmartCardError.SecurityError("R-MAC verification failed"));
                }

                // Return response without MAC
                return Result.Success<(byte[], ImmutableArray<byte>), SmartCardError>(
                    (responseWithoutMac, newChainingValue));
            });
    }

    private static Result<byte[], SmartCardError> ProcessRDecryption(
        byte[] response,
        SessionKeys sessionKeys,
        uint encryptionCounter,
        byte protocolVersion)
    {
        var statusOffset = response.Length - 2;
        if (statusOffset <= 0) // No data to decrypt
        {
            return Result.Success<byte[], SmartCardError>(response);
        }

        var encryptedData = new byte[statusOffset];
        Array.Copy(response, 0, encryptedData, 0, statusOffset);

        // Generate decryption IV
        // For SCP03, use encryption counter for ICV generation
        // For SCP02, use zero IV
        var icv = protocolVersion == ProtocolIdentifiers.Scp03
            ? GenerateScp03EncryptionIcv(sessionKeys.SEnc, encryptionCounter)
            : new byte[8];
        
        return Result.Success<byte[], SmartCardError>(icv)
            .Bind(icv => protocolVersion == ProtocolIdentifiers.Scp03
                ? CryptographicOperations.DecryptAesCbc(sessionKeys.SEnc, icv, encryptedData)
                : CryptographicOperations.Decrypt3DesCbc(sessionKeys.SEnc, new byte[8], encryptedData))
            .Bind(decryptedData => CryptographicOperations.RemoveIso7816Padding(decryptedData))
            .Map(plainData =>
            {
                // Combine decrypted data with status word
                var result = new byte[plainData.Length + 2];
                Array.Copy(plainData, 0, result, 0, plainData.Length);
                Array.Copy(response, statusOffset, result, plainData.Length, 2);
                return result;
            });
    }
    
    /// <summary>
    /// Generates the encryption ICV for SCP03.
    /// </summary>
    private static byte[] GenerateScp03EncryptionIcv(byte[] encKey, uint counter)
    {
        // For SCP03, the ICV is encrypted counter value
        var counterBytes = new byte[16];
        counterBytes[15] = (byte)(counter & 0xFF);
        counterBytes[14] = (byte)((counter >> 8) & 0xFF);
        counterBytes[13] = (byte)((counter >> 16) & 0xFF);
        counterBytes[12] = (byte)((counter >> 24) & 0xFF);
        
        // Encrypt the counter with the S-ENC key in ECB mode
        var cipher = new AesEngine();
        cipher.Init(true, new KeyParameter(encKey));
        var result = new byte[16];
        _ = cipher.ProcessBlock(counterBytes, 0, result, 0);
        return result;
    }

    private static Result<(byte[] mac, ImmutableArray<byte> newChainingValue), SmartCardError> CalculateRMac(
        byte[] response,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        byte protocolVersion)
    {
        // Build MAC input: chaining value || response
        var macInput = new byte[macChainingValue.Length + response.Length];
        macChainingValue.CopyTo(macInput, 0);
        Array.Copy(response, 0, macInput, macChainingValue.Length, response.Length);

        if (protocolVersion == ProtocolIdentifiers.Scp03)
        {
            // Calculate full 128-bit AES-CMAC
            var cmac = new CMac(new AesEngine(), 128);
            cmac.Init(new KeyParameter(sessionKeys.SrMac));
            cmac.BlockUpdate(macInput, 0, macInput.Length);
            
            var fullMac = new byte[16];
            _ = cmac.DoFinal(fullMac, 0);

            // Return truncated 8-byte MAC and full 16-byte chaining value
            var mac = new byte[8];
            Array.Copy(fullMac, 0, mac, 0, 8);
            
            // For SCP03, R-MAC does not update chaining value
            return Result.Success<(byte[], ImmutableArray<byte>), SmartCardError>(
                (mac, macChainingValue)
            );
        }
        else
        {
            // SCP02 uses 3DES MAC
            var engine = new DesEngine();
            var desMac = new ISO9797Alg3Mac(engine);
            desMac.Init(new KeyParameter(sessionKeys.SrMac));
            desMac.BlockUpdate(macInput, 0, macInput.Length);
            var mac = new byte[8];
            _ = desMac.DoFinal(mac, 0);
            
            // For SCP02, check implementation parameter to determine if R-MAC updates chaining
            // Most implementations (i=15, i=55) do not update chaining value for R-MAC
            // Only i=05 updates chaining value
            var newChainingValue = ShouldUpdateChainingAfterRMac(protocolVersion)
                ? [..mac]
                : macChainingValue;
            
            return Result.Success<(byte[], ImmutableArray<byte>), SmartCardError>(
                (mac, newChainingValue)
            );
        }
    }

    private static Result<(byte[] processedResponse, SecureChannelState newState), SmartCardError> CreateNewState(
        byte[] processedResponse,
        SessionKeys sessionKeys,
        SecurityLevel securityLevel,
        byte protocolVersion,
        ImmutableArray<byte> newMacChainingValue,
        uint newEncryptionCounter)
    {
        // Create MAC chaining state
        return MacChainingState.Create(newMacChainingValue.ToArray(), protocolVersion, 0x00)
            .Bind(macState => SecureChannelState.Create(
                sessionKeys,
                securityLevel,
                protocolVersion,
                newMacChainingValue.ToArray(),
                0x00)
                .Bind(state => state.UpdateCounterAndMac(newEncryptionCounter, macState))
                .Map(updatedState => (processedResponse, updatedState)));
    }

    private static bool ShouldApplyResponseSecurity(ushort statusWord)
    {
        // Only apply response security for success and warning status words per GP spec
        return statusWord == 0x9000 ||
               (statusWord & 0xFF00) == 0x6200 ||
               (statusWord & 0xFF00) == 0x6300;
    }

    private static bool HasResponseData(byte[] response)
    {
        return response.Length > 2;
    }

    private static bool ShouldUpdateChainingAfterRMac(byte protocolVersion)
    {
        // For most SCP02 implementations, R-MAC does not update chaining value
        // This would need to check the implementation parameter properly
        // For now, assume no update (most common case)
        return false;
    }
}