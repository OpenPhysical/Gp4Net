using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Functional implementation of response security processing for the host side.
/// Handles verification and removal of R-MAC and decryption of R-ENC.
/// All methods are pure functions with no side effects.
/// </summary>
[PublicAPI]
public class HostResponseSecurityProcessor : IResponseSecurityProcessor
{
    /// <inheritdoc />
    public Result<(byte[] processedResponse, SecureChannelState newState), SmartCardError> ApplyResponseSecurity(
        byte[] response,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter,
        byte protocolVersion)
    {
        // For host-side processing, we need to:
        // 1. Verify and remove R-MAC (if present)
        // 2. Decrypt response data (if R-ENC is enabled)
        return SecurityValidation.ValidateResponseInputs(response, sessionKeys, macChainingValue)
            .Bind(validatedResponse => ProcessHostResponse(
                validatedResponse, 
                securityLevel, 
                sessionKeys, 
                macChainingValue, 
                encryptionCounter,
                protocolVersion));
    }


    private static Result<(byte[] processedResponse, SecureChannelState newState), SmartCardError> ProcessHostResponse(
        byte[] response,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter,
        byte protocolVersion)
    {
        var newEncryptionCounter = encryptionCounter;
        var newMacChainingValue = macChainingValue;

        // Process in reverse order for host-side: first verify/remove MAC, then decrypt
        return VerifyAndRemoveMacIfNeeded(response, securityLevel, sessionKeys, macChainingValue, protocolVersion)
            .Bind(macResult =>
            {
                var (responseAfterMac, updatedMacChaining) = macResult;
                newMacChainingValue = updatedMacChaining;

                return DecryptIfNeeded(responseAfterMac, securityLevel, sessionKeys, encryptionCounter, protocolVersion)
                    .Bind(decryptionResult =>
                    {
                        var (decryptedResponse, updatedCounter) = decryptionResult;
                        newEncryptionCounter = updatedCounter;

                        // Create MAC chaining state
                        var macChainingStateResult = MacChainingState.Create(
                            newMacChainingValue.ToArray(), 
                            protocolVersion,
                            0x00);
                            
                        if (macChainingStateResult.IsFailure)
                        {
                            return Result.Failure<(byte[], SecureChannelState), SmartCardError>(macChainingStateResult.Error);
                        }

                        // Create new state with updated values
                        var newStateResult = SecureChannelState.Create(
                            sessionKeys,
                            securityLevel,
                            protocolVersion,
                            macChainingValue.ToArray(),
                            0x00)
                            .Bind(state => state.UpdateCounterAndMac(newEncryptionCounter, macChainingStateResult.Value));
                            
                        if (newStateResult.IsFailure)
                        {
                            return Result.Failure<(byte[], SecureChannelState), SmartCardError>(newStateResult.Error);
                        }

                        return Result.Success<(byte[], SecureChannelState), SmartCardError>((decryptedResponse, newStateResult.Value));
                    });
            });
    }

    private static Result<(byte[] response, ImmutableArray<byte> newMacChaining), SmartCardError> VerifyAndRemoveMacIfNeeded(
        byte[] response,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        byte protocolVersion)
    {
        if (!securityLevel.HasRMac() || !HasRMac(response))
        {
            return Result.Success<(byte[], ImmutableArray<byte>), SmartCardError>((response, macChainingValue));
        }

        return VerifyAndRemoveRMac(response, sessionKeys, macChainingValue, protocolVersion)
            .Map(responseWithoutMac => (responseWithoutMac, macChainingValue)); // MAC chaining not updated for R-MAC
    }

    private static Result<(byte[] response, uint newCounter), SmartCardError> DecryptIfNeeded(
        byte[] response,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        uint encryptionCounter,
        byte protocolVersion)
    {
        if (!securityLevel.HasREncryption() || !SecurityValidation.HasResponseData(response))
        {
            return Result.Success<(byte[], uint), SmartCardError>((response, encryptionCounter));
        }

        return DecryptResponseData(response, sessionKeys, encryptionCounter, protocolVersion)
            .Map(decryptedData => (decryptedData, encryptionCounter + 1));
    }

    private static bool HasRMac(byte[] response)
    {
        return SecurityValidation.HasRMac(response) && SecurityValidation.ShouldAddRMac(response);
    }

    private static Result<byte[], SmartCardError> VerifyAndRemoveRMac(
        byte[] response,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        byte protocolVersion)
    {
        try
        {
            if (response.Length < 10) // Minimum: 8 bytes R-MAC + 2 bytes SW
            {
                return SmartCardError.InvalidData("Response too short to contain R-MAC");
            }

            // Extract R-MAC (8 bytes before status word)
            var rmacOffset = response.Length - 10;
            var receivedRMac = response.Skip(rmacOffset).Take(8).ToArray();

            // Extract data without R-MAC for verification
            var dataBeforeRMac = response.Take(rmacOffset).ToArray();
            var statusWord = response.TakeLast(2).ToArray();
            var dataForMac = dataBeforeRMac.Concat(statusWord).ToArray();

            // Calculate expected R-MAC
            var expectedRMacResult = CalculateRMac(dataForMac, sessionKeys, macChainingValue, protocolVersion);
            if (expectedRMacResult.IsFailure)
            {
                return expectedRMacResult.Error;
            }

            var expectedRMac = expectedRMacResult.Value;

            // Verify R-MAC (compare first 8 bytes)
            if (!receivedRMac.SequenceEqual(expectedRMac.Take(8).ToArray()))
            {
                return SmartCardError.SecurityError("R-MAC verification failed");
            }

            // Return response without R-MAC
            return Result.Success<byte[], SmartCardError>(dataForMac);
        }
        catch (Exception ex)
        {
            return SmartCardError.SecurityError($"R-MAC verification failed: {ex.Message}");
        }
    }

    private static Result<byte[], SmartCardError> DecryptResponseData(
        byte[] response,
        SessionKeys sessionKeys,
        uint encryptionCounter,
        byte protocolVersion)
    {
        try
        {
            switch (protocolVersion)
            {
                case ProtocolIdentifiers.Scp03:
                    return DecryptScp03ResponseData(response, sessionKeys, encryptionCounter);
                case ProtocolIdentifiers.Scp02:
                    return DecryptScp02ResponseData(response, sessionKeys);
                default:
                    return SmartCardError.InvalidArgument($"Unsupported protocol version: 0x{protocolVersion:X2}");
            }
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"Response decryption failed: {ex.Message}");
        }
    }

    private static Result<byte[], SmartCardError> DecryptScp03ResponseData(
        byte[] response,
        SessionKeys sessionKeys,
        uint encryptionCounter)
    {
        try
        {
            // Extract encrypted response data (without status word)
            var statusOffset = response.Length - 2;
            var encryptedData = response.Take(statusOffset).ToArray();

            // Build ICV for SCP03 R-ENC: counter with MSB set to 0x80
            var icv = new byte[16];
            icv[12] = (byte)(encryptionCounter >> 24);
            icv[13] = (byte)(encryptionCounter >> 16);
            icv[14] = (byte)(encryptionCounter >> 8);
            icv[15] = (byte)encryptionCounter;
            icv[12] |= 0x80; // Set MSB for response decryption

            // Encrypt using AES-CBC with the counter-based ICV
            var cipher = new CbcBlockCipher(new AesEngine());
            cipher.Init(false, new ParametersWithIV(new KeyParameter(sessionKeys.SEnc), icv)); // false for decryption

            // Encrypted data should be padded to block size
            if (encryptedData.Length % 16 != 0)
            {
                return SmartCardError.InvalidData("Encrypted response data not aligned to AES block size");
            }

            var decrypted = new byte[encryptedData.Length];

            for (int i = 0; i < encryptedData.Length; i += 16)
            {
                _ = cipher.ProcessBlock(encryptedData, i, decrypted, i);
            }

            // Remove PKCS#7 padding
            var unpaddedResult = Protocol.CryptographicOperations.RemovePkcs7Padding(decrypted);
            if (unpaddedResult.IsFailure)
            {
                return unpaddedResult.Error;
            }

            // Combine decrypted data with original status word
            var statusWord = response.TakeLast(2).ToArray();
            var result = unpaddedResult.Value.Concat(statusWord).ToArray();

            return Result.Success<byte[], SmartCardError>(result);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"SCP03 response decryption failed: {ex.Message}");
        }
    }

    private static Result<byte[], SmartCardError> DecryptScp02ResponseData(
        byte[] response,
        SessionKeys sessionKeys)
    {
        // SCP02 doesn't typically use R-ENC
        // Return the response unchanged
        return Result.Success<byte[], SmartCardError>(response);
    }

    private static Result<byte[], SmartCardError> CalculateRMac(
        byte[] response,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        byte protocolVersion)
    {
        try
        {
            switch (protocolVersion)
            {
                case ProtocolIdentifiers.Scp03:
                    return CalculateScp03RMac(response, sessionKeys, macChainingValue);
                case ProtocolIdentifiers.Scp02:
                    return CalculateScp02RMac(response, sessionKeys, macChainingValue);
                default:
                    return SmartCardError.InvalidArgument($"Unsupported protocol version: 0x{protocolVersion:X2}");
            }
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"R-MAC calculation failed: {ex.Message}");
        }
    }

    private static Result<byte[], SmartCardError> CalculateScp03RMac(
        byte[] response,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue)
    {
        try
        {
            // Build MAC input: MAC chaining value || response data (including status word)
            var macInput = macChainingValue.ToArray().Concat(response).ToArray();

            // Calculate AES-CMAC
            var cmac = new CMac(new AesEngine(), 128);
            cmac.Init(new KeyParameter(sessionKeys.SrMac));
            cmac.BlockUpdate(macInput, 0, macInput.Length);
            
            var mac = new byte[16];
            _ = cmac.DoFinal(mac, 0);
            
            // Return first 8 bytes as R-MAC
            return Result.Success<byte[], SmartCardError>(mac.Take(8).ToArray());
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"SCP03 R-MAC calculation failed: {ex.Message}");
        }
    }

    private static Result<byte[], SmartCardError> CalculateScp02RMac(
        byte[] response,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue)
    {
        try
        {
            // Per GP Card Spec v2.3.1 Section E.4.5 R-MAC Generation:
            // R-MAC is computed on:
            // 1. The stripped APDU command message (without C-MAC, modified header, logical channel = 0)
            // 2. Response data length (Li)
            // 3. Response data
            // 4. Status bytes
            
            // For trace decryption, we only have the response data + status word
            // We need to reconstruct the full R-MAC input data
            
            if (response.Length < 2)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidData("Response too short for R-MAC calculation"));
            }

            // Extract response data and status word
            var statusOffset = response.Length - 2;
            var responseData = new byte[statusOffset];
            Array.Copy(response, 0, responseData, 0, statusOffset);
            var statusBytes = new byte[2];
            Array.Copy(response, statusOffset, statusBytes, 0, 2);
            
            // Build R-MAC input according to SCP02 spec:
            // For response-only R-MAC (without command context), we calculate over:
            // Response Length (1 byte) + Response Data + Status Word (2 bytes)
            var macInput = new byte[1 + responseData.Length + 2];
            var offset = 0;
            
            // Length of response data
            macInput[offset++] = (byte)responseData.Length;
            
            // Response data
            Array.Copy(responseData, 0, macInput, offset, responseData.Length);
            offset += responseData.Length;
            
            // Status bytes
            Array.Copy(statusBytes, 0, macInput, offset, 2);
            
            // Calculate R-MAC using 3DES with ISO 9797-1 Algorithm 3 (Retail MAC)
            // Use R-MAC session key (SrMac) with MAC chaining value as ICV
            var engine = new DesEngine();
            var desMac = new ISO9797Alg3Mac(engine);
            desMac.Init(new KeyParameter(sessionKeys.SrMac));
            
            // Apply MAC chaining value
            if (macChainingValue.Length >= 8)
            {
                // Set ICV to current MAC chaining value
                var icv = new byte[8];
                Array.Copy(macChainingValue.ToArray(), 0, icv, 0, 8);
                // Note: BouncyCastle ISO9797Alg3Mac doesn't expose ICV setting directly
                // We need to prepend the ICV to achieve chaining
                var chainedInput = new byte[8 + macInput.Length];
                Array.Copy(icv, 0, chainedInput, 0, 8);
                Array.Copy(macInput, 0, chainedInput, 8, macInput.Length);
                desMac.BlockUpdate(chainedInput, 0, chainedInput.Length);
            }
            else
            {
                desMac.BlockUpdate(macInput, 0, macInput.Length);
            }
            
            var rmac = new byte[8];
            _ = desMac.DoFinal(rmac, 0);
            
            return Result.Success<byte[], SmartCardError>(rmac);
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.CryptographicError($"SCP02 R-MAC calculation failed: {ex.Message}"));
        }
    }

}