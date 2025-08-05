using System;
using System.Collections.Immutable;
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
/// Functional processor for applying security to APDU responses on the card side.
/// Adds R-MAC and R-ENC to responses. All methods are pure functions with no side effects.
/// </summary>
[PublicAPI]
public static class CardResponseSecurityProcessor
{
    /// <summary>
    /// Result of applying response security including new state values.
    /// </summary>
    public record ResponseSecurityResult(
        byte[] SecuredData,
        ImmutableArray<byte> NewMacChainingValue,
        uint NewEncryptionCounter
    );

    /// <summary>
    /// Applies response security (R-MAC and/or R-ENCRYPTION) to a response APDU.
    /// Returns the secured data and updated state values.
    /// </summary>
    public static Result<ResponseSecurityResult, SmartCardError> ApplyResponseSecurity(
        byte[] responseData,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter,
        byte protocolVersion)
    {
        var newEncryptionCounter = encryptionCounter;
        var newMacChainingValue = macChainingValue;

        return SecurityValidation.ValidateResponseInputs(responseData, sessionKeys, macChainingValue)
            .Bind(data => 
            {
                if (securityLevel.HasREncryption() && SecurityValidation.HasResponseData(data))
                {
                    // Increment counter for R-ENC
                    newEncryptionCounter = encryptionCounter + 1;
                    return EncryptResponseData(data, sessionKeys, encryptionCounter, protocolVersion);
                }
                return Result.Success<byte[], SmartCardError>(data);
            })
            .Bind(data => 
            {
                if (securityLevel.HasRMac() && SecurityValidation.ShouldAddRMac(data))
                {
                    // Calculate MAC and update chaining value
                    return CalculateRMac(data, sessionKeys, macChainingValue, protocolVersion)
                        .Bind(rmac =>
                        {
                            // For SCP03, the full MAC becomes the new chaining value
                            if (protocolVersion == ProtocolIdentifiers.Scp03)
                            {
                                // We need to recalculate the full MAC (not truncated)
                                var macInput = new byte[macChainingValue.Length + data.Length];
                                macChainingValue.CopyTo(macInput, 0);
                                Array.Copy(data, 0, macInput, macChainingValue.Length, data.Length);

                                var cmac = new CMac(new AesEngine(), 128);
                                cmac.Init(new KeyParameter(sessionKeys.SrMac));
                                cmac.BlockUpdate(macInput, 0, macInput.Length);
                                
                                var fullMac = new byte[16];
                                cmac.DoFinal(fullMac, 0);
                                newMacChainingValue = ImmutableArray.Create(fullMac);
                            }

                            // Insert R-MAC before status word
                            var statusOffset = data.Length - 2;
                            var result = new byte[data.Length + 8];
                            Array.Copy(data, 0, result, 0, statusOffset); // Data
                            Array.Copy(rmac, 0, result, statusOffset, 8); // R-MAC (truncated)
                            Array.Copy(data, statusOffset, result, result.Length - 2, 2); // Status
                            return Result.Success<byte[], SmartCardError>(result);
                        });
                }
                return Result.Success<byte[], SmartCardError>(data);
            })
            .Map(securedData => new ResponseSecurityResult(
                securedData,
                newMacChainingValue,
                newEncryptionCounter
            ));
    }

    /// <summary>
    /// Verifies and removes R-MAC from a response APDU.
    /// </summary>
    public static Result<byte[], SmartCardError> VerifyAndRemoveRMac(
        byte[] response,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        byte protocolVersion)
    {
        if (response == null || response.Length < 10) // Minimum: 2 status bytes + 8 MAC bytes
        {
            return SmartCardError.SecurityError("Response too short for R-MAC");
        }

        // Extract R-MAC (last 8 bytes before status)
        var rmacOffset = response.Length - 10;
        var receivedRMac = new byte[8];
        Array.Copy(response, rmacOffset, receivedRMac, 0, 8);

        // Calculate expected R-MAC
        var dataToMac = new byte[rmacOffset + 2];
        Array.Copy(response, 0, dataToMac, 0, rmacOffset);
        Array.Copy(response, response.Length - 2, dataToMac, rmacOffset, 2); // Status bytes

        return CalculateRMac(dataToMac, sessionKeys, macChainingValue, protocolVersion)
            .Bind(expectedRMac =>
            {
                if (!CryptographicOperations.CompareBytes(receivedRMac, expectedRMac))
                {
                    return SmartCardError.SecurityError("R-MAC verification failed");
                }

                // Remove R-MAC from response
                var result = new byte[response.Length - 8];
                Array.Copy(response, 0, result, 0, rmacOffset);
                Array.Copy(response, response.Length - 2, result, result.Length - 2, 2);

                return Result.Success<byte[], SmartCardError>(result);
            });
    }

    /// <summary>
    /// Decrypts response data using R-ENCRYPTION.
    /// </summary>
    public static Result<byte[], SmartCardError> DecryptResponseData(
        byte[] response,
        SessionKeys sessionKeys,
        uint encryptionCounter,
        byte protocolVersion)
    {
        if (response == null || response.Length <= 2) // Only status word, no data to decrypt
        {
            return Result.Success<byte[], SmartCardError>(response);
        }

        // Extract data (everything except the last 2 bytes which are status word)
        var statusOffset = response.Length - 2;
        var encryptedData = new byte[statusOffset];
        Array.Copy(response, 0, encryptedData, 0, statusOffset);

        return GenerateResponseIcv(sessionKeys.SEnc, encryptionCounter, protocolVersion)
            .Bind(icv => protocolVersion == ProtocolIdentifiers.Scp03
                ? CryptographicOperations.DecryptAesCbc(sessionKeys.SEnc, icv, encryptedData)
                : CryptographicOperations.Decrypt3DesCbc(sessionKeys.SEnc, new byte[8], encryptedData))
            .Bind(decrypted => RemovePadding(decrypted))
            .Map(unpaddedData =>
            {
                // Reconstruct response with decrypted data
                var result = new byte[unpaddedData.Length + 2];
                Array.Copy(unpaddedData, 0, result, 0, unpaddedData.Length);
                Array.Copy(response, statusOffset, result, unpaddedData.Length, 2); // Copy status word
                return result;
            });
    }

    private static Result<byte[], SmartCardError> EncryptResponseData(
        byte[] responseData,
        SessionKeys sessionKeys,
        uint encryptionCounter,
        byte protocolVersion)
    {
        // Extract data to encrypt (everything except status word)
        var statusOffset = responseData.Length - 2;
        var dataToEncrypt = new byte[statusOffset];
        Array.Copy(responseData, 0, dataToEncrypt, 0, statusOffset);

        return AddPadding(dataToEncrypt)
            .Bind(paddedData => GenerateResponseIcv(sessionKeys.SEnc, encryptionCounter, protocolVersion)
                .Bind(icv => protocolVersion == ProtocolIdentifiers.Scp03
                    ? CryptographicOperations.EncryptAesCbc(sessionKeys.SEnc, icv, paddedData)
                    : CryptographicOperations.Encrypt3DesCbc(sessionKeys.SEnc, new byte[8], paddedData)))
            .Map(encryptedData =>
            {
                // Reconstruct response with encrypted data + status word
                var result = new byte[encryptedData.Length + 2];
                Array.Copy(encryptedData, 0, result, 0, encryptedData.Length);
                Array.Copy(responseData, statusOffset, result, encryptedData.Length, 2);
                return result;
            });
    }

    private static Result<byte[], SmartCardError> AppendRMac(
        byte[] responseData,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        byte protocolVersion)
    {
        return CalculateRMac(responseData, sessionKeys, macChainingValue, protocolVersion)
            .Map(rmac =>
            {
                // Insert R-MAC before status word
                var statusOffset = responseData.Length - 2;
                var result = new byte[responseData.Length + 8];
                Array.Copy(responseData, 0, result, 0, statusOffset); // Data
                Array.Copy(rmac, 0, result, statusOffset, 8); // R-MAC
                Array.Copy(responseData, statusOffset, result, result.Length - 2, 2); // Status
                return result;
            });
    }

    private static Result<byte[], SmartCardError> CalculateRMac(
        byte[] data,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        byte protocolVersion)
    {
        var macInput = new byte[macChainingValue.Length + data.Length];
        macChainingValue.CopyTo(macInput, 0);
        Array.Copy(data, 0, macInput, macChainingValue.Length, data.Length);

        if (protocolVersion == ProtocolIdentifiers.Scp03)
        {
            // Calculate full 128-bit AES-CMAC for R-MAC
            var cmac = new CMac(new AesEngine(), 128);
            cmac.Init(new KeyParameter(sessionKeys.SrMac));
            cmac.BlockUpdate(macInput, 0, macInput.Length);
            
            var fullMac = new byte[16];
            cmac.DoFinal(fullMac, 0);
            
            // Return truncated 8-byte MAC
            var mac = new byte[8];
            Array.Copy(fullMac, 0, mac, 0, 8);
            return Result.Success<byte[], SmartCardError>(mac);
        }
        else
        {
            // SCP02 uses 3DES MAC
            var engine = new DesEdeEngine();
            var desMac = new ISO9797Alg3Mac(engine);
            desMac.Init(new KeyParameter(sessionKeys.SrMac));
            desMac.BlockUpdate(macInput, 0, macInput.Length);
            var mac = new byte[8];
            desMac.DoFinal(mac, 0);
            return Result.Success<byte[], SmartCardError>(mac);
        }
    }

    private static Result<byte[], SmartCardError> GenerateResponseIcv(
        byte[] sEncKey,
        uint encryptionCounter,
        byte protocolVersion)
    {
        if (protocolVersion != ProtocolIdentifiers.Scp03)
        {
            return Result.Success<byte[], SmartCardError>(new byte[8]); // Zero IV for SCP02
        }

        // Per GP SCP03 spec section 6.2.7:
        // Response ICV uses same counter as command but with MSB set to 0x80
        var counterBlock = new byte[16];
        counterBlock[0] = 0x80; // Response ICV starts with 0x80
        
        // Counter in last 4 bytes (big-endian)
        counterBlock[12] = (byte)(encryptionCounter >> 24);
        counterBlock[13] = (byte)(encryptionCounter >> 16);
        counterBlock[14] = (byte)(encryptionCounter >> 8);
        counterBlock[15] = (byte)encryptionCounter;

        // Encrypt the counter block with S-ENC to produce the ICV
        var cipher = new AesEngine();
        cipher.Init(true, new KeyParameter(sEncKey));
        
        var icv = new byte[16];
        cipher.ProcessBlock(counterBlock, 0, icv, 0);

        return Result.Success<byte[], SmartCardError>(icv);
    }


    private static Result<byte[], SmartCardError> AddPadding(byte[] data)
    {
        return CryptographicOperations.ApplyIso7816Padding(data, 16);
    }

    private static Result<byte[], SmartCardError> RemovePadding(byte[] data)
    {
        return CryptographicOperations.RemoveIso7816Padding(data);
    }


}