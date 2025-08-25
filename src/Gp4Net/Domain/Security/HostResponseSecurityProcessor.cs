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
        var lengthValidation = ValidateResponseLength(response, 10, "Response too short to contain R-MAC");
        if (lengthValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(lengthValidation.Error);
            
        var extractionResult = Result.Try(() =>
            {
                // Extract R-MAC (8 bytes before status word)
                var rmacOffset = response.Length - 10;
                var receivedRMac = response.Skip(rmacOffset).Take(8).ToArray();

                // Extract data without R-MAC for verification
                var dataBeforeRMac = response.Take(rmacOffset).ToArray();
                var statusWord = response.TakeLast(2).ToArray();
                var dataForMac = dataBeforeRMac.Concat(statusWord).ToArray();

                return (dataForMac, receivedRMac);
            }, ex => SmartCardError.SecurityError($"R-MAC extraction failed: {ex.Message}"));
            
        if (extractionResult.IsFailure)
            return Result.Failure<byte[], SmartCardError>(extractionResult.Error);
            
        if (extractionResult.IsSuccess)
        {
            var extractedValue = extractionResult.Value;
            var (dataForMac, receivedRMac) = extractedValue;
            
            // Calculate expected R-MAC
            return CalculateRMac(dataForMac, sessionKeys, macChainingValue, protocolVersion)
                .Bind(expectedRMac =>
                {
                    // Verify R-MAC (compare first 8 bytes)
                    if (!receivedRMac.SequenceEqual(expectedRMac.Take(8).ToArray()))
                    {
                        return SmartCardError.SecurityError("R-MAC verification failed");
                    }

                    // Return response without R-MAC
                    return Result.Success<byte[], SmartCardError>(dataForMac);
                });
        }
        
        return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidData("Extraction failed"));
    }

    private static Result<byte[], SmartCardError> DecryptResponseData(
        byte[] response,
        SessionKeys sessionKeys,
        uint encryptionCounter,
        byte protocolVersion)
    {
        return protocolVersion switch
        {
            ProtocolIdentifiers.Scp03 => DecryptScp03ResponseData(response, sessionKeys, encryptionCounter),
            ProtocolIdentifiers.Scp02 => DecryptScp02ResponseData(response, sessionKeys),
            _ => SmartCardError.InvalidArgument($"Unsupported protocol version: 0x{protocolVersion:X2}")
        };
    }

    private static Result<byte[], SmartCardError> DecryptScp03ResponseData(
        byte[] response,
        SessionKeys sessionKeys,
        uint encryptionCounter)
    {
        return Result.Try(() =>
        {
            // Extract encrypted response data (without status word)
            var statusOffset = response.Length - 2;
            var encryptedData = response.Take(statusOffset).ToArray();
            var statusWord = response.TakeLast(2).ToArray();
            
            return (encryptedData, statusWord);
        }, ex => SmartCardError.CryptographicError($"Data extraction failed: {ex.Message}"))
        .Bind(extractedData =>
        {
            var (encryptedData, statusWord) = extractedData;
            
            var alignmentValidation = ValidateAesBlockAlignment(encryptedData);
            if (alignmentValidation.IsFailure)
                return Result.Failure<byte[], SmartCardError>(alignmentValidation.Error);
                
            var icvResult = BuildScp03ResponseIcv(encryptionCounter);
            if (icvResult.IsFailure)
                return Result.Failure<byte[], SmartCardError>(icvResult.Error);
                
            if (icvResult.IsSuccess)
            {
                var icvValue = icvResult.Value;
                var decryptResult = DecryptWithAesCbc(encryptedData, sessionKeys.SEnc, icvValue);
                if (decryptResult.IsFailure)
                    return Result.Failure<byte[], SmartCardError>(decryptResult.Error);
                    
                if (decryptResult.IsSuccess)
                {
                    var decryptedValue = decryptResult.Value;
                    var unpaddingResult = Protocol.CryptographicOperations.RemovePkcs7Padding(decryptedValue);
                    if (unpaddingResult.IsFailure)
                        return Result.Failure<byte[], SmartCardError>(unpaddingResult.Error);
                        
                    if (unpaddingResult.IsSuccess)
                    {
                        var unpaddedValue = unpaddingResult.Value;
                        return Result.Success<byte[], SmartCardError>(unpaddedValue.Concat(statusWord).ToArray());
                    }
                    
                    return Result.Failure<byte[], SmartCardError>(SmartCardError.CryptographicError("Padding removal failed"));
                }
                
                return Result.Failure<byte[], SmartCardError>(SmartCardError.CryptographicError("Decryption failed"));
            }
            
            return Result.Failure<byte[], SmartCardError>(SmartCardError.CryptographicError("ICV generation failed"));
        });
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
        return protocolVersion switch
        {
            ProtocolIdentifiers.Scp03 => CalculateScp03RMac(response, sessionKeys, macChainingValue),
            ProtocolIdentifiers.Scp02 => CalculateScp02RMac(response, sessionKeys, macChainingValue),
            _ => SmartCardError.InvalidArgument($"Unsupported protocol version: 0x{protocolVersion:X2}")
        };
    }

    private static Result<byte[], SmartCardError> CalculateScp03RMac(
        byte[] response,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue)
    {
        // Build MAC input: MAC chaining value || response data (including status word)
        var macInput = macChainingValue.ToArray().Concat(response).ToArray();

        var macService = new MacService();
        return macService.CalculateAesCmac(sessionKeys.SrMac, macInput, macLength: 8);
    }

    private static Result<byte[], SmartCardError> CalculateScp02RMac(
        byte[] response,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue)
    {
        var lengthValidation = ValidateResponseLength(response, 2, "Response too short for R-MAC calculation");
        if (lengthValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(lengthValidation.Error);
            
        var componentsResult = ExtractScp02ResponseComponents(response);
        if (componentsResult.IsFailure)
            return Result.Failure<byte[], SmartCardError>(componentsResult.Error);
            
        if (componentsResult.IsSuccess)
        {
            var componentsValue = componentsResult.Value;
            var macInputResult = BuildScp02MacInput(componentsValue.responseData, componentsValue.statusBytes);
            if (macInputResult.IsFailure)
                return Result.Failure<byte[], SmartCardError>(macInputResult.Error);
                
            if (macInputResult.IsSuccess)
            {
                var macInputValue = macInputResult.Value;
                return CalculateScp02DesRetailMac(macInputValue, sessionKeys.SrMac, macChainingValue);
            }
            
            return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidData("MAC input build failed"));
        }
        
        return Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidData("Component extraction failed"));
    }

    private static UnitResult<SmartCardError> ValidateResponseLength(byte[] response, int minimumLength, string errorMessage)
    {
        return (response.Length < minimumLength)
            ? SmartCardError.InvalidData(errorMessage)
            : UnitResult.Success<SmartCardError>();
    }

    private static UnitResult<SmartCardError> ValidateAesBlockAlignment(byte[] data)
    {
        return (data.Length % 16 != 0)
            ? SmartCardError.InvalidData("Encrypted response data not aligned to AES block size")
            : UnitResult.Success<SmartCardError>();
    }

    private static Result<byte[], SmartCardError> BuildScp03ResponseIcv(uint encryptionCounter)
    {
        return Result.Try(() =>
        {
            // Build ICV for SCP03 R-ENC: counter with MSB set to 0x80
            var icv = new byte[16];
            icv[12] = (byte)(encryptionCounter >> 24);
            icv[13] = (byte)(encryptionCounter >> 16);
            icv[14] = (byte)(encryptionCounter >> 8);
            icv[15] = (byte)encryptionCounter;
            icv[12] |= 0x80; // Set MSB for response decryption
            
            return icv;
        }, ex => SmartCardError.CryptographicError($"ICV generation failed: {ex.Message}"));
    }

    private static Result<byte[], SmartCardError> DecryptWithAesCbc(byte[] encryptedData, byte[] key, byte[] icv)
    {
        return Result.Try(() =>
        {
            // Encrypt using AES-CBC with the counter-based ICV
            var cipher = new CbcBlockCipher(new AesEngine());
            cipher.Init(false, new ParametersWithIV(new KeyParameter(key), icv)); // false for decryption

            var decrypted = new byte[encryptedData.Length];

            for (int i = 0; i < encryptedData.Length; i += 16)
            {
                _ = cipher.ProcessBlock(encryptedData, i, decrypted, i);
            }

            return decrypted;
        }, ex => SmartCardError.CryptographicError($"AES-CBC decryption failed: {ex.Message}"));
    }

    private static Result<(byte[] responseData, byte[] statusBytes), SmartCardError> ExtractScp02ResponseComponents(byte[] response)
    {
        return Result.Try(() =>
        {
            var statusOffset = response.Length - 2;
            var responseData = new byte[statusOffset];
            Array.Copy(response, 0, responseData, 0, statusOffset);
            var statusBytes = new byte[2];
            Array.Copy(response, statusOffset, statusBytes, 0, 2);
            
            return (responseData, statusBytes);
        }, ex => SmartCardError.InvalidData($"Failed to extract response components: {ex.Message}"));
    }

    private static Result<byte[], SmartCardError> BuildScp02MacInput(byte[] responseData, byte[] statusBytes)
    {
        return Result.Try(() =>
        {
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
            
            return macInput;
        }, ex => SmartCardError.InvalidData($"Failed to build MAC input: {ex.Message}"));
    }

    private static Result<byte[], SmartCardError> CalculateScp02DesRetailMac(byte[] macInput, byte[] key, ImmutableArray<byte> macChainingValue)
    {
        return Result.Try(() =>
        {
            // Calculate R-MAC using 3DES with ISO 9797-1 Algorithm 3 (Retail MAC)
            // Use R-MAC session key (SrMac) with MAC chaining value as ICV
            var engine = new DesEngine();
            var desMac = new ISO9797Alg3Mac(engine);
            desMac.Init(new KeyParameter(key));
            
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
            
            return rmac;
        }, ex => SmartCardError.CryptographicError($"SCP02 R-MAC calculation failed: {ex.Message}"));
    }

}