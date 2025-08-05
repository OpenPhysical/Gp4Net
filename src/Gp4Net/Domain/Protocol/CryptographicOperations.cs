// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Security;
using JetBrains.Annotations;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Pure static cryptographic operations shared across SCP protocols.
/// All functions are stateless and side-effect free.
/// Uses BouncyCastle's high-level APIs to minimize custom code.
/// </summary>
[PublicAPI]
public static class CryptographicOperations
{
    private static readonly MacService _macService = new MacService();
    
    /// <summary>
    /// Calculates AES-CMAC over the provided data.
    /// Used by SCP03 for MAC calculations.
    /// Delegates to MacService to eliminate DRY violations.
    /// </summary>
    /// <param name="key">The AES key (16, 24, or 32 bytes).</param>
    /// <param name="data">The data to calculate MAC over.</param>
    /// <returns>The full 16-byte AES-CMAC.</returns>
    public static Result<byte[], SmartCardError> CalculateAesCmac(byte[] key, byte[] data)
    {
        // Delegate to centralized MacService, requesting full 16-byte MAC
        return _macService.CalculateAesCmac(key, data, 16);
    }

    /// <summary>
    /// Expands a 16-byte (2-key) 3DES key to 24 bytes (3-key) by setting K3 = K1.
    /// </summary>
    /// <param name="key">The key to expand (16 or 24 bytes).</param>
    /// <returns>The expanded 24-byte key.</returns>
    public static byte[] ExpandTripleDesKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        
        return key.Length switch
        {
            16 => ConcatenateArrays(key, key[..8]), // K3 = K1
            24 => key,
            _ => throw new ArgumentException($"3DES key must be 16 or 24 bytes, got {key.Length}")
        };
    }

    /// <summary>
    /// Calculates Full Triple DES MAC over the provided data.
    /// Used by SCP02 for authentication cryptogram calculations.
    /// Per GP Card Specification v2.3.1 Section B.1.2.1 "Full Triple DES":
    /// "The result of the last encryption with the Triple DES key is the MAC"
    /// Used specifically for SCP02 cryptograms as specified in Section E.4.2.
    /// </summary>
    /// <param name="key">The 3DES key (16 or 24 bytes).</param>
    /// <param name="data">The data to calculate MAC over (must be already padded).</param>
    /// <returns>The 8-byte MAC.</returns>
    public static Result<byte[], SmartCardError> CalculateFull3DesMac(byte[] key, byte[] data)
    {
        try
        {
            if (key == null || data == null)
            {
                return SmartCardError.InvalidArgument("Key and data cannot be null");
            }

            if (key.Length != 16 && key.Length != 24)
            {
                return SmartCardError.InvalidArgument($"3DES key must be 16 or 24 bytes, got {key.Length}");
            }

            if (data.Length % 8 != 0)
            {
                return SmartCardError.InvalidArgument("Data must be padded to 8-byte blocks");
            }

            var expandedKey = ExpandTripleDesKey(key);
            
            // Full CBC-MAC with Triple DES
            var cipher = new CbcBlockCipher(new DesEdeEngine());
            cipher.Init(true, new ParametersWithIV(new KeyParameter(expandedKey), new byte[8]));
            
            // Process all blocks
            var currentBlock = new byte[8];
            for (int i = 0; i < data.Length; i += 8)
            {
                cipher.ProcessBlock(data, i, currentBlock, 0);
            }
            
            return Result.Success<byte[], SmartCardError>(currentBlock);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"Full 3DES-MAC calculation failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Calculates Retail MAC (ISO 9797-1 Algorithm 3) over the provided data.
    /// Used by SCP02 for C-MAC and R-MAC calculations.
    /// Per GP Card Specification B.1.2.2.
    /// Delegates to MacService to eliminate DRY violations.
    /// </summary>
    /// <param name="key">The 3DES key (16 or 24 bytes).</param>
    /// <param name="data">The data to calculate MAC over.</param>
    /// <returns>The 8-byte MAC.</returns>
    public static Result<byte[], SmartCardError> CalculateRetailMac(byte[] key, byte[] data)
    {
        // Delegate to centralized MacService for 3DES MAC
        return _macService.Calculate3DesMac(key, data, 8);
    }

    /// <summary>
    /// Calculates 3DES-MAC (ISO 9797-1 Algorithm 3) over the provided data.
    /// DEPRECATED: Use CalculateFull3DesMac or CalculateRetailMac instead.
    /// </summary>
    /// <param name="key">The 3DES key (16 or 24 bytes).</param>
    /// <param name="data">The data to calculate MAC over.</param>
    /// <returns>The 8-byte 3DES-MAC.</returns>
    [Obsolete("Use CalculateFull3DesMac for cryptograms or CalculateRetailMac for C-MAC/R-MAC")]
    public static Result<byte[], SmartCardError> Calculate3DesMac(byte[] key, byte[] data)
    {
        // For backwards compatibility, delegate to centralized MacService
        return _macService.Calculate3DesMac(key, data, 8);
    }

    /// <summary>
    /// Encrypts data using AES-CBC with ISO7816-4 padding.
    /// Uses BouncyCastle's PaddedBufferedBlockCipher for integrated padding and encryption.
    /// </summary>
    /// <param name="key">The AES key.</param>
    /// <param name="iv">The initialization vector (16 bytes).</param>
    /// <param name="data">The data to encrypt.</param>
    /// <returns>The encrypted and padded data.</returns>
    public static Result<byte[], SmartCardError> EncryptAesCbcWithPadding(byte[] key, byte[] iv, byte[] data)
    {
        try
        {
            if (key == null || iv == null || data == null)
            {
                return SmartCardError.InvalidArgument("Key, IV, and data cannot be null");
            }

            if (iv.Length != 16)
            {
                return SmartCardError.InvalidArgument("IV must be 16 bytes for AES");
            }

            // Use BouncyCastle's high-level API with integrated padding
            var cipher = new PaddedBufferedBlockCipher(
                new CbcBlockCipher(new AesEngine()), 
                new ISO7816d4Padding()
            );
            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

            var output = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
            len += cipher.DoFinal(output, len);

            // Return only the actual encrypted bytes
            if (len < output.Length)
            {
                var result = new byte[len];
                Array.Copy(output, 0, result, 0, len);
                return Result.Success<byte[], SmartCardError>(result);
            }

            return Result.Success<byte[], SmartCardError>(output);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"AES-CBC encryption failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Decrypts data using AES-CBC with ISO7816-4 padding removal.
    /// Uses BouncyCastle's PaddedBufferedBlockCipher for integrated decryption and unpadding.
    /// </summary>
    /// <param name="key">The AES key.</param>
    /// <param name="iv">The initialization vector (16 bytes).</param>
    /// <param name="encryptedData">The encrypted data.</param>
    /// <returns>The decrypted and unpadded data.</returns>
    public static Result<byte[], SmartCardError> DecryptAesCbcWithPadding(byte[] key, byte[] iv, byte[] encryptedData)
    {
        try
        {
            if (key == null || iv == null || encryptedData == null)
            {
                return SmartCardError.InvalidArgument("Key, IV, and encrypted data cannot be null");
            }

            if (iv.Length != 16)
            {
                return SmartCardError.InvalidArgument("IV must be 16 bytes for AES");
            }

            // Use BouncyCastle's high-level API with integrated padding
            var cipher = new PaddedBufferedBlockCipher(
                new CbcBlockCipher(new AesEngine()), 
                new ISO7816d4Padding()
            );
            cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

            var output = new byte[cipher.GetOutputSize(encryptedData.Length)];
            var len = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, output, 0);
            len += cipher.DoFinal(output, len);

            // Return only the actual decrypted bytes
            var result = new byte[len];
            Array.Copy(output, 0, result, 0, len);
            return Result.Success<byte[], SmartCardError>(result);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"AES-CBC decryption failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Encrypts data using 3DES-CBC with ISO7816-4 padding.
    /// Uses BouncyCastle's PaddedBufferedBlockCipher for integrated padding and encryption.
    /// </summary>
    /// <param name="key">The 3DES key (16 or 24 bytes).</param>
    /// <param name="iv">The initialization vector (8 bytes).</param>
    /// <param name="data">The data to encrypt.</param>
    /// <returns>The encrypted and padded data.</returns>
    public static Result<byte[], SmartCardError> Encrypt3DesCbcWithPadding(byte[] key, byte[] iv, byte[] data)
    {
        try
        {
            if (key == null || iv == null || data == null)
            {
                return SmartCardError.InvalidArgument("Key, IV, and data cannot be null");
            }

            if (iv.Length != 8)
            {
                return SmartCardError.InvalidArgument("IV must be 8 bytes for 3DES");
            }

            var expandedKey = ExpandTripleDesKey(key);

            // Use BouncyCastle's high-level API with integrated padding
            var cipher = new PaddedBufferedBlockCipher(
                new CbcBlockCipher(new DesEdeEngine()), 
                new ISO7816d4Padding()
            );
            cipher.Init(true, new ParametersWithIV(new KeyParameter(expandedKey), iv));

            var output = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
            len += cipher.DoFinal(output, len);

            // Return only the actual encrypted bytes
            if (len < output.Length)
            {
                var result = new byte[len];
                Array.Copy(output, 0, result, 0, len);
                return Result.Success<byte[], SmartCardError>(result);
            }

            return Result.Success<byte[], SmartCardError>(output);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"3DES-CBC encryption failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Decrypts data using 3DES-CBC with ISO7816-4 padding removal.
    /// Uses BouncyCastle's PaddedBufferedBlockCipher for integrated decryption and unpadding.
    /// </summary>
    /// <param name="key">The 3DES key (16 or 24 bytes).</param>
    /// <param name="iv">The initialization vector (8 bytes).</param>
    /// <param name="encryptedData">The encrypted data.</param>
    /// <returns>The decrypted and unpadded data.</returns>
    public static Result<byte[], SmartCardError> Decrypt3DesCbcWithPadding(byte[] key, byte[] iv, byte[] encryptedData)
    {
        try
        {
            if (key == null || iv == null || encryptedData == null)
            {
                return SmartCardError.InvalidArgument("Key, IV, and encrypted data cannot be null");
            }

            if (iv.Length != 8)
            {
                return SmartCardError.InvalidArgument("IV must be 8 bytes for 3DES");
            }

            var expandedKey = ExpandTripleDesKey(key);

            // Use BouncyCastle's high-level API with integrated padding
            var cipher = new PaddedBufferedBlockCipher(
                new CbcBlockCipher(new DesEdeEngine()), 
                new ISO7816d4Padding()
            );
            cipher.Init(false, new ParametersWithIV(new KeyParameter(expandedKey), iv));

            var output = new byte[cipher.GetOutputSize(encryptedData.Length)];
            var len = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, output, 0);
            len += cipher.DoFinal(output, len);

            // Return only the actual decrypted bytes
            var result = new byte[len];
            Array.Copy(output, 0, result, 0, len);
            return Result.Success<byte[], SmartCardError>(result);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"3DES-CBC decryption failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Encrypts data using AES-CBC without padding.
    /// Used when data is already padded.
    /// Per GP SCP03 v1.1.1 Section 4.1.2 "Encryption/Decryption".
    /// </summary>
    /// <param name="key">The AES key.</param>
    /// <param name="iv">The initialization vector (16 bytes).</param>
    /// <param name="data">The data to encrypt (must be padded to block size).</param>
    /// <returns>The encrypted data.</returns>
    public static Result<byte[], SmartCardError> EncryptAesCbc(byte[] key, byte[] iv, byte[] data)
    {
        try
        {
            if (key == null || iv == null || data == null)
            {
                return SmartCardError.InvalidArgument("Key, IV, and data cannot be null");
            }

            if (iv.Length != 16)
            {
                return SmartCardError.InvalidArgument("IV must be 16 bytes for AES");
            }

            if (data.Length % 16 != 0)
            {
                return SmartCardError.InvalidArgument("Data must be padded to 16-byte blocks");
            }

            var cipher = new BufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

            var encrypted = new byte[data.Length];
            var len = cipher.ProcessBytes(data, 0, data.Length, encrypted, 0);
            cipher.DoFinal(encrypted, len);

            return Result.Success<byte[], SmartCardError>(encrypted);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"AES-CBC encryption failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Decrypts data using AES-CBC without padding.
    /// Used when padding will be removed separately.
    /// Per GP SCP03 v1.1.1 Section 4.1.2 "Encryption/Decryption".
    /// </summary>
    /// <param name="key">The AES key.</param>
    /// <param name="iv">The initialization vector (16 bytes).</param>
    /// <param name="encryptedData">The encrypted data.</param>
    /// <returns>The decrypted data.</returns>
    public static Result<byte[], SmartCardError> DecryptAesCbc(byte[] key, byte[] iv, byte[] encryptedData)
    {
        try
        {
            if (key == null || iv == null || encryptedData == null)
            {
                return SmartCardError.InvalidArgument("Key, IV, and encrypted data cannot be null");
            }

            if (iv.Length != 16)
            {
                return SmartCardError.InvalidArgument("IV must be 16 bytes for AES");
            }

            if (encryptedData.Length % 16 != 0)
            {
                return SmartCardError.InvalidArgument("Encrypted data must be in 16-byte blocks");
            }

            var cipher = new BufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
            cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

            var decrypted = new byte[encryptedData.Length];
            var len = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, decrypted, 0);
            cipher.DoFinal(decrypted, len);

            return Result.Success<byte[], SmartCardError>(decrypted);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"AES-CBC decryption failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Encrypts data using 3DES-CBC without padding.
    /// Used when data is already padded.
    /// Per GP Card Specification v2.3.1 Section E.4.4 "SCP02 - Encryption/Decryption".
    /// </summary>
    /// <param name="key">The 3DES key (16 or 24 bytes).</param>
    /// <param name="iv">The initialization vector (8 bytes).</param>
    /// <param name="data">The data to encrypt (must be padded to block size).</param>
    /// <returns>The encrypted data.</returns>
    public static Result<byte[], SmartCardError> Encrypt3DesCbc(byte[] key, byte[] iv, byte[] data)
    {
        try
        {
            if (key == null || iv == null || data == null)
            {
                return SmartCardError.InvalidArgument("Key, IV, and data cannot be null");
            }

            if (iv.Length != 8)
            {
                return SmartCardError.InvalidArgument("IV must be 8 bytes for 3DES");
            }

            if (data.Length % 8 != 0)
            {
                return SmartCardError.InvalidArgument("Data must be padded to 8-byte blocks");
            }

            var expandedKey = ExpandTripleDesKey(key);

            var cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
            cipher.Init(true, new ParametersWithIV(new KeyParameter(expandedKey), iv));

            var encrypted = new byte[data.Length];
            var len = cipher.ProcessBytes(data, 0, data.Length, encrypted, 0);
            cipher.DoFinal(encrypted, len);

            return Result.Success<byte[], SmartCardError>(encrypted);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"3DES-CBC encryption failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Decrypts data using 3DES-CBC without padding.
    /// Used when padding will be removed separately.
    /// Per GP Card Specification v2.3.1 Section E.4.4 "SCP02 - Encryption/Decryption".
    /// </summary>
    /// <param name="key">The 3DES key (16 or 24 bytes).</param>
    /// <param name="iv">The initialization vector (8 bytes).</param>
    /// <param name="encryptedData">The encrypted data.</param>
    /// <returns>The decrypted data.</returns>
    public static Result<byte[], SmartCardError> Decrypt3DesCbc(byte[] key, byte[] iv, byte[] encryptedData)
    {
        try
        {
            if (key == null || iv == null || encryptedData == null)
            {
                return SmartCardError.InvalidArgument("Key, IV, and encrypted data cannot be null");
            }

            if (iv.Length != 8)
            {
                return SmartCardError.InvalidArgument("IV must be 8 bytes for 3DES");
            }

            if (encryptedData.Length % 8 != 0)
            {
                return SmartCardError.InvalidArgument("Encrypted data must be in 8-byte blocks");
            }

            var expandedKey = ExpandTripleDesKey(key);

            var cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
            cipher.Init(false, new ParametersWithIV(new KeyParameter(expandedKey), iv));

            var decrypted = new byte[encryptedData.Length];
            var len = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, decrypted, 0);
            cipher.DoFinal(decrypted, len);

            return Result.Success<byte[], SmartCardError>(decrypted);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"3DES-CBC decryption failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Applies ISO 7816-4 padding to data.
    /// Uses BouncyCastle's ISO7816d4Padding class.
    /// </summary>
    /// <param name="data">The data to pad.</param>
    /// <param name="blockSize">The block size (8 for 3DES, 16 for AES).</param>
    /// <returns>The padded data.</returns>
    public static Result<byte[], SmartCardError> ApplyIso7816Padding(byte[] data, int blockSize)
    {
        try
        {
            if (data == null)
            {
                return SmartCardError.InvalidArgument("Data cannot be null");
            }

            if (blockSize <= 0 || blockSize > 255)
            {
                return SmartCardError.InvalidArgument($"Invalid block size: {blockSize}");
            }

            var padding = new ISO7816d4Padding();
            var paddingLength = blockSize - (data.Length % blockSize);
            var paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, paddedData, 0, data.Length);
            
            // Use BouncyCastle's ISO 7816-4 padding
            padding.AddPadding(paddedData, data.Length);

            return Result.Success<byte[], SmartCardError>(paddedData);
        }
        catch (Exception ex)
        {
            return SmartCardError.InvalidArgument($"Padding failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Removes ISO 7816-4 padding from data.
    /// Uses BouncyCastle's ISO7816d4Padding class.
    /// </summary>
    /// <param name="paddedData">The padded data.</param>
    /// <returns>The unpadded data.</returns>
    public static Result<byte[], SmartCardError> RemoveIso7816Padding(byte[] paddedData)
    {
        try
        {
            if (paddedData == null || paddedData.Length == 0)
            {
                return SmartCardError.InvalidArgument("Padded data cannot be null or empty");
            }

            var padding = new ISO7816d4Padding();
            var padCount = padding.PadCount(paddedData);
            
            var unpaddedData = new byte[paddedData.Length - padCount];
            Array.Copy(paddedData, 0, unpaddedData, 0, unpaddedData.Length);

            return Result.Success<byte[], SmartCardError>(unpaddedData);
        }
        catch (Exception ex)
        {
            return SmartCardError.InvalidData($"Unpadding failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Applies PKCS#7 padding to data.
    /// Uses BouncyCastle's Pkcs7Padding class.
    /// </summary>
    /// <param name="data">The data to pad.</param>
    /// <param name="blockSize">The block size (8 for 3DES, 16 for AES).</param>
    /// <returns>The padded data.</returns>
    public static Result<byte[], SmartCardError> ApplyPkcs7Padding(byte[] data, int blockSize)
    {
        try
        {
            if (data == null)
            {
                return SmartCardError.InvalidArgument("Data cannot be null");
            }

            if (blockSize <= 0 || blockSize > 255)
            {
                return SmartCardError.InvalidArgument($"Invalid block size: {blockSize}");
            }

            var padding = new Pkcs7Padding();
            var paddingLength = blockSize - (data.Length % blockSize);
            var paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, paddedData, 0, data.Length);
            
            // Use BouncyCastle's PKCS#7 padding
            padding.AddPadding(paddedData, data.Length);

            return Result.Success<byte[], SmartCardError>(paddedData);
        }
        catch (Exception ex)
        {
            return SmartCardError.InvalidArgument($"Padding failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Removes PKCS#7 padding from data.
    /// Uses BouncyCastle's Pkcs7Padding class.
    /// </summary>
    /// <param name="paddedData">The padded data.</param>
    /// <returns>The unpadded data.</returns>
    public static Result<byte[], SmartCardError> RemovePkcs7Padding(byte[] paddedData)
    {
        try
        {
            if (paddedData == null || paddedData.Length == 0)
            {
                return SmartCardError.InvalidArgument("Padded data cannot be null or empty");
            }

            var padding = new Pkcs7Padding();
            var padCount = padding.PadCount(paddedData);
            
            var unpaddedData = new byte[paddedData.Length - padCount];
            Array.Copy(paddedData, 0, unpaddedData, 0, unpaddedData.Length);

            return Result.Success<byte[], SmartCardError>(unpaddedData);
        }
        catch (Exception ex)
        {
            return SmartCardError.InvalidData($"Unpadding failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Pads data to a specific length using ISO 7816-4 padding.
    /// Per GP Card Specification v2.3.1 Section E.4.2.1: data shall be padded with '80 00 00 00 00 00 00 00'.
    /// Uses BouncyCastle's ISO7816d4Padding for standards-compliant implementation.
    /// </summary>
    /// <param name="data">The data to pad.</param>
    /// <param name="targetLength">The target length.</param>
    /// <returns>The padded data with proper ISO 7816-4 padding.</returns>
    public static Result<byte[], SmartCardError> PadToLength(byte[] data, int targetLength)
    {
        if (data == null)
        {
            return SmartCardError.InvalidArgument("Data cannot be null");
        }

        if (targetLength < 0)
        {
            return SmartCardError.InvalidArgument("Target length cannot be negative");
        }

        if (data.Length >= targetLength)
        {
            return SmartCardError.InvalidArgument($"Data length {data.Length} must be less than target length {targetLength} to allow for padding");
        }

        var paddedData = new byte[targetLength];
        Array.Copy(data, 0, paddedData, 0, data.Length);
        
        // Apply ISO 7816-4 padding using BouncyCastle's implementation
        var padding = new ISO7816d4Padding();
        padding.AddPadding(paddedData, data.Length);

        return Result.Success<byte[], SmartCardError>(paddedData);
    }

    /// <summary>
    /// Compares two byte arrays for equality.
    /// Uses constant-time comparison to prevent timing attacks.
    /// </summary>
    /// <param name="a">First array.</param>
    /// <param name="b">Second array.</param>
    /// <returns>True if arrays are equal, false otherwise.</returns>
    public static bool CompareBytes(byte[] a, byte[] b)
    {
        if (a == null || b == null)
        {
            return false;
        }

        if (a.Length != b.Length)
        {
            return false;
        }

        var result = 0;
        for (var i = 0; i < a.Length; i++)
        {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /// <summary>
    /// Concatenates multiple byte arrays.
    /// </summary>
    /// <param name="arrays">Arrays to concatenate.</param>
    /// <returns>The concatenated array.</returns>
    public static byte[] ConcatenateArrays(params byte[][] arrays)
    {
        ArgumentNullException.ThrowIfNull(arrays);
        
        var totalLength = arrays.Sum(a => a?.Length ?? 0);
        var result = new byte[totalLength];
        var offset = 0;

        foreach (var array in arrays)
        {
            if (array != null)
            {
                Array.Copy(array, 0, result, offset, array.Length);
                offset += array.Length;
            }
        }

        return result;
    }

    /// <summary>
    /// Generates the Initialization Chaining Vector (ICV) for command encryption.
    /// Per GP SCP03 spec section 6.2.6, command ICV uses encryption counter.
    /// For SCP02, returns zero IV.
    /// </summary>
    /// <param name="sEncKey">The session encryption key.</param>
    /// <param name="encryptionCounter">The current encryption counter.</param>
    /// <param name="protocolVersion">The SCP protocol version.</param>
    /// <returns>The 16-byte ICV for SCP03, or 8-byte zero IV for SCP02.</returns>
    public static Result<byte[], SmartCardError> GenerateCommandIcv(
        byte[] sEncKey,
        uint encryptionCounter,
        byte protocolVersion)
    {
        try
        {
            if (protocolVersion != ProtocolIdentifiers.Scp03)
            {
                return Result.Success<byte[], SmartCardError>(new byte[8]); // Zero IV for SCP02
            }

            // Per GP SCP03 spec section 6.2.6:
            // Command ICV uses encryption counter
            var counterBlock = new byte[16];
            counterBlock[12] = (byte)(encryptionCounter >> 24);
            counterBlock[13] = (byte)(encryptionCounter >> 16);
            counterBlock[14] = (byte)(encryptionCounter >> 8);
            counterBlock[15] = (byte)encryptionCounter;

            // Encrypt the counter block with S-ENC to produce the ICV using single-block AES
            var cipher = new AesEngine();
            cipher.Init(true, new KeyParameter(sEncKey));
            
            var icv = new byte[16];
            cipher.ProcessBlock(counterBlock, 0, icv, 0);
            
            return Result.Success<byte[], SmartCardError>(icv);
        }
        catch (Exception ex)
        {
            return SmartCardError.CryptographicError($"ICV generation failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Converts a byte array to a hexadecimal string.
    /// </summary>
    /// <param name="bytes">The bytes to convert.</param>
    /// <returns>The hexadecimal string.</returns>
    public static string ToHexString(this byte[] bytes)
    {
        if (bytes == null)
        {
            return string.Empty;
        }

        return Convert.ToHexString(bytes);
    }
}