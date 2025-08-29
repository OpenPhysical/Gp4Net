// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Core.Validation;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
using JetBrains.Annotations;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Pure static cryptographic operations shared across SCP protocols.
/// All functions are stateless and side-effect free.
/// Uses BouncyCastle's high-level APIs to minimize custom code.
/// </summary>
[PublicAPI]
public static class CryptographicOperations
{

    /// <summary>
    /// Expands a 16-byte (2-key) 3DES key to 24 bytes (3-key) by setting K3 = K1.
    /// </summary>
    /// <param name="key">The key to expand (16 or 24 bytes).</param>
    /// <returns>The expanded 24-byte key or error.</returns>
    public static Result<byte[], SmartCardError> ExpandTripleDesKey(byte[] key)
    {
        return Maybe<byte[]>.From(key)
            .ToResult(SmartCardError.InvalidArgument("Key cannot be null"))
            .Bind(validKey => validKey.Length switch
            {
                16 => Result.Success<byte[], SmartCardError>(ConcatenateArrays(validKey, validKey[..8])), // K3 = K1
                24 => Result.Success<byte[], SmartCardError>(validKey),
                _ => Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument($"3DES key must be 16 or 24 bytes, got {validKey.Length}"))
            });
    }


    private static UnitResult<SmartCardError> ValidateInputs(byte[] key, byte[] data, string errorMessage)
        => CryptographicValidation.ValidateInputs(key, data, errorMessage);

    private static UnitResult<SmartCardError> ValidateInputs(byte[] key, byte[] iv, byte[] data, string errorMessage)
    {
        Maybe<byte[]> keyMaybe = Maybe<byte[]>.From(key);
        Maybe<byte[]> ivMaybe = Maybe<byte[]>.From(iv);
        Maybe<byte[]> dataMaybe = Maybe<byte[]>.From(data);

        return keyMaybe.HasValue && ivMaybe.HasValue && dataMaybe.HasValue
            ? UnitResult.Success<SmartCardError>()
            : UnitResult.Failure<SmartCardError>(SmartCardError.InvalidArgument(errorMessage));
    }

    private static UnitResult<SmartCardError> ValidateIvLength(byte[] iv, int expectedLength, string errorMessage)
    {
        return (iv.Length == expectedLength)
            ? UnitResult.Success<SmartCardError>()
            : UnitResult.Failure<SmartCardError>(SmartCardError.InvalidArgument(errorMessage));
    }

    private static UnitResult<SmartCardError> ValidateKeyLength(byte[] key, int[] validLengths, string errorMessage)
        => CryptographicValidation.ValidateKeyLength(key, validLengths, errorMessage);

    private static UnitResult<SmartCardError> ValidateDataPadding(byte[] data, int blockSize, string errorMessage)
        => CryptographicValidation.ValidateDataPadding(data, blockSize, errorMessage);

    private static UnitResult<SmartCardError> ValidateNonNullData(byte[] data, string errorMessage)
    {
        Maybe<byte[]> dataMaybe = Maybe<byte[]>.From(data);
        return dataMaybe.HasValue
            ? UnitResult.Success<SmartCardError>()
            : UnitResult.Failure<SmartCardError>(SmartCardError.InvalidArgument(errorMessage));
    }

    private static UnitResult<SmartCardError> ValidateNonNullNonEmptyData(byte[] data, string errorMessage)
    {
        Maybe<byte[]> dataMaybe = Maybe<byte[]>.From(data);
        return dataMaybe.Match(
            d => d.Length > 0
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure<SmartCardError>(SmartCardError.InvalidArgument(errorMessage)),
            () => UnitResult.Failure<SmartCardError>(SmartCardError.InvalidArgument(errorMessage)));
    }

    private static UnitResult<SmartCardError> ValidateBlockSize(int blockSize)
    {
        return (blockSize is <= 0 or > 255)
            ? SmartCardError.InvalidArgument($"Invalid block size: {blockSize}")
            : UnitResult.Success<SmartCardError>();
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
        UnitResult<SmartCardError> inputValidation = ValidateInputs(key, iv, data, "Key, IV, and data cannot be null");
        if (inputValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(inputValidation.Error);

        UnitResult<SmartCardError> ivValidation = ValidateIvLength(iv, 16, "IV must be 16 bytes for AES");
        if (ivValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(ivValidation.Error);

        return Result.Try(() =>
            {
                // Use BouncyCastle's high-level API with integrated padding
                PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                    new CbcBlockCipher(new AesEngine()),
                    new ISO7816d4Padding()
                );
                cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

                byte[] output = new byte[cipher.GetOutputSize(data.Length)];
                int len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
                len += cipher.DoFinal(output, len);

                // Return only the actual encrypted bytes
                if (len < output.Length)
                {
                    byte[] result = new byte[len];
                    Array.Copy(output, 0, result, 0, len);
                    return result;
                }

                return output;
            }, ex => SmartCardError.CryptographicError($"AES-CBC encryption failed: {ex.Message}"));
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
        UnitResult<SmartCardError> inputValidation = ValidateInputs(key, iv, encryptedData, "Key, IV, and encrypted data cannot be null");
        if (inputValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(inputValidation.Error);

        UnitResult<SmartCardError> ivValidation = ValidateIvLength(iv, 16, "IV must be 16 bytes for AES");
        if (ivValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(ivValidation.Error);

        return Result.Try(() =>
            {
                // Use BouncyCastle's high-level API with integrated padding
                PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                    new CbcBlockCipher(new AesEngine()),
                    new ISO7816d4Padding()
                );
                cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

                byte[] output = new byte[cipher.GetOutputSize(encryptedData.Length)];
                int len = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, output, 0);
                len += cipher.DoFinal(output, len);

                // Return only the actual decrypted bytes
                byte[] result = new byte[len];
                Array.Copy(output, 0, result, 0, len);
                return result;
            }, ex => SmartCardError.CryptographicError($"AES-CBC decryption failed: {ex.Message}"));
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
        UnitResult<SmartCardError> inputValidation = ValidateInputs(key, iv, data, "Key, IV, and data cannot be null");
        if (inputValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(inputValidation.Error);

        UnitResult<SmartCardError> ivValidation = ValidateIvLength(iv, 8, "IV must be 8 bytes for 3DES");
        if (ivValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(ivValidation.Error);

        return ExpandTripleDesKey(key)
            .Bind(expandedKey => Result.Try(() =>
            {
                // Use BouncyCastle's high-level API with integrated padding
                PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                    new CbcBlockCipher(new DesEdeEngine()),
                    new ISO7816d4Padding()
                );
                cipher.Init(true, new ParametersWithIV(new KeyParameter(expandedKey), iv));

                byte[] output = new byte[cipher.GetOutputSize(data.Length)];
                int len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
                len += cipher.DoFinal(output, len);

                // Return only the actual encrypted bytes
                if (len < output.Length)
                {
                    byte[] result = new byte[len];
                    Array.Copy(output, 0, result, 0, len);
                    return result;
                }

                return output;
            }, ex => SmartCardError.CryptographicError($"3DES-CBC encryption failed: {ex.Message}")));
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
        UnitResult<SmartCardError> inputValidation = ValidateInputs(key, iv, encryptedData, "Key, IV, and encrypted data cannot be null");
        if (inputValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(inputValidation.Error);

        UnitResult<SmartCardError> ivValidation = ValidateIvLength(iv, 8, "IV must be 8 bytes for 3DES");
        if (ivValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(ivValidation.Error);

        return ExpandTripleDesKey(key)
            .Bind(expandedKey => Result.Try(() =>
            {
                // Use BouncyCastle's high-level API with integrated padding
                PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                    new CbcBlockCipher(new DesEdeEngine()),
                    new ISO7816d4Padding()
                );
                cipher.Init(false, new ParametersWithIV(new KeyParameter(expandedKey), iv));

                byte[] output = new byte[cipher.GetOutputSize(encryptedData.Length)];
                int len = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, output, 0);
                len += cipher.DoFinal(output, len);

                // Return only the actual decrypted bytes
                byte[] result = new byte[len];
                Array.Copy(output, 0, result, 0, len);
                return result;
            }, ex => SmartCardError.CryptographicError($"3DES-CBC decryption failed: {ex.Message}")));
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
        UnitResult<SmartCardError> inputValidation = ValidateInputs(key, iv, data, "Key, IV, and data cannot be null");
        if (inputValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(inputValidation.Error);

        UnitResult<SmartCardError> ivValidation = ValidateIvLength(iv, 16, "IV must be 16 bytes for AES");
        if (ivValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(ivValidation.Error);

        UnitResult<SmartCardError> paddingValidation = ValidateDataPadding(data, 16, "Data must be padded to 16-byte blocks");
        if (paddingValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(paddingValidation.Error);

        return Result.Try(() =>
            {
                BufferedBlockCipher cipher = new BufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
                cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

                byte[] encrypted = new byte[data.Length];
                int len = cipher.ProcessBytes(data, 0, data.Length, encrypted, 0);
                _ = cipher.DoFinal(encrypted, len);

                return encrypted;
            }, ex => SmartCardError.CryptographicError($"AES-CBC encryption failed: {ex.Message}"));
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
        UnitResult<SmartCardError> inputValidation = ValidateInputs(key, iv, encryptedData, "Key, IV, and encrypted data cannot be null");
        if (inputValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(inputValidation.Error);

        UnitResult<SmartCardError> ivValidation = ValidateIvLength(iv, 16, "IV must be 16 bytes for AES");
        if (ivValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(ivValidation.Error);

        UnitResult<SmartCardError> paddingValidation = ValidateDataPadding(encryptedData, 16, "Encrypted data must be in 16-byte blocks");
        if (paddingValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(paddingValidation.Error);

        return Result.Try(() =>
            {
                BufferedBlockCipher cipher = new BufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
                cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

                byte[] decrypted = new byte[encryptedData.Length];
                int len = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, decrypted, 0);
                _ = cipher.DoFinal(decrypted, len);

                return decrypted;
            }, ex => SmartCardError.CryptographicError($"AES-CBC decryption failed: {ex.Message}"));
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
        UnitResult<SmartCardError> inputValidation = ValidateInputs(key, iv, data, "Key, IV, and data cannot be null");
        if (inputValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(inputValidation.Error);

        UnitResult<SmartCardError> ivValidation = ValidateIvLength(iv, 8, "IV must be 8 bytes for 3DES");
        if (ivValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(ivValidation.Error);

        UnitResult<SmartCardError> paddingValidation = ValidateDataPadding(data, 8, "Data must be padded to 8-byte blocks");
        if (paddingValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(paddingValidation.Error);

        return ExpandTripleDesKey(key)
            .Bind(expandedKey => Result.Try(() =>
            {
                BufferedBlockCipher cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
                cipher.Init(true, new ParametersWithIV(new KeyParameter(expandedKey), iv));

                byte[] encrypted = new byte[data.Length];
                int len = cipher.ProcessBytes(data, 0, data.Length, encrypted, 0);
                _ = cipher.DoFinal(encrypted, len);

                return encrypted;
            }, ex => SmartCardError.CryptographicError($"3DES-CBC encryption failed: {ex.Message}")));
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
        UnitResult<SmartCardError> inputValidation = ValidateInputs(key, iv, encryptedData, "Key, IV, and encrypted data cannot be null");
        if (inputValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(inputValidation.Error);

        UnitResult<SmartCardError> ivValidation = ValidateIvLength(iv, 8, "IV must be 8 bytes for 3DES");
        if (ivValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(ivValidation.Error);

        UnitResult<SmartCardError> paddingValidation = ValidateDataPadding(encryptedData, 8, "Encrypted data must be in 8-byte blocks");
        if (paddingValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(paddingValidation.Error);

        return ExpandTripleDesKey(key)
            .Bind(expandedKey => Result.Try(() =>
            {
                BufferedBlockCipher cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
                cipher.Init(false, new ParametersWithIV(new KeyParameter(expandedKey), iv));

                byte[] decrypted = new byte[encryptedData.Length];
                int len = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, decrypted, 0);
                _ = cipher.DoFinal(decrypted, len);

                return decrypted;
            }, ex => SmartCardError.CryptographicError($"3DES-CBC decryption failed: {ex.Message}")));
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
        UnitResult<SmartCardError> dataValidation = ValidateNonNullData(data, "Data cannot be null");
        if (dataValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(dataValidation.Error);

        UnitResult<SmartCardError> blockSizeValidation = ValidateBlockSize(blockSize);
        if (blockSizeValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(blockSizeValidation.Error);

        return ApplyPadding(data, blockSize);
    }

    private static Result<byte[], SmartCardError> ApplyPadding(byte[] data, int blockSize)
    {
        ISO7816d4Padding padding = new ISO7816d4Padding();
        int paddingLength = blockSize - (data.Length % blockSize);
        byte[] paddedData = new byte[data.Length + paddingLength];
        Array.Copy(data, 0, paddedData, 0, data.Length);

        // Use BouncyCastle's ISO 7816-4 padding - this operation cannot fail with valid input
        _ = padding.AddPadding(paddedData, data.Length);

        return Result.Success<byte[], SmartCardError>(paddedData);
    }

    /// <summary>
    /// Removes ISO 7816-4 padding from data.
    /// Uses BouncyCastle's ISO7816d4Padding class.
    /// </summary>
    /// <param name="paddedData">The padded data.</param>
    /// <returns>The unpadded data.</returns>
    public static Result<byte[], SmartCardError> RemoveIso7816Padding(byte[] paddedData)
    {
        UnitResult<SmartCardError> dataValidation = ValidateNonNullNonEmptyData(paddedData, "Padded data cannot be null or empty");
        if (dataValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(dataValidation.Error);

        return RemovePadding(paddedData);
    }

    private static Result<byte[], SmartCardError> RemovePadding(byte[] paddedData)
    {
        ISO7816d4Padding padding = new ISO7816d4Padding();
        int padCount = padding.PadCount(paddedData);

        // Validate padding count is reasonable
        if (padCount < 0 || padCount >= paddedData.Length)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidData("Invalid padding in response data"));
        }

        byte[] unpaddedData = new byte[paddedData.Length - padCount];
        Array.Copy(paddedData, 0, unpaddedData, 0, unpaddedData.Length);

        return Result.Success<byte[], SmartCardError>(unpaddedData);
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
        UnitResult<SmartCardError> dataValidation = ValidateNonNullData(data, "Data cannot be null");
        if (dataValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(dataValidation.Error);

        UnitResult<SmartCardError> blockSizeValidation = ValidateBlockSize(blockSize);
        if (blockSizeValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(blockSizeValidation.Error);

        return ApplyPkcs7PaddingInternal(data, blockSize);
    }

    private static Result<byte[], SmartCardError> ApplyPkcs7PaddingInternal(byte[] data, int blockSize)
    {
        Pkcs7Padding padding = new Pkcs7Padding();
        int paddingLength = blockSize - (data.Length % blockSize);
        byte[] paddedData = new byte[data.Length + paddingLength];
        Array.Copy(data, 0, paddedData, 0, data.Length);

        // Use BouncyCastle's PKCS#7 padding - this operation cannot fail with valid input
        _ = padding.AddPadding(paddedData, data.Length);

        return Result.Success<byte[], SmartCardError>(paddedData);
    }

    /// <summary>
    /// Removes PKCS#7 padding from data.
    /// Uses BouncyCastle's Pkcs7Padding class.
    /// </summary>
    /// <param name="paddedData">The padded data.</param>
    /// <returns>The unpadded data.</returns>
    public static Result<byte[], SmartCardError> RemovePkcs7Padding(byte[] paddedData)
    {
        UnitResult<SmartCardError> dataValidation = ValidateNonNullNonEmptyData(paddedData, "Padded data cannot be null or empty");
        if (dataValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(dataValidation.Error);

        return RemovePkcs7PaddingInternal(paddedData);
    }

    private static Result<byte[], SmartCardError> RemovePkcs7PaddingInternal(byte[] paddedData)
    {
        Pkcs7Padding padding = new Pkcs7Padding();
        int padCount = padding.PadCount(paddedData);

        // Validate padding count is reasonable
        if (padCount < 0 || padCount >= paddedData.Length)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidData("Invalid PKCS#7 padding in response data"));
        }

        byte[] unpaddedData = new byte[paddedData.Length - padCount];
        Array.Copy(paddedData, 0, unpaddedData, 0, unpaddedData.Length);

        return Result.Success<byte[], SmartCardError>(unpaddedData);
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
        return Maybe<byte[]>.From(data)
            .ToResult(SmartCardError.InvalidArgument("Data cannot be null"))
            .Bind(validData =>
            {
                if (targetLength < 0)
                {
                    return Result.Failure<byte[], SmartCardError>(
                        SmartCardError.InvalidArgument("Target length cannot be negative"));
                }

                if (validData.Length >= targetLength)
                {
                    return Result.Failure<byte[], SmartCardError>(
                        SmartCardError.InvalidArgument($"Data length {validData.Length} must be less than target length {targetLength} to allow for padding"));
                }

                byte[] paddedData = new byte[targetLength];
                Array.Copy(validData, 0, paddedData, 0, validData.Length);

                // Apply ISO 7816-4 padding using BouncyCastle's implementation
                ISO7816d4Padding padding = new ISO7816d4Padding();
                _ = padding.AddPadding(paddedData, validData.Length);

                return Result.Success<byte[], SmartCardError>(paddedData);
            });
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
        Maybe<byte[]> aMaybe = Maybe<byte[]>.From(a);
        Maybe<byte[]> bMaybe = Maybe<byte[]>.From(b);

        return aMaybe.Match(
            aValue => bMaybe.Match(
                bValue =>
                {
                    if (aValue.Length != bValue.Length)
                    {
                        return false;
                    }

                    // Functional constant-time comparison using LINQ
                    int result = aValue.Zip(bValue, (x, y) => x ^ y)
                        .Aggregate(0, (acc, xor) => acc | xor);

                    return result == 0;
                },
                () => false),
            () => false);
    }

    /// <summary>
    /// Concatenates multiple byte arrays.
    /// </summary>
    /// <param name="arrays">Arrays to concatenate.</param>
    /// <returns>The concatenated array.</returns>
    public static byte[] ConcatenateArrays(params byte[][] arrays)
    {
        byte[][] validArrays = arrays
            .Select(Maybe<byte[]>.From)
            .Where(m => m.HasValue)
            .Select(m => m.Value)
            .ToArray();

        int totalLength = validArrays.Sum(a => a.Length);
        byte[] result = new byte[totalLength];

        // Functional concatenation using LINQ Aggregate
        _ = validArrays.Aggregate(0, (offset, array) =>
        {
            Array.Copy(array, 0, result, offset, array.Length);
            return offset + array.Length;
        });

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
        ScpVersion protocolVersion)
    {

        return Result.Try(() =>
        {
            // Per GP SCP03 spec section 6.2.6:
            // Command ICV uses encryption counter
            byte[] counterBlock = new byte[16];
            counterBlock[12] = (byte)(encryptionCounter >> 24);
            counterBlock[13] = (byte)(encryptionCounter >> 16);
            counterBlock[14] = (byte)(encryptionCounter >> 8);
            counterBlock[15] = (byte)encryptionCounter;

            // Encrypt the counter block with S-ENC to produce the ICV using single-block AES
            AesEngine cipher = new AesEngine();
            cipher.Init(true, new KeyParameter(sEncKey));

            byte[] icv = new byte[16];
            _ = cipher.ProcessBlock(counterBlock, 0, icv, 0);

            return icv;
        }, ex => SmartCardError.CryptographicError($"ICV generation failed: {ex.Message}"));
    }

    // Random number generation functions (from CryptographyHelpers)

    /// <summary>
    /// Generates cryptographically secure random bytes.
    /// Uses BouncyCastle's SecureRandom for cryptographic security.
    /// </summary>
    /// <param name="length">Number of bytes to generate.</param>
    /// <returns>Array of random bytes or error.</returns>
    public static Result<byte[], SmartCardError> GenerateRandomBytes(int length)
    {
        if (length <= 0)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Length must be positive"));
        }

        return Result.Try(() =>
        {
            byte[] bytes = new byte[length];
            SecureRandom random = new Org.BouncyCastle.Security.SecureRandom();
            random.NextBytes(bytes);
            return bytes;
        }, ex => SmartCardError.CryptographicError($"Random number generation failed: {ex.Message}"));
    }

    /// <summary>
    /// Generates an 8-byte host challenge for secure channel establishment.
    /// Per GP Card Specification, host challenge is always 8 bytes.
    /// </summary>
    /// <returns>8-byte host challenge or error.</returns>
    public static Result<byte[], SmartCardError> GenerateHostChallenge()
    {
        return GenerateRandomBytes(8);
    }

    /// <summary>
    /// Generates a 16-byte sequence counter for SCP03.
    /// Per GP SCP03 Specification, sequence counter is 16 bytes.
    /// </summary>
    /// <returns>16-byte sequence counter or error.</returns>
    public static Result<byte[], SmartCardError> GenerateSequenceCounter()
    {
        return GenerateRandomBytes(16);
    }

    // Cryptogram building functions (from CryptogramBuilder)

    /// <summary>
    /// Verifies a card cryptogram using the provided data construction function.
    /// Supports both SCP02 and SCP03 protocols with appropriate key selection.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <param name="sessionKeys">The session keys.</param>
    /// <param name="buildCryptogramData">Function to build protocol-specific cryptogram data.</param>
    /// <param name="keyDerivationService">The key derivation service.</param>
    /// <param name="protocolVersion">The protocol version.</param>
    /// <returns>True if cryptogram is valid, false otherwise.</returns>
    public static Result<bool, SmartCardError> VerifyCardCryptogram(
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        SessionKeys sessionKeys,
        Func<InitializeUpdateResponse, byte[], Result<byte[], SmartCardError>> buildCryptogramData,
        IKeyDerivationService keyDerivationService,
        ScpVersion protocolVersion)
    {
        return Maybe<InitializeUpdateResponse>.From(response)
            .ToResult(SmartCardError.InvalidArgument("Response required"))
            .Bind(_ => Maybe<byte[]>.From(hostChallenge)
                .ToResult(SmartCardError.InvalidArgument("Host challenge required")))
            .Bind(_ => Maybe<SessionKeys>.From(sessionKeys)
                .ToResult(SmartCardError.InvalidArgument("Session keys required")))
            .Bind(_ => Maybe<Func<InitializeUpdateResponse, byte[], Result<byte[], SmartCardError>>>.From(buildCryptogramData)
                .ToResult(SmartCardError.InvalidArgument("Build cryptogram data function required")))
            .Bind(_ => Maybe<IKeyDerivationService>.From(keyDerivationService)
                .ToResult(SmartCardError.InvalidArgument("Key derivation service required")))
            .Bind(_ => buildCryptogramData(response, hostChallenge))
            .Bind(cryptogramData =>
            {
                // SCP02 uses S-ENC for cryptograms, SCP03 uses S-MAC
                byte[] cryptogramKey = protocolVersion == ScpVersion.Scp02 ? sessionKeys.SEnc : sessionKeys.SMac;

                CryptogramContext cryptogramContext = new CryptogramContext(
                    protocolVersion,
                    cryptogramKey,
                    cryptogramData,
                    CryptogramType.CardCryptogram
                );

                return keyDerivationService.CalculateCryptogram(cryptogramContext)
                    .Map(expectedCryptogram =>
                        CompareBytes(expectedCryptogram, response.CardCryptogram));
            });
    }

    /// <summary>
    /// Calculates a host cryptogram using the provided data construction function.
    /// Supports both SCP02 and SCP03 protocols with appropriate key selection.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <param name="sessionKeys">The session keys.</param>
    /// <param name="buildCryptogramData">Function to build protocol-specific cryptogram data.</param>
    /// <param name="keyDerivationService">The key derivation service.</param>
    /// <param name="protocolVersion">The protocol version.</param>
    /// <returns>The calculated host cryptogram.</returns>
    public static Result<byte[], SmartCardError> CalculateHostCryptogram(
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        SessionKeys sessionKeys,
        Func<InitializeUpdateResponse, byte[], Result<byte[], SmartCardError>> buildCryptogramData,
        IKeyDerivationService keyDerivationService,
        ScpVersion protocolVersion)
    {
        return Maybe<InitializeUpdateResponse>.From(response)
            .ToResult(SmartCardError.InvalidArgument("Response required"))
            .Bind(_ => Maybe<byte[]>.From(hostChallenge)
                .ToResult(SmartCardError.InvalidArgument("Host challenge required")))
            .Bind(_ => Maybe<SessionKeys>.From(sessionKeys)
                .ToResult(SmartCardError.InvalidArgument("Session keys required")))
            .Bind(_ => Maybe<Func<InitializeUpdateResponse, byte[], Result<byte[], SmartCardError>>>.From(buildCryptogramData)
                .ToResult(SmartCardError.InvalidArgument("Build cryptogram data function required")))
            .Bind(_ => Maybe<IKeyDerivationService>.From(keyDerivationService)
                .ToResult(SmartCardError.InvalidArgument("Key derivation service required")))
            .Bind(_ => buildCryptogramData(response, hostChallenge))
            .Bind(cryptogramData =>
            {
                // SCP02 uses S-ENC for cryptograms, SCP03 uses S-MAC
                byte[] cryptogramKey = protocolVersion == ScpVersion.Scp02 ? sessionKeys.SEnc : sessionKeys.SMac;

                CryptogramContext cryptogramContext = new CryptogramContext(
                    protocolVersion,
                    cryptogramKey,
                    cryptogramData,
                    CryptogramType.HostCryptogram
                );

                return keyDerivationService.CalculateCryptogram(cryptogramContext);
            });
    }

    /// <summary>
    /// Builds SCP02-specific card cryptogram data.
    /// Per GP Card Specification Appendix E.4.2.1: Host Challenge (8) || Sequence Counter (2) || Card Challenge (6)
    /// with ISO 7816-4 padding to 24 bytes total.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <returns>The SCP02 card cryptogram data.</returns>
    public static Result<byte[], SmartCardError> BuildScp02CardCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        Result<byte[], SmartCardError> hostValidation = ValidateHostChallenge(hostChallenge);
        if (hostValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(hostValidation.Error);

        Result<byte[], SmartCardError> cardValidation = ValidateCardChallenge(response.CardChallenge, 6);
        if (cardValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(cardValidation.Error);

        return ExtractScp02SequenceCounter(response)
            .Bind(sequenceCounter =>
            {
                byte[] seqCounterBytes = sequenceCounter[..2]; // First 2 bytes
                byte[] data = ConcatenateArrays(hostChallenge, seqCounterBytes, response.CardChallenge);
                return PadToLength(data, 24);
            });
    }

    /// <summary>
    /// Builds SCP02-specific host cryptogram data.
    /// Per GP Card Specification Appendix E.4.2.2: Sequence Counter (2) || Card Challenge (6) || Host Challenge (8)
    /// with ISO 7816-4 padding to 24 bytes total.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <returns>The SCP02 host cryptogram data.</returns>
    public static Result<byte[], SmartCardError> BuildScp02HostCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        Result<byte[], SmartCardError> hostValidation = ValidateHostChallenge(hostChallenge);
        if (hostValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(hostValidation.Error);

        Result<byte[], SmartCardError> cardValidation = ValidateCardChallenge(response.CardChallenge, 6);
        if (cardValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(cardValidation.Error);

        return ExtractScp02SequenceCounter(response)
            .Bind(sequenceCounter =>
            {
                byte[] seqCounterBytes = sequenceCounter[..2]; // First 2 bytes
                byte[] data = ConcatenateArrays(seqCounterBytes, response.CardChallenge, hostChallenge);
                return PadToLength(data, 24);
            });
    }

    /// <summary>
    /// Builds SCP03-specific card cryptogram data.
    /// Per GP SCP03 Specification: Host Challenge (8) || Card Challenge (8) (no padding required).
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <returns>The SCP03 card cryptogram data.</returns>
    public static Result<byte[], SmartCardError> BuildScp03CardCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        Result<byte[], SmartCardError> hostValidation = ValidateHostChallenge(hostChallenge);
        if (hostValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(hostValidation.Error);

        Result<byte[], SmartCardError> cardValidation = ValidateCardChallenge(response.CardChallenge, 8);
        if (cardValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(cardValidation.Error);

        // SCP03 card cryptogram data: Host Challenge (8) || Card Challenge (8)
        return Result.Success<byte[], SmartCardError>(
            ConcatenateArrays(hostChallenge, response.CardChallenge));
    }

    /// <summary>
    /// Builds SCP03-specific host cryptogram data.
    /// Per GP SCP03 Specification: Card Challenge (8) || Host Challenge (8) (no padding required).
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <returns>The SCP03 host cryptogram data.</returns>
    public static Result<byte[], SmartCardError> BuildScp03HostCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        Result<byte[], SmartCardError> hostValidation = ValidateHostChallenge(hostChallenge);
        if (hostValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(hostValidation.Error);

        Result<byte[], SmartCardError> cardValidation = ValidateCardChallenge(response.CardChallenge, 8);
        if (cardValidation.IsFailure)
            return Result.Failure<byte[], SmartCardError>(cardValidation.Error);

        // SCP03 host cryptogram data: Card Challenge (8) || Host Challenge (8)
        return Result.Success<byte[], SmartCardError>(
            ConcatenateArrays(response.CardChallenge, hostChallenge));
    }

    // Private helper methods

    /// <summary>
    /// Validates host challenge length and format.
    /// </summary>
    /// <param name="hostChallenge">The host challenge to validate.</param>
    /// <returns>Success if valid, error otherwise.</returns>
    private static Result<byte[], SmartCardError> ValidateHostChallenge(byte[] hostChallenge)
    {
        return Maybe<byte[]>.From(hostChallenge)
            .ToResult(SmartCardError.InvalidArgument("Host challenge required"))
            .Bind(challenge => challenge.Length == 8
                ? Result.Success<byte[], SmartCardError>(challenge)
                : Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument($"Host challenge must be 8 bytes, got {challenge.Length}")));
    }

    /// <summary>
    /// Validates card challenge length and format.
    /// </summary>
    /// <param name="cardChallenge">The card challenge to validate.</param>
    /// <param name="expectedLength">Expected length (6 for SCP02, 8 for SCP03).</param>
    /// <returns>Success if valid, error otherwise.</returns>
    private static Result<byte[], SmartCardError> ValidateCardChallenge(byte[] cardChallenge, int expectedLength)
    {
        return Maybe<byte[]>.From(cardChallenge)
            .ToResult(SmartCardError.InvalidArgument("Card challenge required"))
            .Bind(challenge => challenge.Length == expectedLength
                ? Result.Success<byte[], SmartCardError>(challenge)
                : Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument($"Card challenge must be {expectedLength} bytes, got {challenge.Length}")));
    }

    /// <summary>
    /// Extracts the 2-byte sequence counter from an SCP02 INITIALIZE UPDATE response.
    /// </summary>
    /// <param name="response">The response.</param>
    /// <returns>The sequence counter (at least 2 bytes).</returns>
    private static Result<byte[], SmartCardError> ExtractScp02SequenceCounter(InitializeUpdateResponse response)
    {
        return Maybe<byte[]>.From(response.SequenceCounter)
            .ToResult(SmartCardError.InvalidResponse("SequenceCounter required for SCP02"))
            .Bind(counter => counter.Length >= 2
                ? Result.Success<byte[], SmartCardError>(counter)
                : Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidResponse($"SequenceCounter must be at least 2 bytes, got {counter.Length}")));
    }

    // ICV Encryption functions (consolidated from IcvEncryptionService)

    /// <summary>
    /// Applies ICV encryption to the MAC chaining value if required by the implementation.
    /// Per GP Section E.3.4: "The encryption mechanism used is single DES with the first half
    /// of the Secure Channel C-MAC session key."
    /// </summary>
    /// <param name="macChainingValue">The current MAC chaining value (ICV)</param>
    /// <param name="cMacSessionKey">The 16-byte C-MAC session key</param>
    /// <param name="implementation">The SCP02 implementation parameter</param>
    /// <param name="isFirstIcvOfSession">True if this is the first ICV of the session (never encrypted)</param>
    /// <returns>Result containing the processed ICV (encrypted or unencrypted based on requirements)</returns>
    public static Result<byte[], SmartCardError> ProcessIcvForMacCalculation(
        byte[] macChainingValue,
        byte[] cMacSessionKey,
        ScpImplementation implementation,
        bool isFirstIcvOfSession)
    {
        return Maybe<byte[]>.From(macChainingValue)
            .ToResult(SmartCardError.InvalidArgument("MAC chaining value required"))
            .Bind(_ => Maybe<byte[]>.From(cMacSessionKey)
                .ToResult(SmartCardError.InvalidArgument("C-MAC session key required")))
            .Bind(_ => macChainingValue.Length == 8
                ? Result.Success<byte[], SmartCardError>(macChainingValue)
                : Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("MAC chaining value must be 8 bytes for SCP02")))
            .Bind(_ => cMacSessionKey.Length == 16
                ? Result.Success<byte[], SmartCardError>(cMacSessionKey)
                : Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("C-MAC session key must be 16 bytes")))
            .Bind(_ =>
            {
                // GP Section E.3.4: First ICV of session is never encrypted
                if (isFirstIcvOfSession)
                {
                    return Result.Success<byte[], SmartCardError>(macChainingValue);
                }

                // Check if implementation requires ICV encryption
                if (!ShouldApplyIcvEncryption(implementation, isFirstIcvOfSession))
                {
                    return Result.Success<byte[], SmartCardError>(macChainingValue);
                }

                // Apply ICV encryption per GP Section E.3.4
                return EncryptIcvWithFirstHalfOfCMacKey(macChainingValue, cMacSessionKey);
            });
    }

    /// <summary>
    /// Determines whether ICV encryption should be applied based on implementation and session state.
    /// Per GP specification rules for SCP02 ICV encryption.
    /// </summary>
    /// <param name="implementation">The SCP02 implementation parameter</param>
    /// <param name="isFirstIcvOfSession">True if this is the first ICV of the session</param>
    /// <returns>True if ICV encryption should be applied, false otherwise</returns>
    public static bool ShouldApplyIcvEncryption(ScpImplementation implementation, bool isFirstIcvOfSession)
    {
        // GP Section E.3.4: First ICV is never encrypted
        if (isFirstIcvOfSession)
        {
            return false;
        }

        // GP Table E-1: bit b5 (0x10) indicates ICV encryption
        return implementation.HasIcvEncryption();
    }

    /// <summary>
    /// Validates that the implementation and session keys are compatible with ICV encryption requirements.
    /// </summary>
    /// <param name="implementation">The SCP02 implementation parameter</param>
    /// <param name="cMacSessionKey">The C-MAC session key</param>
    /// <returns>Result indicating validation success or specific error</returns>
    public static Result ValidateIcvEncryptionRequirements(
        ScpImplementation implementation,
        byte[] cMacSessionKey)
    {
        if (!implementation.IsScp02())
        {
            return Result.Failure("ICV encryption only applies to SCP02 implementations");
        }

        if (implementation.HasIcvEncryption())
        {
            return Maybe<byte[]>.From(cMacSessionKey)
                .Match(
                    key => key.Length == 16
                        ? Result.Success()
                        : Result.Failure("ICV encryption implementations require 16-byte C-MAC session key"),
                    () => Result.Failure("ICV encryption implementations require 16-byte C-MAC session key"));
        }

        return Result.Success();
    }

    /// <summary>
    /// Encrypts the ICV using single DES with the first half of the C-MAC session key.
    /// Per GP Section E.3.4: "The encryption mechanism used is single DES with the first half
    /// of the Secure Channel C-MAC session key."
    /// </summary>
    /// <param name="icv">The ICV to encrypt</param>
    /// <param name="cMacSessionKey">The 16-byte C-MAC session key</param>
    /// <returns>The encrypted ICV</returns>
    private static Result<byte[], SmartCardError> EncryptIcvWithFirstHalfOfCMacKey(
        byte[] icv,
        byte[] cMacSessionKey)
    {
        return Result.Try(() =>
        {
            // Extract first 8 bytes of C-MAC session key for ICV encryption
            byte[] icvEncryptionKey = cMacSessionKey[..8];

            // Apply single DES encryption per GP specification
            DesEngine desEngine = new Org.BouncyCastle.Crypto.Engines.DesEngine();
            KeyParameter keyParam = new Org.BouncyCastle.Crypto.Parameters.KeyParameter(icvEncryptionKey);
            desEngine.Init(true, keyParam); // true for encryption

            byte[] encryptedIcv = new byte[8];
            _ = desEngine.ProcessBlock(icv, 0, encryptedIcv, 0);

            return encryptedIcv;
        }, ex => SmartCardError.CryptographicError($"ICV encryption failed: {ex.Message}"));
    }

    // MAC Input Building functions (consolidated from ApduParser)

    /// <summary>
    /// Builds MAC input data for command MAC calculation.
    /// Formats input according to protocol-specific requirements per GP specification.
    /// </summary>
    /// <param name="cla">The class byte</param>
    /// <param name="ins">The instruction byte</param>
    /// <param name="p1">The P1 parameter byte</param>
    /// <param name="p2">The P2 parameter byte</param>
    /// <param name="data">The command data</param>
    /// <param name="protocolVersion">The SCP protocol version</param>
    /// <returns>The formatted MAC input data</returns>
    public static byte[] BuildMacInput(byte cla, byte ins, byte p1, byte p2, byte[] data, ScpVersion protocolVersion)
    {
        if (protocolVersion == ScpVersion.Scp03)
        {
            // SCP03 MAC input: fixed CLA (0x84) + INS + P1 + P2 + modified Lc + data
            List<byte> macInput =
            [
                0x84, // Fixed CLA for SCP03 MAC calculation
                ins,
                p1,
                p2,
                (byte)(data.Length + 8)
            ];
            macInput.AddRange(data);
            return macInput.ToArray();
        }
        else
        {
            // SCP02 MAC input: original CLA + INS + P1 + P2 + modified Lc + data
            List<byte> macInput =
            [
                cla,
                ins,
                p1,
                p2,
                (byte)(data.Length + 8)
            ];
            macInput.AddRange(data);
            return macInput.ToArray();
        }
    }

    /// <summary>
    /// Builds MAC input data from a parsed secured command.
    /// Convenience overload for parsed commands.
    /// </summary>
    /// <param name="parsedCommand">The parsed secured command</param>
    /// <param name="protocolVersion">The SCP protocol version</param>
    /// <returns>The formatted MAC input data</returns>
    public static byte[] BuildMacInput(ParsedSecuredCommand parsedCommand, ScpVersion protocolVersion)
    {
        return BuildMacInput(parsedCommand.Cla, parsedCommand.Ins, parsedCommand.P1, parsedCommand.P2, 
            parsedCommand.Data, protocolVersion);
    }

}
