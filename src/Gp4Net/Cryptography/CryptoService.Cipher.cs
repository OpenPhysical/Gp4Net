using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Cryptography;

public static partial class CryptoService
{
    /// <summary>
    /// Cipher operations: AES and 3DES encryption/decryption with various modes.
    /// Consolidates all symmetric encryption operations from multiple classes.
    /// </summary>
    public static class Cipher
    {
        /// <summary>
        /// Encrypts data using AES-CBC with ISO7816-4 padding.
        /// Uses BouncyCastle's PaddedBufferedBlockCipher for integrated padding and encryption.
        /// </summary>
        /// <param name="key">The AES key.</param>
        /// <param name="iv">The initialization vector (16 bytes).</param>
        /// <param name="data">The data to encrypt.</param>
        /// <returns>The encrypted and padded data.</returns>
        public static Result<byte[], SmartCardError> EncryptAesCbcWithPadding(
            byte[] key,
            byte[] iv,
            byte[] data
        )
        {
            // @TODO NO NULLS!
            return Validation.ValidateInputs(key, iv, data)
                .Bind(() => Validation.ValidateIvLength(iv, 16, "IV must be 16 bytes for AES"))
                .Bind(() =>
                    Result.Try(
                        () =>
                        {
                            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                                new CbcBlockCipher(new AesEngine()),
                                new ISO7816d4Padding()
                            );
                            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

                            byte[] output = new byte[cipher.GetOutputSize(data.Length)];
                            int len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
                            len += cipher.DoFinal(output, len);

                            if (len < output.Length)
                            {
                                byte[] result = new byte[len];
                                Array.Copy(output, 0, result, 0, len);
                                return result;
                            }

                            return output;
                        },
                        ex => SmartCardError.CryptographicError($"AES-CBC encryption failed: {ex.Message}")
                    )
                );
        }

        /// <summary>
        /// Decrypts data using AES-CBC with ISO7816-4 padding removal.
        /// Uses BouncyCastle's PaddedBufferedBlockCipher for integrated decryption and unpadding.
        /// </summary>
        /// <param name="key">The AES key.</param>
        /// <param name="iv">The initialization vector (16 bytes).</param>
        /// <param name="encryptedData">The encrypted data.</param>
        /// <returns>The decrypted and unpadded data.</returns>
        public static Result<byte[], SmartCardError> DecryptAesCbcWithPadding(
            byte[] key,
            byte[] iv,
            byte[] encryptedData
        )
        {
            // @TODO NO NULLS!
            return Validation.ValidateInputs(key, iv, encryptedData)
                .Bind(() => Validation.ValidateIvLength(iv, 16, "IV must be 16 bytes for AES"))
                .Bind(() =>
                    Result.Try(
                        () =>
                        {
                            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                                new CbcBlockCipher(new AesEngine()),
                                new ISO7816d4Padding()
                            );
                            cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

                            byte[] output = new byte[cipher.GetOutputSize(encryptedData.Length)];
                            int len = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, output, 0);
                            len += cipher.DoFinal(output, len);

                            byte[] result = new byte[len];
                            Array.Copy(output, 0, result, 0, len);
                            return result;
                        },
                        ex => SmartCardError.CryptographicError($"AES-CBC decryption failed: {ex.Message}")
                    )
                );
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
        {// @TODO NO NULLS!
            return Validation.ValidateInputs(key, iv, data)
                .Bind(() => Validation.ValidateIvLength(iv, 16, "IV must be 16 bytes for AES"))
                .Bind(() => Validation.ValidateDataPadding(data, 16, "Data must be padded to 16-byte blocks"))
                .Bind(() =>
                    Result.Try(
                        () =>
                        {
                            BufferedBlockCipher cipher = new BufferedBlockCipher(
                                new CbcBlockCipher(new AesEngine())
                            );
                            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

                            byte[] encrypted = new byte[data.Length];
                            int len = cipher.ProcessBytes(data, 0, data.Length, encrypted, 0);
                            cipher.DoFinal(encrypted, len);

                            return encrypted;
                        },
                        ex => SmartCardError.CryptographicError($"AES-CBC encryption failed: {ex.Message}")
                    )
                );
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
        public static Result<byte[], SmartCardError> DecryptAesCbc(
            byte[] key,
            byte[] iv,
            byte[] encryptedData
        )
        {// @TODO NO NULLS!
            return Validation.ValidateInputs(key, iv, encryptedData)
                .Bind(() => Validation.ValidateIvLength(iv, 16, "IV must be 16 bytes for AES"))
                .Bind(() => Validation.ValidateDataPadding(encryptedData, 16, "Encrypted data must be in 16-byte blocks"))
                .Bind(() =>
                    Result.Try(
                        () =>
                        {
                            BufferedBlockCipher cipher = new BufferedBlockCipher(
                                new CbcBlockCipher(new AesEngine())
                            );
                            cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

                            byte[] decrypted = new byte[encryptedData.Length];
                            int len = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, decrypted, 0);
                            cipher.DoFinal(decrypted, len);

                            return decrypted;
                        },
                        ex => SmartCardError.CryptographicError($"AES-CBC decryption failed: {ex.Message}")
                    )
                );
        }

        /// <summary>
        /// Encrypts data using 3DES-CBC with ISO7816-4 padding.
        /// Uses BouncyCastle's PaddedBufferedBlockCipher for integrated padding and encryption.
        /// </summary>
        /// <param name="key">The 3DES key (16 or 24 bytes).</param>
        /// <param name="iv">The initialization vector (8 bytes).</param>
        /// <param name="data">The data to encrypt.</param>
        /// <returns>The encrypted and padded data.</returns>
        public static Result<byte[], SmartCardError> Encrypt3DesCbcWithPadding(
            byte[] key,
            byte[] iv,
            byte[] data
        )
        {// @TODO NO NULLS!
            return Validation.ValidateInputs(key, iv, data)
                .Bind(() => Validation.ValidateIvLength(iv, 8, "IV must be 8 bytes for 3DES"))
                .Bind(() => Utils.ExpandTripleDesKey(key))
                .Bind(expandedKey =>
                    Result.Try(
                        () =>
                        {
                            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                                new CbcBlockCipher(new DesEdeEngine()),
                                new ISO7816d4Padding()
                            );
                            cipher.Init(true, new ParametersWithIV(new KeyParameter(expandedKey), iv));

                            byte[] output = new byte[cipher.GetOutputSize(data.Length)];
                            int len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
                            len += cipher.DoFinal(output, len);

                            if (len < output.Length)
                            {
                                byte[] result = new byte[len];
                                Array.Copy(output, 0, result, 0, len);
                                return result;
                            }

                            return output;
                        },
                        ex => SmartCardError.CryptographicError($"3DES-CBC encryption failed: {ex.Message}")
                    )
                );
        }

        /// <summary>
        /// Decrypts data using 3DES-CBC with ISO7816-4 padding removal.
        /// Uses BouncyCastle's PaddedBufferedBlockCipher for integrated decryption and unpadding.
        /// </summary>
        /// <param name="key">The 3DES key (16 or 24 bytes).</param>
        /// <param name="iv">The initialization vector (8 bytes).</param>
        /// <param name="encryptedData">The encrypted data.</param>
        /// <returns>The decrypted and unpadded data.</returns>
        public static Result<byte[], SmartCardError> Decrypt3DesCbcWithPadding(
            byte[] key,
            byte[] iv,
            byte[] encryptedData
        )
        {// @TODO NO NULLS!
            return Validation.ValidateInputs(key, iv, encryptedData)
                .Bind(() => Validation.ValidateIvLength(iv, 8, "IV must be 8 bytes for 3DES"))
                .Bind(() => Utils.ExpandTripleDesKey(key))
                .Bind(expandedKey =>
                    Result.Try(
                        () =>
                        {
                            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                                new CbcBlockCipher(new DesEdeEngine()),
                                new ISO7816d4Padding()
                            );
                            cipher.Init(false, new ParametersWithIV(new KeyParameter(expandedKey), iv));

                            byte[] output = new byte[cipher.GetOutputSize(encryptedData.Length)];
                            int len = cipher.ProcessBytes(
                                encryptedData,
                                0,
                                encryptedData.Length,
                                output,
                                0
                            );
                            len += cipher.DoFinal(output, len);

                            byte[] result = new byte[len];
                            Array.Copy(output, 0, result, 0, len);
                            return result;
                        },
                        ex => SmartCardError.CryptographicError($"3DES-CBC decryption failed: {ex.Message}")
                    )
                );
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
        {// @TODO NO NULLS!
            return Validation.ValidateInputs(key, iv, data)
                .Bind(() => Validation.ValidateIvLength(iv, 8, "IV must be 8 bytes for 3DES"))
                .Bind(() => Validation.ValidateDataPadding(data, 8, "Data must be padded to 8-byte blocks"))
                .Bind(() => Utils.ExpandTripleDesKey(key))
                .Bind(expandedKey =>
                    Result.Try(
                        () =>
                        {
                            BufferedBlockCipher cipher = new BufferedBlockCipher(
                                new CbcBlockCipher(new DesEdeEngine())
                            );
                            cipher.Init(true, new ParametersWithIV(new KeyParameter(expandedKey), iv));

                            byte[] encrypted = new byte[data.Length];
                            int len = cipher.ProcessBytes(data, 0, data.Length, encrypted, 0);
                            cipher.DoFinal(encrypted, len);

                            return encrypted;
                        },
                        ex => SmartCardError.CryptographicError($"3DES-CBC encryption failed: {ex.Message}")
                    )
                );
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
        public static Result<byte[], SmartCardError> Decrypt3DesCbc(
            byte[] key,
            byte[] iv,
            byte[] encryptedData
        )
        {// @TODO NO NULLS!
            return Validation.ValidateInputs(key, iv, encryptedData)
                .Bind(() => Validation.ValidateIvLength(iv, 8, "IV must be 8 bytes for 3DES"))
                .Bind(() => Validation.ValidateDataPadding(encryptedData, 8, "Encrypted data must be in 8-byte blocks"))
                .Bind(() => Utils.ExpandTripleDesKey(key))
                .Bind(expandedKey =>
                    Result.Try(
                        () =>
                        {
                            BufferedBlockCipher cipher = new BufferedBlockCipher(
                                new CbcBlockCipher(new DesEdeEngine())
                            );
                            cipher.Init(false, new ParametersWithIV(new KeyParameter(expandedKey), iv));

                            byte[] decrypted = new byte[encryptedData.Length];
                            int len = cipher.ProcessBytes(
                                encryptedData,
                                0,
                                encryptedData.Length,
                                decrypted,
                                0
                            );
                            cipher.DoFinal(decrypted, len);

                            return decrypted;
                        },
                        ex => SmartCardError.CryptographicError($"3DES-CBC decryption failed: {ex.Message}")
                    )
                );
        }

        /// <summary>
        /// Encrypts data using AES-ECB mode.
        /// Used for KCV calculation per GlobalPlatform specification.
        /// AES-ECB encrypts each 16-byte block independently.
        /// </summary>
        /// <param name="key">The AES key (16, 24, or 32 bytes).</param>
        /// <param name="data">The data to encrypt (must be multiple of 16 bytes).</param>
        /// <returns>The encrypted data.</returns>
        public static Result<byte[], SmartCardError> EncryptAesEcb(byte[] key, byte[] data)
        {
            return Validation.ValidateInputs(key, data)
                .Bind(() => Validation.ValidateKeyLength(key, [16, 24, 32], "AES key must be 16, 24, or 32 bytes"))
                .Bind(() => Validation.ValidateDataPadding(data, 16, "Data must be padded to 16-byte blocks"))
                .Bind(() =>
                    Result.Try(
                        () =>
                        {
                            BufferedBlockCipher cipher = new BufferedBlockCipher(new AesEngine());
                            cipher.Init(true, new KeyParameter(key));

                            byte[] encrypted = new byte[data.Length];
                            int len = cipher.ProcessBytes(data, 0, data.Length, encrypted, 0);
                            cipher.DoFinal(encrypted, len);

                            return encrypted;
                        },
                        ex => SmartCardError.CryptographicError($"AES-ECB encryption failed: {ex.Message}")
                    )
                );
        }
    }
}
