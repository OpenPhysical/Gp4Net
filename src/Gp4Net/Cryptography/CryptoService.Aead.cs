using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Gp4Net.Cryptography;

public static partial class CryptoService
{
    /// <summary>
    /// Authenticated Encryption with Associated Data (AEAD) operations.
    /// Provides AES-GCM encryption and decryption for secure communications.
    /// Consolidates AEAD operations from multiple classes into a single interface.
    /// </summary>
    public static class Aead
    {
        /// <summary>
        /// Encrypts data using AES-GCM with associated data.
        /// Per NIST SP 800-38D for AES-GCM authenticated encryption.
        /// </summary>
        /// <param name="key">The AES key (16, 24, or 32 bytes).</param>
        /// <param name="nonce">The nonce/IV (typically 12 bytes for GCM).</param>
        /// <param name="plaintext">The data to encrypt.</param>
        /// <param name="associatedData">Associated data to authenticate (can be empty).</param>
        /// <param name="tagLength">The authentication tag length in bits (default 128).</param>
        /// <returns>The encrypted data with authentication tag appended or error.</returns>
        public static Result<byte[], SmartCardError> EncryptAesGcm(
            byte[] key,
            byte[] nonce,
            byte[] plaintext,
            byte[] associatedData,
            int tagLength = 128
        )
        {
            return ValidateAesGcmInputs(key, nonce, plaintext, tagLength)
                .Bind(
                    () =>
                        Result.Try(
                            () =>
                            {
                                var gcmCipher = new GcmBlockCipher(new AesEngine());
                                var parameters = new AeadParameters(
                                    new KeyParameter(key),
                                    tagLength,
                                    nonce,
                                    associatedData
                                );
                                gcmCipher.Init(true, parameters);

                                int outputLength = gcmCipher.GetOutputSize(plaintext.Length);
                                byte[] output = new byte[outputLength];
                                int len = gcmCipher.ProcessBytes(
                                    plaintext,
                                    0,
                                    plaintext.Length,
                                    output,
                                    0
                                );
                                len += gcmCipher.DoFinal(output, len);

                                if (len < outputLength)
                                {
                                    byte[] result = new byte[len];
                                    Array.Copy(output, 0, result, 0, len);
                                    return result;
                                }

                                return output;
                            },
                            static ex =>
                                SmartCardError.CryptographicError(
                                    $"AES-GCM encryption failed: {ex.Message}"
                                )
                        )
                );
        }

        /// <summary>
        /// Decrypts data using AES-GCM with associated data verification.
        /// Per NIST SP 800-38D for AES-GCM authenticated decryption.
        /// </summary>
        /// <param name="key">The AES key (16, 24, or 32 bytes).</param>
        /// <param name="nonce">The nonce/IV (typically 12 bytes for GCM).</param>
        /// <param name="ciphertext">The encrypted data with authentication tag.</param>
        /// <param name="associatedData">Associated data to verify (can be empty).</param>
        /// <param name="tagLength">The authentication tag length in bits (default 128).</param>
        /// <returns>The decrypted plaintext or error.</returns>
        public static Result<byte[], SmartCardError> DecryptAesGcm(
            byte[] key,
            byte[] nonce,
            byte[] ciphertext,
            byte[] associatedData,
            int tagLength = 128
        )
        {
            return ValidateAesGcmInputs(key, nonce, ciphertext, tagLength)
                .Bind(() => ValidateCiphertextLength(ciphertext, tagLength))
                .Bind(
                    () =>
                        Result.Try(
                            () =>
                            {
                                var gcmCipher = new GcmBlockCipher(new AesEngine());
                                var parameters = new AeadParameters(
                                    new KeyParameter(key),
                                    tagLength,
                                    nonce,
                                    associatedData
                                );
                                gcmCipher.Init(false, parameters);

                                int outputLength = gcmCipher.GetOutputSize(ciphertext.Length);
                                byte[] output = new byte[outputLength];
                                int len = gcmCipher.ProcessBytes(
                                    ciphertext,
                                    0,
                                    ciphertext.Length,
                                    output,
                                    0
                                );
                                len += gcmCipher.DoFinal(output, len);

                                byte[] result = new byte[len];
                                Array.Copy(output, 0, result, 0, len);
                                return result;
                            },
                            static ex =>
                                ex is Org.BouncyCastle.Crypto.InvalidCipherTextException
                                    ? SmartCardError.IntegrityError(
                                        $"AES-GCM decryption failed: {ex.Message}"
                                    )
                                    : SmartCardError.CryptographicError(
                                        $"AES-GCM decryption failed: {ex.Message}"
                                    )
                        )
                );
        }

        /// <summary>
        /// Validates AES-GCM operation inputs.
        /// </summary>
        private static UnitResult<SmartCardError> ValidateAesGcmInputs(
            byte[] key,
            byte[] nonce,
            byte[] data,
            int tagLength
        )
        {
            return Validation
                .ValidateInputs(key, data)
                .Bind(
                    () =>
                        Validation.ValidateKeyLength(
                            key,
                            [16, 24, 32],
                            "AES key must be 16, 24, or 32 bytes"
                        )
                )
                .Bind(
                    () =>
                        nonce.Length > 0
                            ? UnitResult.Success<SmartCardError>()
                            : UnitResult.Failure(
                                SmartCardError.InvalidArgument("Nonce cannot be empty")
                            )
                )
                .Bind(
                    () =>
                        tagLength is 96 or 104 or 112 or 120 or 128
                            ? UnitResult.Success<SmartCardError>()
                            : UnitResult.Failure(
                                SmartCardError.InvalidArgument(
                                    "Tag length must be 96, 104, 112, 120, or 128 bits"
                                )
                            )
                );
        }

        /// <summary>
        /// Validates that ciphertext is long enough to contain the authentication tag.
        /// </summary>
        private static UnitResult<SmartCardError> ValidateCiphertextLength(
            byte[] ciphertext,
            int tagLength
        )
        {
            int tagBytes = tagLength / 8;
            return ciphertext.Length >= tagBytes
                ? UnitResult.Success<SmartCardError>()
                : UnitResult.Failure(
                    SmartCardError.InvalidArgument(
                        $"Ciphertext too short: {ciphertext.Length} bytes, need at least {tagBytes} bytes for tag"
                    )
                );
        }
    }
}
