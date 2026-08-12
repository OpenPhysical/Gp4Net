using System;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Persistence;

/// <summary>
/// Service for AEAD encryption/decryption of card state data.
/// Uses AES-256-GCM with UUID as additional authenticated data for identity binding.
/// Provides confidentiality, integrity, and authenticity for persisted card state.
/// </summary>
[PublicAPI]
public class CardStateEncryption : IDisposable
{
    private bool _disposed;

    /// <summary>
    /// Encrypts plaintext using AES-256-GCM with UUID as additional authenticated data.
    /// The UUID binding ensures ciphertext cannot be used with different card identities.
    /// </summary>
    /// <param name="key">256-bit encryption key derived from KDF108.</param>
    /// <param name="plaintext">CBOR-encoded card state data to encrypt.</param>
    /// <param name="cardUuid">Card UUID used as AAD for identity binding.</param>
    /// <returns>Encrypted payload with IV, ciphertext, and authentication tag.</returns>
    public Result<EncryptedPayload, SmartCardError> Encrypt(
        byte[] key,
        byte[] plaintext,
        CardUuid cardUuid
    )
    {
        return EnsureNotDisposed()
            .Bind(_ => ValidateEncryptionInputs(key, plaintext, cardUuid))
            .Bind(_ => ExecuteEncryption(key, plaintext, cardUuid));
    }

    /// <summary>
    /// Decrypts ciphertext using AES-256-GCM with UUID as additional authenticated data.
    /// Authentication will fail if the UUID doesn't match the original encryption.
    /// </summary>
    /// <param name="key">256-bit decryption key derived from KDF108.</param>
    /// <param name="encryptedPayload">Encrypted payload from persistence storage.</param>
    /// <param name="cardUuid">Card UUID used as AAD for identity verification.</param>
    /// <returns>Decrypted plaintext CBOR data or authentication failure.</returns>
    public Result<byte[], SmartCardError> Decrypt(
        byte[] key,
        EncryptedPayload encryptedPayload,
        CardUuid cardUuid
    )
    {
        return EnsureNotDisposed()
            .Bind(_ => ValidateDecryptionInputs(key, encryptedPayload, cardUuid))
            .Bind(_ => ExecuteDecryption(key, encryptedPayload, cardUuid));
    }

    private Result<bool, SmartCardError> EnsureNotDisposed()
    {
        return _disposed
            ? Result.Failure<bool, SmartCardError>(
                SmartCardError.CommunicationError("AEAD service has been disposed")
            )
            : Result.Success<bool, SmartCardError>(true);
    }

    private static Result<bool, SmartCardError> ValidateEncryptionInputs(
        byte[] key,
        byte[] plaintext,
        CardUuid cardUuid
    )
    {
        return ValidateKey(key)
            .Bind(_ => ValidatePlaintext(plaintext))
            .Bind(_ => ValidateCardUuid(cardUuid));
    }

    private static Result<bool, SmartCardError> ValidateDecryptionInputs(
        byte[] key,
        EncryptedPayload encryptedPayload,
        CardUuid cardUuid
    )
    {
        return ValidateKey(key)
            .Bind(_ => ValidateEncryptedPayload(encryptedPayload))
            .Bind(_ => ValidateCardUuid(cardUuid));
    }

    private static Result<bool, SmartCardError> ValidateKey(byte[] key)
    {
        if (key is null)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("Encryption key must be 32 bytes (AES-256)")
            );
        }

        return key.Length == 32
            ? Result.Success<bool, SmartCardError>(true)
            : Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("Encryption key must be 32 bytes (AES-256)")
            );
    }

    private static Result<bool, SmartCardError> ValidatePlaintext(byte[] plaintext)
    {
        return plaintext is null
            ? Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("Plaintext cannot be null")
            )
            : Result.Success<bool, SmartCardError>(true);
    }

    private static Result<bool, SmartCardError> ValidateEncryptedPayload(
        EncryptedPayload encryptedPayload
    )
    {
        if (encryptedPayload is null)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("Invalid encrypted payload structure")
            );
        }

        return encryptedPayload.IsValid
            ? Result.Success<bool, SmartCardError>(true)
            : Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("Invalid encrypted payload structure")
            );
    }

    private static Result<bool, SmartCardError> ValidateCardUuid(CardUuid cardUuid)
    {
        return cardUuid.IsEmpty
            ? Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("Card UUID cannot be empty")
            )
            : Result.Success<bool, SmartCardError>(true);
    }

    private static Result<EncryptedPayload, SmartCardError> ExecuteEncryption(
        byte[] key,
        byte[] plaintext,
        CardUuid cardUuid
    )
    {
        return ExecuteAesGcmEncryption(key, plaintext, cardUuid);
    }

    private static Result<EncryptedPayload, SmartCardError> ExecuteAesGcmEncryption(
        byte[] key,
        byte[] plaintext,
        CardUuid cardUuid
    )
    {
        return CryptoOperations
            .Rng.GenerateBytes(12) // 96-bit IV for GCM
            .Bind(iv => PerformUnifiedCryptoEncryption(key, plaintext, cardUuid, iv));
    }

    private static Result<EncryptedPayload, SmartCardError> PerformUnifiedCryptoEncryption(
        byte[] key,
        byte[] plaintext,
        CardUuid cardUuid,
        byte[] iv
    )
    {
        byte[] aad = cardUuid.ToByteArray();
        return CryptoOperations
            .Aead.EncryptAesGcm(key, iv, plaintext, aad, 128)
            .Bind(ciphertextWithTag =>
                ExtractCiphertextAndTag(ciphertextWithTag, plaintext.Length, iv)
            );
    }

    private static Result<EncryptedPayload, SmartCardError> ExtractCiphertextAndTag(
        byte[] ciphertextWithTag,
        int plaintextLength,
        byte[] iv
    )
    {
        return Result.Try(
            () =>
            {
                // Split ciphertext and authentication tag (last 16 bytes)
                byte[] ciphertext = new byte[plaintextLength];
                byte[] authTag = new byte[16]; // 128-bit tag = 16 bytes

                Array.Copy(ciphertextWithTag, 0, ciphertext, 0, plaintextLength);
                Array.Copy(ciphertextWithTag, plaintextLength, authTag, 0, 16);

                return new EncryptedPayload(
                    Algorithm: "aes-256-gcm",
                    Iv: iv,
                    Ciphertext: ciphertext,
                    AuthTag: authTag
                );
            },
            ex =>
                SmartCardError.CryptographicError(
                    $"Failed to extract ciphertext and tag: {ex.Message}"
                )
        );
    }

    private static Result<byte[], SmartCardError> ExecuteDecryption(
        byte[] key,
        EncryptedPayload encryptedPayload,
        CardUuid cardUuid
    )
    {
        return ExecuteAesGcmDecryption(key, encryptedPayload, cardUuid);
    }

    private static Result<byte[], SmartCardError> ExecuteAesGcmDecryption(
        byte[] key,
        EncryptedPayload encryptedPayload,
        CardUuid cardUuid
    )
    {
        return CombineCiphertextAndTag(encryptedPayload)
            .Bind(ciphertextWithTag =>
            {
                byte[] aad = cardUuid.ToByteArray();
                return CryptoOperations.Aead.DecryptAesGcm(
                    key,
                    encryptedPayload.Iv,
                    ciphertextWithTag,
                    aad,
                    128
                );
            });
    }

    private static Result<byte[], SmartCardError> CombineCiphertextAndTag(
        EncryptedPayload encryptedPayload
    )
    {
        return Result.Try(
            () =>
            {
                // Combine ciphertext and authentication tag for decryption
                byte[] ciphertextWithTag = new byte[
                    encryptedPayload.Ciphertext.Length + encryptedPayload.AuthTag.Length
                ];
                Array.Copy(
                    encryptedPayload.Ciphertext,
                    0,
                    ciphertextWithTag,
                    0,
                    encryptedPayload.Ciphertext.Length
                );
                Array.Copy(
                    encryptedPayload.AuthTag,
                    0,
                    ciphertextWithTag,
                    encryptedPayload.Ciphertext.Length,
                    encryptedPayload.AuthTag.Length
                );
                return ciphertextWithTag;
            },
            ex =>
                SmartCardError.CryptographicError(
                    $"Failed to combine ciphertext and tag: {ex.Message}"
                )
        );
    }

    /// <summary>
    /// Disposes the AEAD encryption service.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
        }
    }
}
