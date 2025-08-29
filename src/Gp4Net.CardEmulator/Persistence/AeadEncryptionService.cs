using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.CardEmulator.Core;
using JetBrains.Annotations;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Gp4Net.CardEmulator.Persistence;

/// <summary>
/// Service for AEAD encryption/decryption of card state data.
/// Uses AES-256-GCM with UUID as additional authenticated data for identity binding.
/// Provides confidentiality, integrity, and authenticity for persisted card state.
/// </summary>
[PublicAPI]
public class AeadEncryptionService : IDisposable
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
        CardUuid cardUuid)
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
        CardUuid cardUuid)
    {
        return EnsureNotDisposed()
            .Bind(_ => ValidateDecryptionInputs(key, encryptedPayload, cardUuid))
            .Bind(_ => ExecuteDecryption(key, encryptedPayload, cardUuid));
    }

    private Result<bool, SmartCardError> EnsureNotDisposed()
    {
        return _disposed
            ? Result.Failure<bool, SmartCardError>(
                SmartCardError.CommunicationError("AEAD service has been disposed"))
            : Result.Success<bool, SmartCardError>(true);
    }

    private static Result<bool, SmartCardError> ValidateEncryptionInputs(
        byte[] key, 
        byte[] plaintext, 
        CardUuid cardUuid)
    {
        return ValidateKey(key)
            .Bind(_ => ValidatePlaintext(plaintext))
            .Bind(_ => ValidateCardUuid(cardUuid));
    }

    private static Result<bool, SmartCardError> ValidateDecryptionInputs(
        byte[] key,
        EncryptedPayload encryptedPayload,
        CardUuid cardUuid)
    {
        return ValidateKey(key)
            .Bind(_ => ValidateEncryptedPayload(encryptedPayload))
            .Bind(_ => ValidateCardUuid(cardUuid));
    }

    private static Result<bool, SmartCardError> ValidateKey(byte[] key)
    {
        return Maybe<byte[]>.From(key)
            .Where(k => k.Length == 32)
            .ToResult(SmartCardError.InvalidArgument("Encryption key must be 32 bytes (AES-256)"))
            .Map(_ => true);
    }

    private static Result<bool, SmartCardError> ValidatePlaintext(byte[] plaintext)
    {
        return Maybe<byte[]>.From(plaintext)
            .ToResult(SmartCardError.InvalidArgument("Plaintext cannot be null"))
            .Map(_ => true);
    }

    private static Result<bool, SmartCardError> ValidateEncryptedPayload(EncryptedPayload encryptedPayload)
    {
        return Maybe<EncryptedPayload>.From(encryptedPayload)
            .Where(payload => payload.IsValid)
            .ToResult(SmartCardError.InvalidArgument("Invalid encrypted payload structure"))
            .Map(_ => true);
    }

    private static Result<bool, SmartCardError> ValidateCardUuid(CardUuid cardUuid)
    {
        return cardUuid.IsEmpty
            ? Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("Card UUID cannot be empty"))
            : Result.Success<bool, SmartCardError>(true);
    }

    private static Result<EncryptedPayload, SmartCardError> ExecuteEncryption(
        byte[] key,
        byte[] plaintext,
        CardUuid cardUuid)
    {
        return ExecuteAesGcmEncryption(key, plaintext, cardUuid);
    }

    private static Result<EncryptedPayload, SmartCardError> ExecuteAesGcmEncryption(
        byte[] key,
        byte[] plaintext,
        CardUuid cardUuid)
    {
        return GenerateSecureIv()
            .Bind(iv => PerformBouncyCastleEncryption(key, plaintext, cardUuid, iv));
    }

    private static Result<byte[], SmartCardError> GenerateSecureIv()
    {
        return Result.Try(() =>
        {
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[12]; // 96-bit IV for GCM
            secureRandom.NextBytes(iv);
            return iv;
        }, ex => SmartCardError.CryptographicError($"Failed to generate secure IV: {ex.Message}"));
    }

    private static Result<EncryptedPayload, SmartCardError> PerformBouncyCastleEncryption(
        byte[] key,
        byte[] plaintext,
        CardUuid cardUuid,
        byte[] iv)
    {
        return Result.Try(() =>
        {
            // Initialize AES-GCM cipher with BouncyCastle
            AesEngine aesEngine = new AesEngine();
            GcmBlockCipher gcmCipher = new GcmBlockCipher(aesEngine);
            
            byte[] aad = cardUuid.ToByteArray();
            AeadParameters aeadParameters = new AeadParameters(
                new KeyParameter(key),
                128, // 16-byte authentication tag in bits
                iv,
                aad);
            
            gcmCipher.Init(true, aeadParameters); // true for encryption
            
            // Encrypt plaintext and generate authentication tag
            byte[] ciphertextWithTag = new byte[gcmCipher.GetOutputSize(plaintext.Length)];
            int outputLen = gcmCipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertextWithTag, 0);
            outputLen += gcmCipher.DoFinal(ciphertextWithTag, outputLen);
            
            // Split ciphertext and authentication tag
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] authTag = new byte[16]; // 128-bit tag = 16 bytes
            
            Array.Copy(ciphertextWithTag, 0, ciphertext, 0, plaintext.Length);
            Array.Copy(ciphertextWithTag, plaintext.Length, authTag, 0, 16);
            
            return new EncryptedPayload(
                Algorithm: "aes-256-gcm",
                IV: iv,
                Ciphertext: ciphertext,
                AuthTag: authTag
            );
        }, ex => SmartCardError.CryptographicError($"AES-GCM encryption failed: {ex.Message}"));
    }

    private static Result<byte[], SmartCardError> ExecuteDecryption(
        byte[] key,
        EncryptedPayload encryptedPayload,
        CardUuid cardUuid)
    {
        return ExecuteAesGcmDecryption(key, encryptedPayload, cardUuid);
    }

    private static Result<byte[], SmartCardError> ExecuteAesGcmDecryption(
        byte[] key,
        EncryptedPayload encryptedPayload,
        CardUuid cardUuid)
    {
        return Result.Try(() =>
        {
            // Initialize AES-GCM cipher with BouncyCastle
            AesEngine aesEngine = new AesEngine();
            GcmBlockCipher gcmCipher = new GcmBlockCipher(aesEngine);
            
            byte[] aad = cardUuid.ToByteArray();
            AeadParameters aeadParameters = new AeadParameters(
                new KeyParameter(key),
                128, // 16-byte authentication tag in bits
                encryptedPayload.IV,
                aad);
            
            gcmCipher.Init(false, aeadParameters); // false for decryption
            
            // Combine ciphertext and authentication tag for decryption
            byte[] ciphertextWithTag = new byte[encryptedPayload.Ciphertext.Length + encryptedPayload.AuthTag.Length];
            Array.Copy(encryptedPayload.Ciphertext, 0, ciphertextWithTag, 0, encryptedPayload.Ciphertext.Length);
            Array.Copy(encryptedPayload.AuthTag, 0, ciphertextWithTag, encryptedPayload.Ciphertext.Length, encryptedPayload.AuthTag.Length);
            
            // Decrypt and verify authentication tag
            byte[] plaintext = new byte[gcmCipher.GetOutputSize(ciphertextWithTag.Length)];
            int outputLen = gcmCipher.ProcessBytes(ciphertextWithTag, 0, ciphertextWithTag.Length, plaintext, 0);
            outputLen += gcmCipher.DoFinal(plaintext, outputLen);
            
            // Trim plaintext to actual size (remove padding)
            byte[] result = new byte[encryptedPayload.Ciphertext.Length];
            Array.Copy(plaintext, 0, result, 0, encryptedPayload.Ciphertext.Length);
            
            return result;
        }, ex => ex.Message.Contains("mac check failed") || ex.Message.Contains("authentication")
            ? SmartCardError.IntegrityError($"AEAD authentication failed: {ex.Message}")
            : SmartCardError.CryptographicError($"AES-GCM decryption failed: {ex.Message}"));
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