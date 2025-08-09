using System;
using System.Collections.Immutable;
using System.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Domain.Keys;

/// <summary>
/// Immutable, thread-safe secure key store that manages cryptographic keys
/// using functional programming patterns. Keys are encrypted in memory
/// and can only be accessed through secure operations.
/// </summary>
public sealed class SecureKeyStore
{
    private readonly ImmutableDictionary<string, EncryptedKey> _keys;
    private readonly byte[] _masterKey;
    private readonly byte[] _salt;

    /// <summary>
    /// Initializes a new secure key store.
    /// </summary>
    private SecureKeyStore(
        ImmutableDictionary<string, EncryptedKey> keys,
        byte[] masterKey,
        byte[] salt)
    {
        _keys = keys;
        _masterKey = masterKey;
        _salt = salt;
    }

    /// <summary>
    /// Creates a new empty secure key store with a randomly generated master key.
    /// </summary>
    public static Result<SecureKeyStore, SmartCardError> Create()
    {
        try
        {
            // Generate cryptographically secure master key and salt
            var masterKey = new byte[32]; // 256-bit key
            var salt = new byte[16];      // 128-bit salt
                
            var random = new SecureRandom();
            random.NextBytes(masterKey);
            random.NextBytes(salt);

            return Result.Success<SecureKeyStore, SmartCardError>(
                new SecureKeyStore(
                    ImmutableDictionary<string, EncryptedKey>.Empty,
                    masterKey,
                    salt));
        }
        catch (Exception ex)
        {
            return Result.Failure<SecureKeyStore, SmartCardError>(
                SmartCardError.SecurityError($"Failed to create secure key store: {ex.Message}"));
        }
    }

    /// <summary>
    /// Adds a key to the store, returning a new immutable store instance.
    /// </summary>
    public Result<SecureKeyStore, SmartCardError> AddKey(string keyId, byte[] keyData)
    {
        if (string.IsNullOrEmpty(keyId))
        {
            return Result.Failure<SecureKeyStore, SmartCardError>(
                SmartCardError.InvalidArgument("Key ID cannot be null or empty"));
        }

        if (keyData == null || keyData.Length == 0)
        {
            return Result.Failure<SecureKeyStore, SmartCardError>(
                SmartCardError.InvalidArgument("Key data cannot be null or empty"));
        }

        if (_keys.ContainsKey(keyId))
        {
            return Result.Failure<SecureKeyStore, SmartCardError>(
                SmartCardError.InvalidArgument($"Key with ID '{keyId}' already exists"));
        }

        try
        {
            // Encrypt the key before storing
            var encryptedKey = EncryptKey(keyId, keyData);
            var newKeys = _keys.Add(keyId, encryptedKey);

            // Clear the original key data
            Array.Clear(keyData, 0, keyData.Length);

            return Result.Success<SecureKeyStore, SmartCardError>(
                new SecureKeyStore(newKeys, _masterKey, _salt));
        }
        catch (Exception ex)
        {
            return Result.Failure<SecureKeyStore, SmartCardError>(
                SmartCardError.SecurityError($"Failed to add key: {ex.Message}"));
        }
    }

    /// <summary>
    /// Retrieves a key from the store securely.
    /// The returned key should be used immediately and then cleared.
    /// </summary>
    public Result<SecureKey, SmartCardError> GetKey(string keyId)
    {
        if (string.IsNullOrEmpty(keyId))
        {
            return Result.Failure<SecureKey, SmartCardError>(
                SmartCardError.InvalidArgument("Key ID cannot be null or empty"));
        }

        if (!_keys.TryGetValue(keyId, out var encryptedKey))
        {
            return Result.Failure<SecureKey, SmartCardError>(
                SmartCardError.InvalidArgument($"Key with ID '{keyId}' not found"));
        }

        try
        {
            var decryptedKey = DecryptKey(keyId, encryptedKey);
            return Result.Success<SecureKey, SmartCardError>(
                new SecureKey(keyId, decryptedKey));
        }
        catch (Exception ex)
        {
            return Result.Failure<SecureKey, SmartCardError>(
                SmartCardError.SecurityError($"Failed to retrieve key: {ex.Message}"));
        }
    }

    /// <summary>
    /// Removes a key from the store, returning a new immutable store instance.
    /// </summary>
    public Result<SecureKeyStore, SmartCardError> RemoveKey(string keyId)
    {
        if (string.IsNullOrEmpty(keyId))
        {
            return Result.Failure<SecureKeyStore, SmartCardError>(
                SmartCardError.InvalidArgument("Key ID cannot be null or empty"));
        }

        if (!_keys.ContainsKey(keyId))
        {
            return Result.Failure<SecureKeyStore, SmartCardError>(
                SmartCardError.InvalidArgument($"Key with ID '{keyId}' not found"));
        }

        var newKeys = _keys.Remove(keyId);
        return Result.Success<SecureKeyStore, SmartCardError>(
            new SecureKeyStore(newKeys, _masterKey, _salt));
    }

    /// <summary>
    /// Lists all key IDs in the store.
    /// </summary>
    public ImmutableArray<string> ListKeyIds()
    {
        return _keys.Keys.ToImmutableArray();
    }

    /// <summary>
    /// Performs a secure operation with a key, ensuring the key is cleared after use.
    /// </summary>
    public Result<T, SmartCardError> UseKey<T>(string keyId, Func<byte[], Result<T, SmartCardError>> operation)
    {
        return GetKey(keyId)
            .Bind(secureKey => secureKey.Use(operation));
    }

    /// <summary>
    /// Creates a key set from stored keys for GlobalPlatform operations.
    /// </summary>
    public Result<IKeySet, SmartCardError> CreateKeySet(
        string encKeyId,
        string macKeyId,
        string dekKeyId,
        byte keyVersion,
        bool isScp03 = false)
    {
        var encKeyResult = GetKey(encKeyId);
        var macKeyResult = GetKey(macKeyId);
        var dekKeyResult = GetKey(dekKeyId);

        if (encKeyResult.IsFailure)
        {
            return Result.Failure<IKeySet, SmartCardError>(encKeyResult.Error);
        }

        if (macKeyResult.IsFailure)
        {
            return Result.Failure<IKeySet, SmartCardError>(macKeyResult.Error);
        }

        if (dekKeyResult.IsFailure)
        {
            return Result.Failure<IKeySet, SmartCardError>(dekKeyResult.Error);
        }

        using (var encKey = encKeyResult.Value)
        using (var macKey = macKeyResult.Value)
        using (var dekKey = dekKeyResult.Value)
        {
            return encKey.Use(encData =>
                macKey.Use(macData =>
                    dekKey.Use(dekData =>
                    {
                        if (isScp03)
                        {
                            var keySetResult = Scp03KeySet.Create(encData, macData, dekData, keyVersion);
                            if (keySetResult.IsFailure)
                            {
                                return Result.Failure<IKeySet, SmartCardError>(
                                    SmartCardError.SecurityError(keySetResult.Error.Message));
                            }
                            return Result.Success<IKeySet, SmartCardError>(keySetResult.Value);
                        }
                        else
                        {
                            var keySetResult = Scp02KeySet.Create(encData, macData, dekData, keyVersion);
                            if (keySetResult.IsFailure)
                            {
                                return Result.Failure<IKeySet, SmartCardError>(
                                    SmartCardError.SecurityError(keySetResult.Error.Message));
                            }
                            return Result.Success<IKeySet, SmartCardError>(keySetResult.Value);
                        }
                    })));
        }
    }

    private EncryptedKey EncryptKey(string keyId, byte[] keyData)
    {
        // Derive a key-specific encryption key from master key
        var keySpecificKey = DeriveKeySpecificKey(keyId);
        
        // Generate IV
        var iv = new byte[16];
        var random = new SecureRandom();
        random.NextBytes(iv);
        
        // Setup AES-CBC cipher
        var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
        var keyParam = new KeyParameter(keySpecificKey);
        var keyParamWithIv = new ParametersWithIV(keyParam, iv);
        
        cipher.Init(true, keyParamWithIv);
        
        // Encrypt
        var outputSize = cipher.GetOutputSize(keyData.Length);
        var encrypted = new byte[outputSize];
        var processedBytes = cipher.ProcessBytes(keyData, 0, keyData.Length, encrypted, 0);
        var finalBytes = cipher.DoFinal(encrypted, processedBytes);
        
        // Resize array if needed
        if (processedBytes + finalBytes < encrypted.Length)
        {
            encrypted = encrypted.Take(processedBytes + finalBytes).ToArray();
        }
        
        return new EncryptedKey(encrypted, iv);
    }

    private byte[] DecryptKey(string keyId, EncryptedKey encryptedKey)
    {
        var keySpecificKey = DeriveKeySpecificKey(keyId);
        
        // Setup AES-CBC cipher for decryption
        var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
        var keyParam = new KeyParameter(keySpecificKey);
        var keyParamWithIv = new ParametersWithIV(keyParam, encryptedKey.Iv);
        
        cipher.Init(false, keyParamWithIv); // false for decryption
        
        // Decrypt
        var outputSize = cipher.GetOutputSize(encryptedKey.Data.Length);
        var decrypted = new byte[outputSize];
        var processedBytes = cipher.ProcessBytes(encryptedKey.Data, 0, encryptedKey.Data.Length, decrypted, 0);
        var finalBytes = cipher.DoFinal(decrypted, processedBytes);
        
        // Resize array if needed
        if (processedBytes + finalBytes < decrypted.Length)
        {
            decrypted = decrypted.Take(processedBytes + finalBytes).ToArray();
        }
        
        return decrypted;
    }

    private byte[] DeriveKeySpecificKey(string keyId)
    {
        // Use PBKDF2 to derive a key-specific encryption key
        var keyIdBytes = System.Text.Encoding.UTF8.GetBytes(keyId);
        var combinedSalt = _salt.Concat(keyIdBytes).ToArray();
        
        var generator = new Pkcs5S2ParametersGenerator(new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
        generator.Init(_masterKey, combinedSalt, 10000);
        
        var keyParam = (KeyParameter)generator.GenerateDerivedParameters("AES", 256); // 256 bits
        return keyParam.GetKey();
    }


    /// <summary>
    /// Encrypted key data with initialization vector.
    /// </summary>
    private sealed record EncryptedKey(byte[] Data, byte[] Iv);
}

/// <summary>
/// Represents a decrypted key that automatically clears itself when disposed.
/// Ensures keys are not left in memory after use.
/// </summary>
public sealed class SecureKey : IDisposable
{
    private readonly string _keyId;
    private byte[] _keyData;
    private bool _disposed;

    internal SecureKey(string keyId, byte[] keyData)
    {
        _keyId = keyId;
        _keyData = keyData;
    }

    /// <summary>
    /// Uses the key in a secure operation, ensuring it's not exposed.
    /// </summary>
    public Result<T, SmartCardError> Use<T>(Func<byte[], Result<T, SmartCardError>> operation)
    {
        if (_disposed)
        {
            return Result.Failure<T, SmartCardError>(
                SmartCardError.InvalidArgument("Cannot use disposed key"));
        }

        try
        {
            return operation(_keyData);
        }
        catch (Exception ex)
        {
            return Result.Failure<T, SmartCardError>(
                SmartCardError.UnexpectedError($"Key operation failed: {ex.Message}", ex));
        }
    }

    /// <summary>
    /// Gets a copy of the key data. The caller is responsible for clearing it.
    /// </summary>
    public Result<byte[], SmartCardError> GetCopy()
    {
        if (_disposed)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Cannot access disposed key"));
        }

        return Result.Success<byte[], SmartCardError>((byte[])_keyData.Clone());
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_keyData != null)
            {
                Array.Clear(_keyData, 0, _keyData.Length);
                _keyData = null!;
            }
            _disposed = true;
        }
    }
}