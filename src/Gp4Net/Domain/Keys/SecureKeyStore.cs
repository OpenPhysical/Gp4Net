using System;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Shared;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Gp4Net.Domain.Keys;

/// <summary>
/// Immutable, thread-safe secure key store that manages cryptographic keys
///. Keys are encrypted in memory
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
        byte[] salt
    )
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
        // Generate cryptographically secure master key and salt using CryptoOperations.Rng
        return CryptoOperations
            .Rng.GenerateBytes(32) // 256-bit key
            .Bind(masterKey =>
                CryptoOperations
                    .Rng.GenerateBytes(16) // 128-bit salt
                    .Map(salt => new SecureKeyStore(
                        ImmutableDictionary<string, EncryptedKey>.Empty,
                        masterKey,
                        salt
                    ))
            );
    }

    /// <summary>
    /// Adds a key to the store, returning a new immutable store instance.
    /// </summary>
    public Result<SecureKeyStore, SmartCardError> AddKey(string keyId, byte[] keyData)
    {
        return ValidateKeyId(keyId)
            .Bind(_ => ValidateKeyData(keyData))
            .Ensure(
                _ => !_keys.ContainsKey(keyId),
                SmartCardError.InvalidArgument($"Key with ID '{keyId}' already exists")
            )
            .Bind(_ => EncryptAndStore(keyId, keyData));
    }

    private static Result<string, SmartCardError> ValidateKeyId(string keyId) =>
        Maybe<string>
            .From(keyId)
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .ToResult(Errors.EmptyArgument("Key ID"));

    private static Result<byte[], SmartCardError> ValidateKeyData(byte[] keyData) =>
        Maybe<byte[]>
            .From(keyData)
            .Where(data => data.Length > 0)
            .ToResult(Errors.EmptyArgument("Key data"));

    private Result<SecureKeyStore, SmartCardError> EncryptAndStore(string keyId, byte[] keyData) =>
        Result.Try(
            () =>
            {
                var encryptedKey = EncryptKey(keyId, keyData);
                var keysBuilder = _keys.ToBuilder();
                keysBuilder.Add(keyId, encryptedKey);
                Array.Clear(keyData, 0, keyData.Length);
                return new SecureKeyStore(keysBuilder.ToImmutable(), _masterKey, _salt);
            },
            ex => SmartCardError.SecurityError($"Failed to add key: {ex.Message}")
        );

    /// <summary>
    /// Retrieves a key from the store securely.
    /// The returned key should be used immediately and then cleared.
    /// </summary>
    public Result<SecureKey, SmartCardError> GetKey(string keyId) =>
        ValidateKeyId(keyId)
            .Bind(id =>
                FindEncryptedKey(id).Bind(encryptedKey => DecryptKeySecurely(id, encryptedKey))
            );

    private Result<EncryptedKey, SmartCardError> FindEncryptedKey(string keyId) =>
        _keys.ContainsKey(keyId)
            ? Result.Success<EncryptedKey, SmartCardError>(_keys[keyId])
            : Result.Failure<EncryptedKey, SmartCardError>(
                SmartCardError.InvalidArgument($"Key with ID '{keyId}' not found")
            );

    private Result<SecureKey, SmartCardError> DecryptKeySecurely(
        string keyId,
        EncryptedKey encryptedKey
    ) =>
        Result.Try(
            () => new SecureKey(keyId, DecryptKey(keyId, encryptedKey)),
            ex => SmartCardError.SecurityError($"Failed to retrieve key: {ex.Message}")
        );

    /// <summary>
    /// Removes a key from the store, returning a new immutable store instance.
    /// </summary>
    public Result<SecureKeyStore, SmartCardError> RemoveKey(string keyId) =>
        ValidateKeyId(keyId)
            .Ensure(
                id => _keys.ContainsKey(id),
                SmartCardError.InvalidArgument($"Key with ID '{keyId}' not found")
            )
            .Map(id => new SecureKeyStore(_keys.Remove(id), _masterKey, _salt));

    /// <summary>
    /// Lists all key IDs in the store.
    /// </summary>
    public ImmutableArray<string> ListKeyIds()
    {
        return [.. _keys.Keys];
    }

    /// <summary>
    /// Performs a secure operation with a key, ensuring the key is cleared after use.
    /// </summary>
    public Result<T, SmartCardError> UseKey<T>(
        string keyId,
        Func<byte[], Result<T, SmartCardError>> operation
    )
    {
        return GetKey(keyId).Bind(secureKey => secureKey.Use(operation));
    }

    /// <summary>
    /// Creates a key set from stored keys for GlobalPlatform operations.
    /// </summary>
    public Result<IKeySet, SmartCardError> CreateKeySet(
        string encKeyId,
        string macKeyId,
        string dekKeyId,
        byte keyVersion,
        bool isScp03 = false
    )
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
                            var keySetResult = Scp03KeySet.Create(
                                encData,
                                macData,
                                dekData,
                                keyVersion
                            );
                            if (keySetResult.IsFailure)
                            {
                                return Result.Failure<IKeySet, SmartCardError>(
                                    SmartCardError.SecurityError(keySetResult.Error.Message)
                                );
                            }
                            return Result.Success<IKeySet, SmartCardError>(keySetResult.Value);
                        }
                        else
                        {
                            var keySetResult = Scp02KeySet.Create(
                                encData,
                                macData,
                                dekData,
                                keyVersion
                            );
                            if (keySetResult.IsFailure)
                            {
                                return Result.Failure<IKeySet, SmartCardError>(
                                    SmartCardError.SecurityError(keySetResult.Error.Message)
                                );
                            }
                            return Result.Success<IKeySet, SmartCardError>(keySetResult.Value);
                        }
                    })
                )
            );
        }
    }

    private EncryptedKey EncryptKey(string keyId, byte[] keyData)
    {
        // Derive a key-specific encryption key from master key
        byte[] keySpecificKey = DeriveKeySpecificKey(keyId);

        // Generate IV
        byte[] iv = new byte[16];
        var random = new SecureRandom();
        random.NextBytes(iv);

        // Setup AES-CBC cipher
        var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
        var keyParam = new KeyParameter(keySpecificKey);
        var keyParamWithIv = new ParametersWithIV(keyParam, iv);

        cipher.Init(true, keyParamWithIv);

        // Encrypt
        int outputSize = cipher.GetOutputSize(keyData.Length);
        byte[] encrypted = new byte[outputSize];
        int processedBytes = cipher.ProcessBytes(keyData, 0, keyData.Length, encrypted, 0);
        int finalBytes = cipher.DoFinal(encrypted, processedBytes);

        // Resize array if needed
        if (processedBytes + finalBytes < encrypted.Length)
        {
            encrypted = [.. encrypted.Take(processedBytes + finalBytes)];
        }

        return new EncryptedKey(encrypted, iv);
    }

    private byte[] DecryptKey(string keyId, EncryptedKey encryptedKey)
    {
        byte[] keySpecificKey = DeriveKeySpecificKey(keyId);

        // Setup AES-CBC cipher for decryption
        var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
        var keyParam = new KeyParameter(keySpecificKey);
        var keyParamWithIv = new ParametersWithIV(keyParam, encryptedKey.Iv);

        cipher.Init(false, keyParamWithIv); // false for decryption

        // Decrypt
        int outputSize = cipher.GetOutputSize(encryptedKey.Data.Length);
        byte[] decrypted = new byte[outputSize];
        int processedBytes = cipher.ProcessBytes(
            encryptedKey.Data,
            0,
            encryptedKey.Data.Length,
            decrypted,
            0
        );
        int finalBytes = cipher.DoFinal(decrypted, processedBytes);

        // Resize array if needed
        if (processedBytes + finalBytes < decrypted.Length)
        {
            decrypted = [.. decrypted.Take(processedBytes + finalBytes)];
        }

        return decrypted;
    }

    private byte[] DeriveKeySpecificKey(string keyId)
    {
        // Use PBKDF2 to derive a key-specific encryption key
        byte[] keyIdBytes = Encoding.UTF8.GetBytes(keyId);
        byte[] combinedSalt = [.. _salt, .. keyIdBytes];

        var generator = new Pkcs5S2ParametersGenerator(new Sha256Digest());
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
                SmartCardError.InvalidArgument("Cannot use disposed key")
            );
        }

        return Result
            .Try(
                () => operation(_keyData),
                ex => SmartCardError.UnexpectedError($"Key operation failed: {ex.Message}", ex)
            )
            .Bind(result => result);
    }

    /// <summary>
    /// Gets a copy of the key data. The caller is responsible for clearing it.
    /// </summary>
    public Result<byte[], SmartCardError> GetCopy()
    {
        if (_disposed)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Cannot access disposed key")
            );
        }

        return Result.Success<byte[], SmartCardError>((byte[])_keyData.Clone());
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            Array.Clear(_keyData, 0, _keyData.Length);
            _keyData = Array.Empty<byte>();
            _disposed = true;
        }
    }
}
