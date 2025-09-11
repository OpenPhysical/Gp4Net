using System;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Domain.Keys;

/// <summary>
/// Immutable configuration for secure key management.
/// Enforces security policies and best practices for key handling.
/// </summary>
public sealed record KeyManagementConfiguration
{
    /// <summary>
    /// Default secure configuration with recommended settings.
    /// </summary>
    public static KeyManagementConfiguration Default { get; } =
        new()
        {
            RequireKeyRotation = true,
            KeyRotationIntervalDays = 90,
            MaxKeyUsageCount = 10000,
            RequireSecureStorage = true,
            AllowKeyExport = false,
            MinimumKeyLength = 16, // 128 bits
            RequireKeyDerivation = true,
            ClearKeysAfterUse = true,
            KeyLifetimeMinutes = 30,
            EnableKeyAuditing = true,
        };

    /// <summary>
    /// Gets whether key rotation is required.
    /// </summary>
    public bool RequireKeyRotation { get; init; }

    /// <summary>
    /// Gets the key rotation interval in days.
    /// </summary>
    public int KeyRotationIntervalDays { get; init; }

    /// <summary>
    /// Gets the maximum number of times a key can be used.
    /// </summary>
    public int MaxKeyUsageCount { get; init; }

    /// <summary>
    /// Gets whether secure storage is required for keys.
    /// </summary>
    public bool RequireSecureStorage { get; init; }

    /// <summary>
    /// Gets whether keys can be exported from the system.
    /// </summary>
    public bool AllowKeyExport { get; init; }

    /// <summary>
    /// Gets the minimum key length in bytes.
    /// </summary>
    public int MinimumKeyLength { get; init; }

    /// <summary>
    /// Gets whether key derivation is required for session keys.
    /// </summary>
    public bool RequireKeyDerivation { get; init; }

    /// <summary>
    /// Gets whether keys should be cleared from memory after use.
    /// </summary>
    public bool ClearKeysAfterUse { get; init; }

    /// <summary>
    /// Gets the maximum lifetime of a key in memory (minutes).
    /// </summary>
    public int KeyLifetimeMinutes { get; init; }

    /// <summary>
    /// Gets whether key usage should be audited.
    /// </summary>
    public bool EnableKeyAuditing { get; init; }

    /// <summary>
    /// Validates a key against the configuration policies.
    /// </summary>
    public Result<bool, string> ValidateKey(byte[] key, string keyType)
    {
        if (key == null || key.Length == 0)
        {
            return Result.Failure<bool, string>("Key cannot be null or empty");
        }

        if (key.Length < MinimumKeyLength)
        {
            return Result.Failure<bool, string>(
                $"{keyType} key length ({key.Length} bytes) is below minimum ({MinimumKeyLength} bytes)"
            );
        }

        return Result.Success<bool, string>(true);
    }

    /// <summary>
    /// Creates a development configuration with relaxed security.
    /// Should only be used for testing and development.
    /// </summary>
    public static KeyManagementConfiguration Development { get; } =
        new()
        {
            RequireKeyRotation = false,
            KeyRotationIntervalDays = 365,
            MaxKeyUsageCount = int.MaxValue,
            RequireSecureStorage = false,
            AllowKeyExport = true,
            MinimumKeyLength = 8,
            RequireKeyDerivation = false,
            ClearKeysAfterUse = true,
            KeyLifetimeMinutes = 60,
            EnableKeyAuditing = false,
        };
}

/// <summary>
/// Manages key lifecycle with security policies.
/// </summary>
public sealed class KeyLifecycleManager
{
    private readonly KeyManagementConfiguration _config;
    private readonly SecureKeyStore _keyStore;
    private readonly ImmutableDictionary<string, KeyMetadata> _metadata;

    private KeyLifecycleManager(
        KeyManagementConfiguration config,
        SecureKeyStore keyStore,
        ImmutableDictionary<string, KeyMetadata> metadata
    )
    {
        _config = config;
        _keyStore = keyStore;
        _metadata = metadata;
    }

    /// <summary>
    /// Creates a new key lifecycle manager.
    /// </summary>
    public static Result<KeyLifecycleManager, SmartCardError> Create(
        KeyManagementConfiguration config = null
    )
    {
        var configuration = config ?? KeyManagementConfiguration.Default;

        return SecureKeyStore
            .Create()
            .Map(store => new KeyLifecycleManager(
                configuration,
                store,
                ImmutableDictionary<string, KeyMetadata>.Empty
            ));
    }

    /// <summary>
    /// Registers a new key with lifecycle management.
    /// </summary>
    public Result<KeyLifecycleManager, SmartCardError> RegisterKey(
        string keyId,
        byte[] keyData,
        KeyPurpose purpose
    )
    {
        // Validate key
        var validationResult = _config.ValidateKey(keyData, purpose.ToString());
        if (validationResult.IsFailure)
        {
            return Result.Failure<KeyLifecycleManager, SmartCardError>(
                SmartCardError.SecurityError(validationResult.Error)
            );
        }

        // Add to secure store
        return _keyStore
            .AddKey(keyId, keyData)
            .Map(newStore =>
            {
                var metadata = new KeyMetadata(
                    keyId,
                    purpose,
                    DateTime.UtcNow,
                    0,
                    DateTime.UtcNow
                );

                var newMetadata = _metadata.Add(
                    keyId,
                    metadata
                );
                return new KeyLifecycleManager(_config, newStore, newMetadata);
            });
    }

    /// <summary>
    /// Uses a key with lifecycle tracking.
    /// </summary>
    public Result<(T Result, KeyLifecycleManager Manager), SmartCardError> UseKey<T>(
        string keyId,
        Func<byte[], Result<T, SmartCardError>> operation
    )
    {
        if (!_metadata.TryGetValue(keyId, out var metadata))
        {
            return Result.Failure<(T, KeyLifecycleManager), SmartCardError>(
                SmartCardError.InvalidArgument($"Key '{keyId}' not found")
            );
        }

        // Check if key needs rotation
        if (_config.RequireKeyRotation && IsRotationRequired(metadata))
        {
            return Result.Failure<(T, KeyLifecycleManager), SmartCardError>(
                SmartCardError.SecurityError($"Key '{keyId}' requires rotation")
            );
        }

        // Check usage count
        if (metadata.UsageCount >= _config.MaxKeyUsageCount)
        {
            return Result.Failure<(T, KeyLifecycleManager), SmartCardError>(
                SmartCardError.SecurityError($"Key '{keyId}' has exceeded maximum usage count")
            );
        }

        // Use the key
        return _keyStore
            .UseKey(keyId, operation)
            .Map(result =>
            {
                // Update metadata
                var updatedMetadata = metadata with
                {
                    UsageCount = metadata.UsageCount + 1,
                    LastUsedUtc = DateTime.UtcNow,
                };

                var newMetadata = _metadata.SetItem(
                    keyId,
                    updatedMetadata
                );
                var newManager = new KeyLifecycleManager(
                    _config,
                    _keyStore,
                    newMetadata
                );

                return (result, newManager);
            });
    }

    /// <summary>
    /// Checks if a key exists and is valid.
    /// </summary>
    public bool IsKeyValid(string keyId)
    {
        if (!_metadata.TryGetValue(keyId, out var metadata))
        {
            return false;
        }

        if (_config.RequireKeyRotation && IsRotationRequired(metadata))
        {
            return false;
        }

        if (metadata.UsageCount >= _config.MaxKeyUsageCount)
        {
            return false;
        }

        var keyAge = DateTime.UtcNow - metadata.CreatedUtc;
        if (keyAge.TotalMinutes > _config.KeyLifetimeMinutes)
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Gets audit information for a key.
    /// </summary>
    public Maybe<KeyAuditInfo> GetKeyAuditInfo(string keyId)
    {
        return _metadata.TryGetValue(keyId, out var metadata)
            ? Maybe<KeyAuditInfo>.From(
                new KeyAuditInfo(
                    metadata.KeyId,
                    metadata.Purpose,
                    metadata.CreatedUtc,
                    metadata.LastUsedUtc,
                    metadata.UsageCount,
                    IsRotationRequired(metadata)
                )
            )
            : Maybe<KeyAuditInfo>.None;
    }

    private bool IsRotationRequired(KeyMetadata metadata)
    {
        var age = DateTime.UtcNow - metadata.CreatedUtc;
        return age.TotalDays >= _config.KeyRotationIntervalDays;
    }

    /// <summary>
    /// Key metadata for lifecycle tracking.
    /// </summary>
    private sealed record KeyMetadata(
        string KeyId,
        KeyPurpose Purpose,
        DateTime CreatedUtc,
        int UsageCount,
        DateTime LastUsedUtc
    );
}

/// <summary>
/// Defines the purpose of a cryptographic key.
/// </summary>
public enum KeyPurpose
{
    /// <summary>
    /// Master key for key derivation.
    /// </summary>
    Master,

    /// <summary>
    /// Session key for secure channel.
    /// </summary>
    Session,

    /// <summary>
    /// Key encryption key.
    /// </summary>
    KeyEncryption,

    /// <summary>
    /// Data encryption key.
    /// </summary>
    DataEncryption,

    /// <summary>
    /// Message authentication key.
    /// </summary>
    Authentication,

    /// <summary>
    /// Key for secure storage.
    /// </summary>
    Storage,
}

/// <summary>
/// Audit information for a key.
/// </summary>
public sealed record KeyAuditInfo(
    string KeyId,
    KeyPurpose Purpose,
    DateTime CreatedUtc,
    DateTime LastUsedUtc,
    int UsageCount,
    bool RequiresRotation
);
