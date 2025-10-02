// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Org.BouncyCastle.Utilities;

namespace Gp4Net.Domain.Keys;

/// <summary>
/// Interface for a set of GlobalPlatform static keys.
/// </summary>
public interface IKeySet : IDisposable
{
    /// <summary>
    /// Gets the key version number.
    /// </summary>
    byte KeyVersion { get; }

    /// <summary>
    /// Gets the key identifier.
    /// </summary>
    byte KeyId { get; }

    /// <summary>
    /// Gets the encryption key (Key-ENC).
    /// </summary>
    byte[] EncKey { get; }

    /// <summary>
    /// Gets the MAC key (Key-MAC).
    /// </summary>
    byte[] MacKey { get; }

    /// <summary>
    /// Gets the data encryption key (Key-DEK).
    /// </summary>
    byte[] DekKey { get; }
}

/// <summary>
/// Base class for a set of GlobalPlatform static keys.
/// </summary>
public abstract class KeySet : IKeySet
{
    /// <summary>
    /// Gets the key version number.
    /// </summary>
    public byte KeyVersion { get; }

    /// <summary>
    /// Gets the key identifier.
    /// </summary>
    public byte KeyId { get; }

    /// <summary>
    /// Gets the encryption key (Key-ENC).
    /// </summary>
    public byte[] EncKey { get; }

    /// <summary>
    /// Gets the MAC key (Key-MAC).
    /// </summary>
    public byte[] MacKey { get; }

    /// <summary>
    /// Gets the data encryption key (Key-DEK).
    /// </summary>
    public byte[] DekKey { get; }

    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the KeySet class.
    /// </summary>
    /// <param name="keyVersion">The key version number.</param>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="encKey">The encryption key.</param>
    /// <param name="macKey">The MAC key.</param>
    /// <param name="dekKey">The data encryption key.</param>
    protected KeySet(byte keyVersion, byte keyId, byte[] encKey, byte[] macKey, byte[] dekKey)
    {
        KeyVersion = keyVersion;
        KeyId = keyId;
        EncKey = encKey;
        MacKey = macKey;
        DekKey = dekKey;
    }

    /// <summary>
    /// Clears all cryptographic keys from memory.
    /// </summary>
    public virtual void Clear()
    {
        Arrays.Fill(EncKey, 0);
        Arrays.Fill(MacKey, 0);
        Arrays.Fill(DekKey, 0);
    }

    /// <summary>
    /// Disposes of the key set, clearing sensitive data from memory.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            Clear();
            _disposed = true;
        }
    }
}

/// <summary>
/// Represents a set of SCP02 static keys (3DES).
/// </summary>
public class Scp02KeySet : KeySet
{
    /// <summary>
    /// Gets the session encryption key (S-ENC) for cryptogram calculations.
    /// Required for type-safe cryptogram parameter validation.
    /// </summary>
    public byte[] SEnc { get; init; }

    /// <summary>
    /// Private constructor for successful creation.
    /// </summary>
    private Scp02KeySet(
        byte[] encKey,
        byte[] macKey,
        byte[] dekKey,
        byte keyVersion = 0,
        byte keyId = 0
    )
        : base(keyVersion, keyId, encKey, macKey, dekKey)
    {
        // Default to static ENC key if no session key provided
        SEnc = encKey;
    }

    /// <summary>
    /// Creates a new SCP02 key set with validation.
    /// </summary>
    /// <param name="encKey">The 3DES encryption key (16 or 24 bytes).</param>
    /// <param name="macKey">The 3DES MAC key (16 or 24 bytes).</param>
    /// <param name="dekKey">The 3DES data encryption key (16 or 24 bytes).</param>
    /// <param name="keyVersion">The key version number (default is 0).</param>
    /// <param name="keyId">The key identifier (default is 0).</param>
    /// <returns>A Result containing the KeySet or an error.</returns>
    public static Result<Scp02KeySet, SmartCardError> Create(
        byte[] encKey,
        byte[] macKey,
        byte[] dekKey,
        byte keyVersion = 0,
        byte keyId = 0
    )
    {
        var encKeyValidation = ValidateKey(encKey, nameof(encKey));
        if (encKeyValidation.IsFailure)
            return Result.Failure<Scp02KeySet, SmartCardError>(encKeyValidation.Error);

        var macKeyValidation = ValidateKey(macKey, nameof(macKey));
        if (macKeyValidation.IsFailure)
            return Result.Failure<Scp02KeySet, SmartCardError>(macKeyValidation.Error);

        var dekKeyValidation = ValidateKey(dekKey, nameof(dekKey));
        if (dekKeyValidation.IsFailure)
            return Result.Failure<Scp02KeySet, SmartCardError>(dekKeyValidation.Error);

        return Result.Success<Scp02KeySet, SmartCardError>(
            new Scp02KeySet(encKey, macKey, dekKey, keyVersion, keyId)
        );
    }

    private static Result<bool, SmartCardError> ValidateKey(byte[] key, string paramName)
    {
        if (key is null)
        {
            return SmartCardError.InvalidArgument($"Key {paramName} cannot be null");
        }

        if (key.Length != 16 && key.Length != 24)
        {
            return SmartCardError.InvalidArgument(
                $"3DES key {paramName} must be 16 or 24 bytes, got {key.Length} bytes"
            );
        }

        return true;
    }
}

/// <summary>
/// Represents a set of SCP03 static keys (AES).
/// </summary>
public class Scp03KeySet : KeySet
{
    /// <summary>
    /// Gets the session MAC key (S-MAC) for cryptogram calculations.
    /// Required for type-safe cryptogram parameter validation.
    /// </summary>
    public byte[] SMac { get; init; }

    /// <summary>
    /// Private constructor for successful creation.
    /// </summary>
    public Scp03KeySet(
        byte[] encKey,
        byte[] macKey,
        byte[] dekKey,
        byte keyVersion = 0,
        byte keyId = 0
    )
        : base(keyVersion, keyId, encKey, macKey, dekKey)
    {
        // Default to static MAC key if no session key provided
        SMac = macKey;
    }

    /// <summary>
    /// Creates a new SCP03 key set with validation.
    /// </summary>
    /// <param name="encKey">The AES encryption key (16, 24, or 32 bytes).</param>
    /// <param name="macKey">The AES MAC key (16, 24, or 32 bytes).</param>
    /// <param name="dekKey">The AES data encryption key (16, 24, or 32 bytes).</param>
    /// <param name="keyVersion">The key version number (default is 0).</param>
    /// <param name="keyId">The key identifier (default is 0).</param>
    /// <returns>A Result containing the KeySet or an error.</returns>
    public static Result<Scp03KeySet, SmartCardError> Create(
        byte[] encKey,
        byte[] macKey,
        byte[] dekKey,
        byte keyVersion = 0,
        byte keyId = 0
    )
    {
        var encKeyValidation = ValidateKey(encKey, nameof(encKey));
        if (encKeyValidation.IsFailure)
            return Result.Failure<Scp03KeySet, SmartCardError>(encKeyValidation.Error);

        var macKeyValidation = ValidateKey(macKey, nameof(macKey));
        if (macKeyValidation.IsFailure)
            return Result.Failure<Scp03KeySet, SmartCardError>(macKeyValidation.Error);

        var dekKeyValidation = ValidateKey(dekKey, nameof(dekKey));
        if (dekKeyValidation.IsFailure)
            return Result.Failure<Scp03KeySet, SmartCardError>(dekKeyValidation.Error);

        var lengthMatchValidation = ValidateKeyLengthsMatch(encKey, macKey, dekKey);
        if (lengthMatchValidation.IsFailure)
            return Result.Failure<Scp03KeySet, SmartCardError>(lengthMatchValidation.Error);

        return Result.Success<Scp03KeySet, SmartCardError>(
            new Scp03KeySet(encKey, macKey, dekKey, keyVersion, keyId)
        );
    }

    private static Result<bool, SmartCardError> ValidateKey(byte[] key, string paramName)
    {
        if (key is null)
        {
            return SmartCardError.InvalidArgument($"Key {paramName} cannot be null");
        }

        if (key.Length != 16 && key.Length != 24 && key.Length != 32)
        {
            return SmartCardError.InvalidArgument(
                $"AES key {paramName} must be 16, 24, or 32 bytes, got {key.Length} bytes"
            );
        }

        return true;
    }

    private static Result<bool, SmartCardError> ValidateKeyLengthsMatch(
        byte[] encKey,
        byte[] macKey,
        byte[] dekKey
    )
    {
        if (encKey.Length != macKey.Length || macKey.Length != dekKey.Length)
        {
            return SmartCardError.InvalidArgument(
                $"All AES keys must have the same length. Got ENC: {encKey.Length}, MAC: {macKey.Length}, DEK: {dekKey.Length} bytes"
            );
        }

        return true;
    }
}
