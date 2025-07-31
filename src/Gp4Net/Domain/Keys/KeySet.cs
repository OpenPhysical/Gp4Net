// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Domain.Keys
{
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

        private bool _disposed = false;

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
            CryptographicOperations.ZeroMemory(EncKey);
            CryptographicOperations.ZeroMemory(MacKey);
            CryptographicOperations.ZeroMemory(DekKey);
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
        /// Private constructor for successful creation.
        /// </summary>
        private Scp02KeySet(byte[] encKey, byte[] macKey, byte[] dekKey, byte keyVersion = 0, byte keyId = 0)
            : base(keyVersion, keyId, encKey, macKey, dekKey)
        {
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
        public static Result<Scp02KeySet, SmartCardError> Create(byte[] encKey, byte[] macKey, byte[] dekKey, byte keyVersion = 0, byte keyId = 0)
        {
            return ValidateKey(encKey, nameof(encKey))
                .Bind(_ => ValidateKey(macKey, nameof(macKey)))
                .Bind(_ => ValidateKey(dekKey, nameof(dekKey)))
                .Map(_ => new Scp02KeySet(encKey, macKey, dekKey, keyVersion, keyId));
        }

        private static Result<bool, SmartCardError> ValidateKey(byte[] key, string paramName)
        {
            if (key is null)
                return SmartCardError.InvalidArgument($"Key {paramName} cannot be null");
            
            if (key.Length != 16 && key.Length != 24)
                return SmartCardError.InvalidArgument($"3DES key {paramName} must be 16 or 24 bytes, got {key.Length} bytes");
            
            return true;
        }
    }

    /// <summary>
    /// Represents a set of SCP03 static keys (AES).
    /// </summary>
    public class Scp03KeySet : KeySet
    {
        /// <summary>
        /// Private constructor for successful creation.
        /// </summary>
        private Scp03KeySet(byte[] encKey, byte[] macKey, byte[] dekKey, byte keyVersion = 0, byte keyId = 0)
            : base(keyVersion, keyId, encKey, macKey, dekKey)
        {
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
        public static Result<Scp03KeySet, SmartCardError> Create(byte[] encKey, byte[] macKey, byte[] dekKey, byte keyVersion = 0, byte keyId = 0)
        {
            return ValidateKey(encKey, nameof(encKey))
                .Bind(_ => ValidateKey(macKey, nameof(macKey)))
                .Bind(_ => ValidateKey(dekKey, nameof(dekKey)))
                .Bind(_ => ValidateKeyLengthsMatch(encKey, macKey, dekKey))
                .Map(_ => new Scp03KeySet(encKey, macKey, dekKey, keyVersion, keyId));
        }

        private static Result<bool, SmartCardError> ValidateKey(byte[] key, string paramName)
        {
            if (key is null)
                return SmartCardError.InvalidArgument($"Key {paramName} cannot be null");
            
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                return SmartCardError.InvalidArgument($"AES key {paramName} must be 16, 24, or 32 bytes, got {key.Length} bytes");
            
            return true;
        }

        private static Result<bool, SmartCardError> ValidateKeyLengthsMatch(byte[] encKey, byte[] macKey, byte[] dekKey)
        {
            if (encKey.Length != macKey.Length || macKey.Length != dekKey.Length)
                return SmartCardError.InvalidArgument($"All AES keys must have the same length. Got ENC: {encKey.Length}, MAC: {macKey.Length}, DEK: {dekKey.Length} bytes");
            
            return true;
        }
    }
}
