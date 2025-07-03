// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Security.Cryptography;

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
        /// <param name="encKey">The encryption key.</param>
        /// <param name="macKey">The MAC key.</param>
        /// <param name="dekKey">The data encryption key.</param>
        protected KeySet(byte keyVersion, byte[] encKey, byte[] macKey, byte[] dekKey)
        {
            KeyVersion = keyVersion;
            ArgumentNullException.ThrowIfNull(encKey);
            ArgumentNullException.ThrowIfNull(macKey);
            ArgumentNullException.ThrowIfNull(dekKey);
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
        /// Initializes a new instance of the Scp02KeySet class.
        /// </summary>
        /// <param name="encKey">The 3DES encryption key (16 or 24 bytes).</param>
        /// <param name="macKey">The 3DES MAC key (16 or 24 bytes).</param>
        /// <param name="dekKey">The 3DES data encryption key (16 or 24 bytes).</param>
        /// <param name="keyVersion">The key version number (default is 0).</param>
        public Scp02KeySet(byte[] encKey, byte[] macKey, byte[] dekKey, byte keyVersion = 0)
            : base(keyVersion, encKey, macKey, dekKey)
        {
            ValidateKey(encKey, nameof(encKey));
            ValidateKey(macKey, nameof(macKey));
            ValidateKey(dekKey, nameof(dekKey));
        }

        private static void ValidateKey(byte[] key, string paramName)
        {
            if (key.Length != 16 && key.Length != 24)
            {
                throw new ArgumentException("3DES key must be 16 or 24 bytes.", paramName);
            }
        }
    }

    /// <summary>
    /// Represents a set of SCP03 static keys (AES).
    /// </summary>
    public class Scp03KeySet : KeySet
    {
        /// <summary>
        /// Initializes a new instance of the Scp03KeySet class.
        /// </summary>
        /// <param name="encKey">The AES encryption key (16, 24, or 32 bytes).</param>
        /// <param name="macKey">The AES MAC key (16, 24, or 32 bytes).</param>
        /// <param name="dekKey">The AES data encryption key (16, 24, or 32 bytes).</param>
        /// <param name="keyVersion">The key version number (default is 0).</param>
        public Scp03KeySet(byte[] encKey, byte[] macKey, byte[] dekKey, byte keyVersion = 0)
            : base(keyVersion, encKey, macKey, dekKey)
        {
            ValidateKey(encKey, nameof(encKey));
            ValidateKey(macKey, nameof(macKey));
            ValidateKey(dekKey, nameof(dekKey));

            // All keys should have the same length
            if (encKey.Length != macKey.Length || macKey.Length != dekKey.Length)
            {
                throw new ArgumentException("All AES keys must have the same length.");
            }
        }

        private static void ValidateKey(byte[] key, string paramName)
        {
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            {
                throw new ArgumentException("AES key must be 16, 24, or 32 bytes.", paramName);
            }
        }
    }
}
