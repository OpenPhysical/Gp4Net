// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

namespace Gp4Net.Domain.Keys
{
    using System;
    using CSharpFunctionalExtensions;
    using Gp4Net.Core;

    /// <summary>
    /// Provides secure storage for a key set with automatic memory cleanup.
    /// </summary>
    public sealed class SecureKeySet : IDisposable
    {
        private readonly SecureKeyStorage encKey;
        private readonly SecureKeyStorage macKey;
        private readonly SecureKeyStorage dekKey;
        private bool isDisposed;

        /// <summary>
        /// Gets the key version number.
        /// </summary>
        public byte KeyVersion { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecureKeySet"/> class.
        /// </summary>
        /// <param name="keyVersion">The key version number.</param>
        /// <param name="encKey">The encryption key.</param>
        /// <param name="macKey">The MAC key.</param>
        /// <param name="dekKey">The data encryption key.</param>
        public SecureKeySet(byte keyVersion, byte[] encKey, byte[] macKey, byte[] dekKey)
        {
            this.KeyVersion = keyVersion;
            this.encKey = new SecureKeyStorage(encKey);
            this.macKey = new SecureKeyStorage(macKey);
            this.dekKey = new SecureKeyStorage(dekKey);
        }

        /// <summary>
        /// Creates a secure key set from an existing key set.
        /// </summary>
        /// <param name="keySet">The key set to secure.</param>
        /// <returns>A new secure key set.</returns>
        public static SecureKeySet FromKeySet(IKeySet keySet)
        {
            ArgumentNullException.ThrowIfNull(keySet);

            return new SecureKeySet(keySet.KeyVersion, keySet.EncKey, keySet.MacKey, keySet.DekKey);
        }

        /// <summary>
        /// Uses the encryption key.
        /// </summary>
        /// <param name="action">The action to execute with the key.</param>
        public void UseEncKey(Action<byte[]> action)
        {
            this.ThrowIfDisposed();
            this.encKey.UseKey(action);
        }

        /// <summary>
        /// Uses the encryption key.
        /// </summary>
        /// <typeparam name="T">The return type.</typeparam>
        /// <param name="func">The function to execute with the key.</param>
        /// <returns>The result of the function.</returns>
        public T UseEncKey<T>(Func<byte[], T> func)
        {
            this.ThrowIfDisposed();
            return this.encKey.UseKey(func);
        }

        /// <summary>
        /// Uses the MAC key.
        /// </summary>
        /// <param name="action">The action to execute with the key.</param>
        public void UseMacKey(Action<byte[]> action)
        {
            this.ThrowIfDisposed();
            this.macKey.UseKey(action);
        }

        /// <summary>
        /// Uses the MAC key.
        /// </summary>
        /// <typeparam name="T">The return type.</typeparam>
        /// <param name="func">The function to execute with the key.</param>
        /// <returns>The result of the function.</returns>
        public T UseMacKey<T>(Func<byte[], T> func)
        {
            this.ThrowIfDisposed();
            return this.macKey.UseKey(func);
        }

        /// <summary>
        /// Uses the data encryption key.
        /// </summary>
        /// <param name="action">The action to execute with the key.</param>
        public void UseDekKey(Action<byte[]> action)
        {
            this.ThrowIfDisposed();
            this.dekKey.UseKey(action);
        }

        /// <summary>
        /// Uses the data encryption key.
        /// </summary>
        /// <typeparam name="T">The return type.</typeparam>
        /// <param name="func">The function to execute with the key.</param>
        /// <returns>The result of the function.</returns>
        public T UseDekKey<T>(Func<byte[], T> func)
        {
            this.ThrowIfDisposed();
            return this.dekKey.UseKey(func);
        }

        /// <summary>
        /// Creates a legacy KeySet object. The caller is responsible for clearing the keys.
        /// </summary>
        /// <returns>A KeySet object with copies of the keys.</returns>
        public Scp02KeySet ToScp02KeySet()
        {
            this.ThrowIfDisposed();
            return Scp02KeySet.Create(
                this.encKey.GetKeyCopy(),
                this.macKey.GetKeyCopy(),
                this.dekKey.GetKeyCopy(),
                this.KeyVersion
            ).Match(
                onSuccess: keySet => keySet,
                onFailure: error => throw new InvalidOperationException(error.Message));
        }

        /// <summary>
        /// Creates a legacy KeySet object. The caller is responsible for clearing the keys.
        /// </summary>
        /// <returns>A KeySet object with copies of the keys.</returns>
        public Scp03KeySet ToScp03KeySet()
        {
            this.ThrowIfDisposed();
            return Scp03KeySet.Create(
                this.encKey.GetKeyCopy(),
                this.macKey.GetKeyCopy(),
                this.dekKey.GetKeyCopy(),
                this.KeyVersion
            ).Match(
                onSuccess: keySet => keySet,
                onFailure: error => throw new InvalidOperationException(error.Message));
        }

        /// <summary>
        /// Disposes of the key set, clearing sensitive data from memory.
        /// </summary>
        public void Dispose()
        {
            if (!this.isDisposed)
            {
                this.encKey?.Dispose();
                this.macKey?.Dispose();
                this.dekKey?.Dispose();
                this.isDisposed = true;
            }
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(this.isDisposed, this);
        }
    }
}
