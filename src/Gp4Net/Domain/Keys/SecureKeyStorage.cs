// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

namespace Gp4Net.Domain.Keys
{
    using System;
    using System.Runtime.CompilerServices;
    using System.Security.Cryptography;

    /// <summary>
    /// Provides secure storage for cryptographic keys with automatic memory cleanup.
    /// </summary>
    public sealed class SecureKeyStorage : IDisposable
    {
        private byte[]? keyData;
        private bool isDisposed;

        /// <summary>
        /// Gets the length of the key in bytes.
        /// </summary>
        public int Length => this.keyData?.Length ?? 0;

        /// <summary>
        /// Initializes a new instance of the <see cref="SecureKeyStorage"/> class.
        /// </summary>
        /// <param name="key">The key data to store securely.</param>
        public SecureKeyStorage(byte[] key)
        {
            ArgumentNullException.ThrowIfNull(key);

            this.keyData = new byte[key.Length];
            Array.Copy(key, this.keyData, key.Length);
        }

        /// <summary>
        /// Creates a copy of the key data. The caller is responsible for clearing this copy.
        /// </summary>
        /// <returns>A copy of the key data.</returns>
        public byte[] GetKeyCopy()
        {
            this.ThrowIfDisposed();

            if (this.keyData == null)
            {
                throw new InvalidOperationException("Key data is not available.");
            }

            byte[] copy = new byte[this.keyData.Length];
            Array.Copy(this.keyData, copy, this.keyData.Length);
            return copy;
        }

        /// <summary>
        /// Executes an action with the key data. The key data should not be stored or leaked from the action.
        /// </summary>
        /// <param name="action">The action to execute with the key data.</param>
        public void UseKey(Action<byte[]> action)
        {
            this.ThrowIfDisposed();

            if (this.keyData == null)
            {
                throw new InvalidOperationException("Key data is not available.");
            }

            ArgumentNullException.ThrowIfNull(action);

            action(this.keyData);
        }

        /// <summary>
        /// Executes a function with the key data. The key data should not be stored or leaked from the function.
        /// </summary>
        /// <typeparam name="T">The return type of the function.</typeparam>
        /// <param name="func">The function to execute with the key data.</param>
        /// <returns>The result of the function.</returns>
        public T UseKey<T>(Func<byte[], T> func)
        {
            this.ThrowIfDisposed();

            if (this.keyData == null)
            {
                throw new InvalidOperationException("Key data is not available.");
            }

            ArgumentNullException.ThrowIfNull(func);

            return func(this.keyData);
        }

        /// <summary>
        /// Clears the key data from memory.
        /// </summary>
        public void Clear()
        {
            if (this.keyData != null)
            {
                CryptographicOperations.ZeroMemory(this.keyData);
                this.keyData = null;
            }
        }

        /// <summary>
        /// Disposes of the key storage, clearing sensitive data from memory.
        /// </summary>
        public void Dispose()
        {
            if (!this.isDisposed)
            {
                this.Clear();
                this.isDisposed = true;
            }
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(this.isDisposed, nameof(SecureKeyStorage));
        }
    }

    /// <summary>
    /// Provides secure storage for session keys with automatic memory cleanup.
    /// </summary>
    public sealed class SecureSessionKeys : IDisposable
    {
        private readonly SecureKeyStorage sEnc;
        private readonly SecureKeyStorage sMac;
        private readonly SecureKeyStorage sRMac;
        private readonly SecureKeyStorage? dek;
        private bool isDisposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="SecureSessionKeys"/> class.
        /// </summary>
        /// <param name="sEnc">The session encryption key.</param>
        /// <param name="sMac">The session MAC key.</param>
        /// <param name="sRMac">The session R-MAC key.</param>
        /// <param name="dek">The data encryption key (optional).</param>
        public SecureSessionKeys(byte[] sEnc, byte[] sMac, byte[] sRMac, byte[]? dek = null)
        {
            this.sEnc = new SecureKeyStorage(sEnc);
            this.sMac = new SecureKeyStorage(sMac);
            this.sRMac = new SecureKeyStorage(sRMac);
            this.dek = dek != null ? new SecureKeyStorage(dek) : null;
        }

        /// <summary>
        /// Uses the session encryption key.
        /// </summary>
        /// <param name="action">The action to execute with the key.</param>
        public void UseSEnc(Action<byte[]> action)
        {
            this.ThrowIfDisposed();
            this.sEnc.UseKey(action);
        }

        /// <summary>
        /// Uses the session encryption key.
        /// </summary>
        /// <typeparam name="T">The return type.</typeparam>
        /// <param name="func">The function to execute with the key.</param>
        /// <returns>The result of the function.</returns>
        public T UseSEnc<T>(Func<byte[], T> func)
        {
            this.ThrowIfDisposed();
            return this.sEnc.UseKey(func);
        }

        /// <summary>
        /// Uses the session MAC key.
        /// </summary>
        /// <param name="action">The action to execute with the key.</param>
        public void UseSMac(Action<byte[]> action)
        {
            this.ThrowIfDisposed();
            this.sMac.UseKey(action);
        }

        /// <summary>
        /// Uses the session MAC key.
        /// </summary>
        /// <typeparam name="T">The return type.</typeparam>
        /// <param name="func">The function to execute with the key.</param>
        /// <returns>The result of the function.</returns>
        public T UseSMac<T>(Func<byte[], T> func)
        {
            this.ThrowIfDisposed();
            return this.sMac.UseKey(func);
        }

        /// <summary>
        /// Uses the session R-MAC key.
        /// </summary>
        /// <param name="action">The action to execute with the key.</param>
        public void UseSRMac(Action<byte[]> action)
        {
            this.ThrowIfDisposed();
            this.sRMac.UseKey(action);
        }

        /// <summary>
        /// Uses the session R-MAC key.
        /// </summary>
        /// <typeparam name="T">The return type.</typeparam>
        /// <param name="func">The function to execute with the key.</param>
        /// <returns>The result of the function.</returns>
        public T UseSRMac<T>(Func<byte[], T> func)
        {
            this.ThrowIfDisposed();
            return this.sRMac.UseKey(func);
        }

        /// <summary>
        /// Uses the data encryption key if available.
        /// </summary>
        /// <param name="action">The action to execute with the key.</param>
        public void UseDek(Action<byte[]?> action)
        {
            this.ThrowIfDisposed();
            if (this.dek != null)
            {
                this.dek.UseKey(key => action(key));
            }
            else
            {
                action(null);
            }
        }

        /// <summary>
        /// Creates a legacy SessionKeys object. The caller is responsible for clearing the keys.
        /// </summary>
        /// <returns>A SessionKeys object with copies of the keys.</returns>
        public SessionKeys ToSessionKeys()
        {
            this.ThrowIfDisposed();
            return new SessionKeys(
                this.sEnc.GetKeyCopy(),
                this.sMac.GetKeyCopy(),
                this.sRMac.GetKeyCopy(),
                this.dek?.GetKeyCopy()
            );
        }

        /// <summary>
        /// Disposes of the session keys, clearing sensitive data from memory.
        /// </summary>
        public void Dispose()
        {
            if (!this.isDisposed)
            {
                this.sEnc?.Dispose();
                this.sMac?.Dispose();
                this.sRMac?.Dispose();
                this.dek?.Dispose();
                this.isDisposed = true;
            }
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(this.isDisposed, nameof(SecureSessionKeys));
        }
    }
}
