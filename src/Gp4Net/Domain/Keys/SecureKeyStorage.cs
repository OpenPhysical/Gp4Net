// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

namespace Gp4Net.Domain.Keys;

using System;
using System.Security.Cryptography;

/// <summary>
/// Provides secure storage for cryptographic keys with automatic memory cleanup.
/// </summary>
public sealed class SecureKeyStorage : IDisposable
{
    private byte[]? _keyData;
    private bool _isDisposed;

    /// <summary>
    /// Gets the length of the key in bytes.
    /// </summary>
    public int Length => this._keyData?.Length ?? 0;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureKeyStorage"/> class.
    /// </summary>
    /// <param name="key">The key data to store securely.</param>
    public SecureKeyStorage(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        this._keyData = new byte[key.Length];
        Array.Copy(key, this._keyData, key.Length);
    }

    /// <summary>
    /// Creates a copy of the key data. The caller is responsible for clearing this copy.
    /// </summary>
    /// <returns>A copy of the key data.</returns>
    public byte[] GetKeyCopy()
    {
        this.ThrowIfDisposed();

        if (this._keyData == null)
        {
            throw new InvalidOperationException("Key data is not available.");
        }

        var copy = new byte[this._keyData.Length];
        Array.Copy(this._keyData, copy, this._keyData.Length);
        return copy;
    }

    /// <summary>
    /// Executes an action with the key data. The key data should not be stored or leaked from the action.
    /// </summary>
    /// <param name="action">The action to execute with the key data.</param>
    public void UseKey(Action<byte[]> action)
    {
        this.ThrowIfDisposed();

        if (this._keyData == null)
        {
            throw new InvalidOperationException("Key data is not available.");
        }

        ArgumentNullException.ThrowIfNull(action);

        action(this._keyData);
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

        if (this._keyData == null)
        {
            throw new InvalidOperationException("Key data is not available.");
        }

        ArgumentNullException.ThrowIfNull(func);

        return func(this._keyData);
    }

    /// <summary>
    /// Clears the key data from memory.
    /// </summary>
    public void Clear()
    {
        if (this._keyData != null)
        {
            CryptographicOperations.ZeroMemory(this._keyData);
            this._keyData = null;
        }
    }

    /// <summary>
    /// Disposes of the key storage, clearing sensitive data from memory.
    /// </summary>
    public void Dispose()
    {
        if (!this._isDisposed)
        {
            this.Clear();
            this._isDisposed = true;
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(this._isDisposed, nameof(SecureKeyStorage));
    }
}

/// <summary>
/// Provides secure storage for session keys with automatic memory cleanup.
/// </summary>
public sealed class SecureSessionKeys : IDisposable
{
    private readonly SecureKeyStorage _sEnc;
    private readonly SecureKeyStorage _sMac;
    private readonly SecureKeyStorage _sRMac;
    private readonly SecureKeyStorage? _dek;
    private bool _isDisposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureSessionKeys"/> class.
    /// </summary>
    /// <param name="sEnc">The session encryption key.</param>
    /// <param name="sMac">The session MAC key.</param>
    /// <param name="sRMac">The session R-MAC key.</param>
    /// <param name="dek">The data encryption key (optional).</param>
    public SecureSessionKeys(byte[] sEnc, byte[] sMac, byte[] sRMac, byte[]? dek = null)
    {
        this._sEnc = new SecureKeyStorage(sEnc);
        this._sMac = new SecureKeyStorage(sMac);
        this._sRMac = new SecureKeyStorage(sRMac);
        this._dek = dek != null ? new SecureKeyStorage(dek) : null;
    }

    /// <summary>
    /// Uses the session encryption key.
    /// </summary>
    /// <param name="action">The action to execute with the key.</param>
    public void UseSEnc(Action<byte[]> action)
    {
        this.ThrowIfDisposed();
        this._sEnc.UseKey(action);
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
        return this._sEnc.UseKey(func);
    }

    /// <summary>
    /// Uses the session MAC key.
    /// </summary>
    /// <param name="action">The action to execute with the key.</param>
    public void UseSMac(Action<byte[]> action)
    {
        this.ThrowIfDisposed();
        this._sMac.UseKey(action);
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
        return this._sMac.UseKey(func);
    }

    /// <summary>
    /// Uses the session R-MAC key.
    /// </summary>
    /// <param name="action">The action to execute with the key.</param>
    public void UseSrMac(Action<byte[]> action)
    {
        this.ThrowIfDisposed();
        this._sRMac.UseKey(action);
    }

    /// <summary>
    /// Uses the session R-MAC key.
    /// </summary>
    /// <typeparam name="T">The return type.</typeparam>
    /// <param name="func">The function to execute with the key.</param>
    /// <returns>The result of the function.</returns>
    public T UseSrMac<T>(Func<byte[], T> func)
    {
        this.ThrowIfDisposed();
        return this._sRMac.UseKey(func);
    }

    /// <summary>
    /// Uses the data encryption key if available.
    /// </summary>
    /// <param name="action">The action to execute with the key.</param>
    public void UseDek(Action<byte[]?> action)
    {
        this.ThrowIfDisposed();
        if (this._dek != null)
        {
            this._dek.UseKey(key => action(key));
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
            this._sEnc.GetKeyCopy(),
            this._sMac.GetKeyCopy(),
            this._sRMac.GetKeyCopy(),
            this._dek?.GetKeyCopy()
        );
    }

    /// <summary>
    /// Disposes of the session keys, clearing sensitive data from memory.
    /// </summary>
    public void Dispose()
    {
        if (!this._isDisposed)
        {
            this._sEnc?.Dispose();
            this._sMac?.Dispose();
            this._sRMac?.Dispose();
            this._dek?.Dispose();
            this._isDisposed = true;
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(this._isDisposed, nameof(SecureSessionKeys));
    }
}