// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Domain.Keys;

/// <summary>
/// Provides secure storage for a key set with automatic memory cleanup.
/// </summary>
public sealed class SecureKeySet : IDisposable
{
    private readonly SecureKeyStorage _encKey;
    private readonly SecureKeyStorage _macKey;
    private readonly SecureKeyStorage _dekKey;
    private bool _isDisposed;

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
        KeyVersion = keyVersion;
        _encKey = new SecureKeyStorage(encKey);
        _macKey = new SecureKeyStorage(macKey);
        _dekKey = new SecureKeyStorage(dekKey);
    }

    /// <summary>
    /// Creates a secure key set from an existing key set.
    /// </summary>
    /// <param name="keySet">The key set to secure.</param>
    /// <returns>A new secure key set.</returns>
    public static SecureKeySet FromKeySet(IKeySet keySet)
    {
        return new SecureKeySet(keySet.KeyVersion, keySet.EncKey, keySet.MacKey, keySet.DekKey);
    }

    /// <summary>
    /// Uses the encryption key.
    /// </summary>
    /// <param name="action">The action to execute with the key.</param>
    /// <returns>Success or failure result.</returns>
    public Result<bool, SmartCardError> UseEncKey(Action<byte[]> action)
    {
        if (_isDisposed)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("SecureKeySet has been disposed")
            );
        }
        return _encKey.UseKey(action);
    }

    /// <summary>
    /// Uses the encryption key.
    /// </summary>
    /// <typeparam name="T">The return type.</typeparam>
    /// <param name="func">The function to execute with the key.</param>
    /// <returns>The result of the function or failure.</returns>
    public Result<T, SmartCardError> UseEncKey<T>(Func<byte[], T> func)
    {
        if (_isDisposed)
        {
            return Result.Failure<T, SmartCardError>(
                SmartCardError.InvalidArgument("SecureKeySet has been disposed")
            );
        }
        return _encKey.UseKey(func);
    }

    /// <summary>
    /// Uses the MAC key.
    /// </summary>
    /// <param name="action">The action to execute with the key.</param>
    /// <returns>Success or failure result.</returns>
    public Result<bool, SmartCardError> UseMacKey(Action<byte[]> action)
    {
        if (_isDisposed)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("SecureKeySet has been disposed")
            );
        }
        return _macKey.UseKey(action);
    }

    /// <summary>
    /// Uses the MAC key.
    /// </summary>
    /// <typeparam name="T">The return type.</typeparam>
    /// <param name="func">The function to execute with the key.</param>
    /// <returns>The result of the function or failure.</returns>
    public Result<T, SmartCardError> UseMacKey<T>(Func<byte[], T> func)
    {
        if (_isDisposed)
        {
            return Result.Failure<T, SmartCardError>(
                SmartCardError.InvalidArgument("SecureKeySet has been disposed")
            );
        }
        return _macKey.UseKey(func);
    }

    /// <summary>
    /// Uses the data encryption key.
    /// </summary>
    /// <param name="action">The action to execute with the key.</param>
    /// <returns>Success or failure result.</returns>
    public Result<bool, SmartCardError> UseDekKey(Action<byte[]> action)
    {
        if (_isDisposed)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("SecureKeySet has been disposed")
            );
        }
        return _dekKey.UseKey(action);
    }

    /// <summary>
    /// Uses the data encryption key.
    /// </summary>
    /// <typeparam name="T">The return type.</typeparam>
    /// <param name="func">The function to execute with the key.</param>
    /// <returns>The result of the function or failure.</returns>
    public Result<T, SmartCardError> UseDekKey<T>(Func<byte[], T> func)
    {
        if (_isDisposed)
        {
            return Result.Failure<T, SmartCardError>(
                SmartCardError.InvalidArgument("SecureKeySet has been disposed")
            );
        }
        return _dekKey.UseKey(func);
    }

    /// <summary>
    /// Creates a legacy KeySet object. The caller is responsible for clearing the keys.
    /// </summary>
    /// <returns>A KeySet object with copies of the keys or failure.</returns>
    public Result<Scp02KeySet, SmartCardError> ToScp02KeySet()
    {
        if (_isDisposed)
        {
            return Result.Failure<Scp02KeySet, SmartCardError>(
                SmartCardError.InvalidArgument("SecureKeySet has been disposed")
            );
        }
        
        return _encKey.GetKeyCopy()
            .Bind(encKey => _macKey.GetKeyCopy().Map(macKey => (encKey, macKey)))
            .Bind(keys => _dekKey.GetKeyCopy().Map(dekKey => (keys.encKey, keys.macKey, dekKey)))
            .Bind(keys => Scp02KeySet.Create(keys.encKey, keys.macKey, keys.dekKey, KeyVersion));
    }

    /// <summary>
    /// Creates a legacy KeySet object. The caller is responsible for clearing the keys.
    /// </summary>
    /// <returns>A KeySet object with copies of the keys or failure.</returns>
    public Result<Scp03KeySet, SmartCardError> ToScp03KeySet()
    {
        if (_isDisposed)
        {
            return Result.Failure<Scp03KeySet, SmartCardError>(
                SmartCardError.InvalidArgument("SecureKeySet has been disposed")
            );
        }
        
        return _encKey.GetKeyCopy()
            .Bind(encKey => _macKey.GetKeyCopy().Map(macKey => (encKey, macKey)))
            .Bind(keys => _dekKey.GetKeyCopy().Map(dekKey => (keys.encKey, keys.macKey, dekKey)))
            .Bind(keys => Scp03KeySet.Create(keys.encKey, keys.macKey, keys.dekKey, KeyVersion));
    }

    /// <summary>
    /// Disposes of the key set, clearing sensitive data from memory.
    /// </summary>
    public void Dispose()
    {
        if (!_isDisposed)
        {
            _encKey.Dispose();
            _macKey.Dispose();
            _dekKey.Dispose();
            _isDisposed = true;
        }
    }

}
