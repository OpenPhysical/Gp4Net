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
/// Provides secure storage for cryptographic keys with automatic memory cleanup.
/// </summary>
public sealed class SecureKeyStorage : IDisposable
{
    private Maybe<byte[]> _keyData;
    private bool _isDisposed;

    /// <summary>
    /// Gets the length of the key in bytes.
    /// </summary>
    public int Length
    {
        get { return _keyData.Match(data => data.Length, () => 0); }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureKeyStorage"/> class.
    /// </summary>
    /// <param name="key">The key data to store securely.</param>
    public SecureKeyStorage(byte[] key)
    {
        var keyData = new byte[key.Length];
        key.CopyTo(keyData, 0);
        _keyData = Maybe<byte[]>.From(keyData);
    }

    /// <summary>
    /// Creates a copy of the key data. The caller is responsible for clearing this copy.
    /// </summary>
    /// <returns>A copy of the key data or failure if not available.</returns>
    public Result<byte[], SmartCardError> GetKeyCopy()
    {
        if (_isDisposed)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("SecureKeyStorage has been disposed")
            );
        }

        return _keyData.Match(
            keyData =>
            {
                byte[] copy = new byte[keyData.Length];
                keyData.CopyTo(copy, 0);
                return Result.Success<byte[], SmartCardError>(copy);
            },
            () =>
                Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("Key data is not available")
                )
        );
    }

    /// <summary>
    /// Executes an action with the key data. The key data should not be stored or leaked from the action.
    /// </summary>
    /// <param name="action">The action to execute with the key data.</param>
    /// <returns>Success or failure result.</returns>
    public Result<bool, SmartCardError> UseKey(Action<byte[]> action)
    {
        if (_isDisposed)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("SecureKeyStorage has been disposed")
            );
        }

        return _keyData.Match(
            keyData =>
            {
                action(keyData);
                return Result.Success<bool, SmartCardError>(true);
            },
            () =>
                Result.Failure<bool, SmartCardError>(
                    SmartCardError.InvalidArgument("Key data is not available")
                )
        );
    }

    /// <summary>
    /// Executes a function with the key data. The key data should not be stored or leaked from the function.
    /// </summary>
    /// <typeparam name="T">The return type of the function.</typeparam>
    /// <param name="func">The function to execute with the key data.</param>
    /// <returns>The result of the function or failure.</returns>
    public Result<T, SmartCardError> UseKey<T>(Func<byte[], T> func)
    {
        if (_isDisposed)
        {
            return Result.Failure<T, SmartCardError>(
                SmartCardError.InvalidArgument("SecureKeyStorage has been disposed")
            );
        }

        return _keyData.Match(
            keyData => Result.Success<T, SmartCardError>(func(keyData)),
            () =>
                Result.Failure<T, SmartCardError>(
                    SmartCardError.InvalidArgument("Key data is not available")
                )
        );
    }

    /// <summary>
    /// Clears the key data from memory.
    /// </summary>
    public UnitResult<SmartCardError> Clear()
    {
        return _keyData.Match(
            Some: keyData =>
            {
                Arrays.Fill(keyData, 0);
                _keyData = Maybe<byte[]>.None;
                return UnitResult.Success<SmartCardError>();
            },
            None: () => UnitResult.Success<SmartCardError>()
        );
    }

    /// <summary>
    /// Disposes of the key storage, clearing sensitive data from memory.
    /// </summary>
    public void Dispose()
    {
        if (!_isDisposed)
        {
            Clear();
            _isDisposed = true;
        }
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
    private readonly Maybe<SecureKeyStorage> _dek;
    private bool _isDisposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureSessionKeys"/> class.
    /// </summary>
    /// <param name="sEnc">The session encryption key.</param>
    /// <param name="sMac">The session MAC key.</param>
    /// <param name="sRMac">The session R-MAC key.</param>
    /// <param name="dek">The data encryption key (optional).</param>
    public SecureSessionKeys(byte[] sEnc, byte[] sMac, byte[] sRMac, Maybe<byte[]> dek = default)
    {
        _sEnc = new SecureKeyStorage(sEnc);
        _sMac = new SecureKeyStorage(sMac);
        _sRMac = new SecureKeyStorage(sRMac);
        _dek = dek.Map(d => new SecureKeyStorage(d));
    }

    /// <summary>
    /// Uses the session encryption key.
    /// </summary>
    /// <param name="action">The action to execute with the key.</param>
    /// <returns>Success or failure result.</returns>
    public Result<bool, SmartCardError> UseSEnc(Action<byte[]> action)
    {
        if (_isDisposed)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("SecureSessionKeys has been disposed")
            );
        }
        return _sEnc.UseKey(action);
    }

    /// <summary>
    /// Uses the session encryption key.
    /// </summary>
    /// <typeparam name="T">The return type.</typeparam>
    /// <param name="func">The function to execute with the key.</param>
    /// <returns>The result of the function or failure.</returns>
    public Result<T, SmartCardError> UseSEnc<T>(Func<byte[], T> func)
    {
        if (_isDisposed)
        {
            return Result.Failure<T, SmartCardError>(
                SmartCardError.InvalidArgument("SecureSessionKeys has been disposed")
            );
        }
        return _sEnc.UseKey(func);
    }

    /// <summary>
    /// Uses the session MAC key.
    /// </summary>
    /// <param name="action">The action to execute with the key.</param>
    /// <returns>Success or failure result.</returns>
    public Result<bool, SmartCardError> UseSMac(Action<byte[]> action)
    {
        if (_isDisposed)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("SecureSessionKeys has been disposed")
            );
        }
        return _sMac.UseKey(action);
    }

    /// <summary>
    /// Uses the session MAC key.
    /// </summary>
    /// <typeparam name="T">The return type.</typeparam>
    /// <param name="func">The function to execute with the key.</param>
    /// <returns>The result of the function or failure.</returns>
    public Result<T, SmartCardError> UseSMac<T>(Func<byte[], T> func)
    {
        if (_isDisposed)
        {
            return Result.Failure<T, SmartCardError>(
                SmartCardError.InvalidArgument("SecureSessionKeys has been disposed")
            );
        }
        return _sMac.UseKey(func);
    }

    /// <summary>
    /// Uses the session R-MAC key.
    /// </summary>
    /// <param name="action">The action to execute with the key.</param>
    /// <returns>Success or failure result.</returns>
    public Result<bool, SmartCardError> UseSrMac(Action<byte[]> action)
    {
        if (_isDisposed)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("SecureSessionKeys has been disposed")
            );
        }
        return _sRMac.UseKey(action);
    }

    /// <summary>
    /// Uses the session R-MAC key.
    /// </summary>
    /// <typeparam name="T">The return type.</typeparam>
    /// <param name="func">The function to execute with the key.</param>
    /// <returns>The result of the function or failure.</returns>
    public Result<T, SmartCardError> UseSrMac<T>(Func<byte[], T> func)
    {
        if (_isDisposed)
        {
            return Result.Failure<T, SmartCardError>(
                SmartCardError.InvalidArgument("SecureSessionKeys has been disposed")
            );
        }
        return _sRMac.UseKey(func);
    }

    /// <summary>
    /// Uses the data encryption key if available.
    /// </summary>
    /// <param name="action">The action to execute with the key (receives Maybe for optional DEK).</param>
    /// <returns>Success or failure result.</returns>
    public Result<bool, SmartCardError> UseDek(Action<Maybe<byte[]>> action)
    {
        if (_isDisposed)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("SecureSessionKeys has been disposed")
            );
        }

        return _dek.Match(
            dek => dek.UseKey(key => action(Maybe<byte[]>.From(key))),
            () =>
            {
                action(Maybe<byte[]>.None);
                return Result.Success<bool, SmartCardError>(true);
            }
        );
    }

    /// <summary>
    /// Creates a legacy SessionKeys object. The caller is responsible for clearing the keys.
    /// </summary>
    /// <returns>A SessionKeys object with copies of the keys or failure.</returns>
    public Result<SessionKeys, SmartCardError> ToSessionKeys()
    {
        if (_isDisposed)
        {
            return Result.Failure<SessionKeys, SmartCardError>(
                SmartCardError.InvalidArgument("SecureSessionKeys has been disposed")
            );
        }

        return _sEnc
            .GetKeyCopy()
            .Bind(sEnc => _sMac.GetKeyCopy().Map(sMac => (sEnc, sMac)))
            .Bind(keys => _sRMac.GetKeyCopy().Map(sRMac => (keys.sEnc, keys.sMac, sRMac)))
            .Bind(keys =>
            {
                Maybe<byte[]> dekKey = Maybe<byte[]>.None;
                Result<bool, SmartCardError> dekResult = _dek.Match(
                    dekStorage =>
                        dekStorage
                            .GetKeyCopy()
                            .Tap(key => dekKey = Maybe<byte[]>.From(key))
                            .Map(_ => true),
                    () => Result.Success<bool, SmartCardError>(true)
                );

                return dekResult.Map(_ => new { keys.sEnc, keys.sMac, keys.sRMac, dekKey });
            })
            .Map(payload => new SessionKeys(payload.sEnc, payload.sMac, payload.sRMac, payload.dekKey));
    }

    /// <summary>
    /// Disposes of the session keys, clearing sensitive data from memory.
    /// </summary>
    public void Dispose()
    {
        if (!_isDisposed)
        {
            _sEnc.Dispose();
            _sMac.Dispose();
            _sRMac.Dispose();
            _dek.Execute(d => d.Dispose());
            _isDisposed = true;
        }
    }
}
