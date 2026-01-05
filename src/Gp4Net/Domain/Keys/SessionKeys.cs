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
/// Represents the session keys derived during secure channel establishment.
/// </summary>
public class SessionKeys : IDisposable
{
    /// <summary>
    /// Gets the session encryption key (S-ENC).
    /// </summary>
    public byte[] SEnc { get; }

    /// <summary>
    /// Gets the session MAC key (S-MAC).
    /// </summary>
    public byte[] SMac { get; }

    /// <summary>
    /// Gets the session R-MAC key (S-RMAC).
    /// </summary>
    public byte[] SrMac { get; }

    /// <summary>
    /// Gets the data encryption key (DEK) if applicable.
    /// </summary>
    public Maybe<byte[]> Dek { get; }

    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the SessionKeys class.
    /// </summary>
    /// <param name="sEnc">The session encryption key.</param>
    /// <param name="sMac">The session MAC key.</param>
    /// <param name="sRMac">The session R-MAC key.</param>
    /// <param name="dek">The data encryption key (optional).</param>
    public SessionKeys(byte[] sEnc, byte[] sMac, byte[] sRMac, Maybe<byte[]> dek = default)
    {
        ArgumentNullException.ThrowIfNull(sEnc);
        ArgumentNullException.ThrowIfNull(sMac);
        ArgumentNullException.ThrowIfNull(sRMac);

        SEnc = (byte[])sEnc.Clone();
        SMac = (byte[])sMac.Clone();
        SrMac = (byte[])sRMac.Clone();
        Dek = dek.Map(value => (byte[])value.Clone());
    }

    /// <summary>
    /// Creates session keys with functional validation using Maybe&lt;T&gt; patterns.
    /// </summary>
    /// <param name="sEnc">The session encryption key.</param>
    /// <param name="sMac">The session MAC key.</param>
    /// <param name="sRMac">The session R-MAC key.</param>
    /// <param name="dek">The data encryption key (optional).</param>
    /// <returns>A Result containing the SessionKeys or an error.</returns>
    public static Result<SessionKeys, SmartCardError> Create(
        byte[] sEnc,
        byte[] sMac,
        byte[] sRMac,
        Maybe<byte[]> dek = default
    )
    {
        return ValidateKey(sEnc, "S-ENC")
            .Bind(_ => ValidateKey(sMac, "S-MAC"))
            .Bind(_ => ValidateKey(sRMac, "S-RMAC"))
            .Map(_ => new SessionKeys(sEnc, sMac, sRMac, dek));
    }

    private static Result<byte[], SmartCardError> ValidateKey(byte[] key, string name)
    {
        return Maybe<byte[]>.From(key)
            .ToResult(SmartCardError.InvalidArgument($"{name} key cannot be null"))
            .Bind(bytes =>
                bytes.Length > 0
                    ? Result.Success<byte[], SmartCardError>(bytes)
                    : Result.Failure<byte[], SmartCardError>(
                        SmartCardError.InvalidArgument($"{name} key cannot be empty")
                    )
            );
    }

    /// <summary>
    /// Clears all cryptographic keys from memory.
    /// </summary>
    public UnitResult<SmartCardError> Clear()
    {
        Arrays.Fill(SEnc, 0);
        Arrays.Fill(SMac, 0);
        Arrays.Fill(SrMac, 0);
        Dek.Execute(dekKey => Arrays.Fill(dekKey, 0));
        return UnitResult.Success<SmartCardError>();
    }

    /// <summary>
    /// Disposes of the session keys, clearing sensitive data from memory.
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
