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
    public byte[] Dek { get; }

    private bool _disposed = false;

    /// <summary>
    /// Initializes a new instance of the SessionKeys class.
    /// </summary>
    /// <param name="sEnc">The session encryption key.</param>
    /// <param name="sMac">The session MAC key.</param>
    /// <param name="sRMac">The session R-MAC key.</param>
    /// <param name="dek">The data encryption key (optional).</param>
    public SessionKeys(byte[] sEnc, byte[] sMac, byte[] sRMac, byte[] dek = null)
    {
        SEnc = sEnc;
        SMac = sMac;
        SrMac = sRMac;
        Dek = dek;
    }

    /// <summary>
    /// Creates session keys with functional validation using Maybe&lt;T&gt; patterns.
    /// </summary>
    /// <param name="sEnc">The session encryption key.</param>
    /// <param name="sMac">The session MAC key.</param>
    /// <param name="sRMac">The session R-MAC key.</param>
    /// <param name="dek">The data encryption key (optional).</param>
    /// <returns>A Result containing the SessionKeys or an error.</returns>
    public static Result<SessionKeys, SmartCardError> Create(byte[] sEnc, byte[] sMac, byte[] sRMac, byte[] dek = null)
    {
        return Maybe<byte[]>.From(sEnc)
            .ToResult(SmartCardError.InvalidArgument("S-ENC key cannot be null"))
            .Bind(encKey => encKey.Length > 0
                ? Result.Success<byte[], SmartCardError>(encKey)
                : Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidArgument("S-ENC key cannot be empty")))
            .Bind(_ => Maybe<byte[]>.From(sMac)
                .ToResult(SmartCardError.InvalidArgument("S-MAC key cannot be null")))
            .Bind(macKey => macKey.Length > 0
                ? Result.Success<byte[], SmartCardError>(macKey)
                : Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidArgument("S-MAC key cannot be empty")))
            .Bind(_ => Maybe<byte[]>.From(sRMac)
                .ToResult(SmartCardError.InvalidArgument("S-RMAC key cannot be null")))
            .Bind(rMacKey => rMacKey.Length > 0
                ? Result.Success<byte[], SmartCardError>(rMacKey)
                : Result.Failure<byte[], SmartCardError>(SmartCardError.InvalidArgument("S-RMAC key cannot be empty")))
            .Map(_ => new SessionKeys(sEnc, sMac, sRMac, dek));
    }

    /// <summary>
    /// Clears all cryptographic keys from memory.
    /// </summary>
    public void Clear()
    {
        Arrays.Fill(SEnc, 0);
        Arrays.Fill(SMac, 0);
        Arrays.Fill(SrMac, 0);
        if (Dek != null)
        {
            Arrays.Fill(Dek, 0);
        }
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