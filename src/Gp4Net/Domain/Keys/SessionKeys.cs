// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Security.Cryptography;

namespace Gp4Net.Domain.Keys
{
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
        public byte[] SRMac { get; }

        /// <summary>
        /// Gets the data encryption key (DEK) if applicable.
        /// </summary>
        public byte[]? Dek { get; }

        private bool _disposed = false;

        /// <summary>
        /// Initializes a new instance of the SessionKeys class.
        /// </summary>
        /// <param name="sEnc">The session encryption key.</param>
        /// <param name="sMac">The session MAC key.</param>
        /// <param name="sRMac">The session R-MAC key.</param>
        /// <param name="dek">The data encryption key (optional).</param>
        public SessionKeys(byte[] sEnc, byte[] sMac, byte[] sRMac, byte[]? dek = null)
        {
            ArgumentNullException.ThrowIfNull(sEnc);
            ArgumentNullException.ThrowIfNull(sMac);
            ArgumentNullException.ThrowIfNull(sRMac);
            SEnc = sEnc;
            SMac = sMac;
            SRMac = sRMac;
            Dek = dek;
        }

        /// <summary>
        /// Clears all cryptographic keys from memory.
        /// </summary>
        public void Clear()
        {
            CryptographicOperations.ZeroMemory(SEnc);
            CryptographicOperations.ZeroMemory(SMac);
            CryptographicOperations.ZeroMemory(SRMac);
            if (Dek != null)
            {
                CryptographicOperations.ZeroMemory(Dek);
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
}
