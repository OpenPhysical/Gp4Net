// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using Gp4Net.Constants;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands
{
    /// <summary>
    /// Represents the EXTERNAL AUTHENTICATE command for secure channel authentication.
    /// </summary>
    [PublicAPI]
    public class ExternalAuthenticateCommand
    {
        /// <summary>
        /// The command class byte.
        /// </summary>
        public const byte Cla = 0x84;

        /// <summary>
        /// The command instruction byte.
        /// </summary>
        public const byte Ins = 0x82;

        /// <summary>
        /// Gets the security level.
        /// </summary>
        public SecurityLevel SecurityLevel { get; }

        /// <summary>
        /// Gets the host cryptogram.
        /// </summary>
        public byte[] HostCryptogram { get; }

        /// <summary>
        /// Gets the MAC value (optional, only when C-MAC is requested).
        /// </summary>
        public byte[]? Mac { get; }

        /// <summary>
        /// Initializes a new instance of the ExternalAuthenticateCommand class.
        /// </summary>
        /// <param name="securityLevel">The security level for the secure channel.</param>
        /// <param name="hostCryptogram">The host cryptogram (8 bytes).</param>
        /// <param name="mac">The MAC value (8 bytes, optional).</param>
        public ExternalAuthenticateCommand(SecurityLevel securityLevel, byte[] hostCryptogram, byte[]? mac = null)
        {
            if (hostCryptogram?.Length != 8)
                throw new ArgumentException("Host cryptogram must be 8 bytes.", nameof(hostCryptogram));

            if (mac != null && mac.Length != 8)
                throw new ArgumentException("MAC must be 8 bytes.", nameof(mac));

            SecurityLevel = securityLevel;
            HostCryptogram = (byte[])hostCryptogram.Clone();
            Mac = mac != null ? (byte[])mac.Clone() : null;
        }

        /// <summary>
        /// Converts this command to an APDU byte array.
        /// </summary>
        /// <returns>The APDU command bytes.</returns>
        public byte[] ToApdu()
        {
            var dataLength = HostCryptogram.Length + (Mac?.Length ?? 0);
            var apdu = new byte[5 + dataLength];

            apdu[0] = Cla;
            apdu[1] = Ins;
            apdu[2] = (byte)SecurityLevel;
            apdu[3] = 0x00; // P2
            apdu[4] = (byte)dataLength; // Lc

            // Copy host cryptogram
            Array.Copy(HostCryptogram, 0, apdu, 5, HostCryptogram.Length);

            // Copy MAC if present
            if (Mac != null)
            {
                Array.Copy(Mac, 0, apdu, 5 + HostCryptogram.Length, Mac.Length);
            }

            return apdu;
        }
    }
}
