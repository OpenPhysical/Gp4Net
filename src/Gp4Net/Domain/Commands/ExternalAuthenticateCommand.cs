// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using Gp4Net.Constants;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands
{
    /// <summary>
    /// Represents the EXTERNAL AUTHENTICATE command for secure channel authentication.
    /// </summary>
    [PublicAPI]
    public class ExternalAuthenticateCommand : BaseApduCommand
    {
        /// <summary>
        /// The command class byte.
        /// </summary>
        public const byte ClassByte = 0x84;

        /// <summary>
        /// The command instruction byte.
        /// </summary>
        public const byte InstructionByte = 0x82;

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
        public ExternalAuthenticateCommand(
            SecurityLevel securityLevel,
            byte[] hostCryptogram,
            byte[]? mac = null
        )
        {
            if (hostCryptogram?.Length != 8)
            {
                throw new ArgumentException(
                    "Host cryptogram must be 8 bytes.",
                    nameof(hostCryptogram)
                );
            }

            if (mac != null && mac.Length != 8)
            {
                throw new ArgumentException("MAC must be 8 bytes.", nameof(mac));
            }

            SecurityLevel = securityLevel;
            HostCryptogram = (byte[])hostCryptogram.Clone();
            Mac = mac != null ? (byte[])mac.Clone() : null;
        }

        /// <inheritdoc />
        public override byte Cla => ClassByte;

        /// <inheritdoc />
        public override byte Ins => InstructionByte;

        /// <inheritdoc />
        public override byte P1 => (byte)SecurityLevel;

        /// <inheritdoc />
        public override byte P2 => 0x00;

        /// <inheritdoc />
        public override byte[]? Data
        {
            get
            {
                var dataLength = HostCryptogram.Length + (Mac?.Length ?? 0);
                if (dataLength == 0)
                {
                    return null;
                }

                var data = new byte[dataLength];
                Array.Copy(HostCryptogram, 0, data, 0, HostCryptogram.Length);

                if (Mac != null)
                {
                    Array.Copy(Mac, 0, data, HostCryptogram.Length, Mac.Length);
                }

                return data;
            }
        }

        /// <inheritdoc />
        public override int? ExpectedResponseLength => null; // No response data expected

        /// <summary>
        /// Converts this command to an APDU byte array.
        /// This method is obsolete. Use IApduTransport.TransmitAsync instead.
        /// </summary>
        /// <returns>The APDU command bytes.</returns>
        [Obsolete("Use IApduTransport.TransmitAsync instead of manual APDU building")]
        public new byte[] ToApdu()
        {
            return base.ToApdu();
        }
    }
}
