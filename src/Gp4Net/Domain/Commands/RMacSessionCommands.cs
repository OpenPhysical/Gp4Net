// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;

namespace Gp4Net.Domain.Commands
{
    /// <summary>
    /// Represents the BEGIN R-MAC SESSION command.
    /// </summary>
    public class BeginRMacSessionCommand
    {
        /// <summary>
        /// The command class byte options.
        /// </summary>
        public const byte Cla80 = 0x80;
        public const byte ClaC0 = 0xC0;
        public const byte ClaE0 = 0xE0;

        /// <summary>
        /// The command instruction byte.
        /// </summary>
        public const byte Ins = 0x7A;

        /// <summary>
        /// Gets the command class byte.
        /// </summary>
        public byte Cla { get; }

        /// <summary>
        /// Gets the P1 parameter (security level for responses).
        /// </summary>
        public byte P1 { get; }

        /// <summary>
        /// Gets the data field (optional).
        /// </summary>
        public byte[]? Data { get; }

        /// <summary>
        /// Gets the MAC value (optional).
        /// </summary>
        public byte[]? Mac { get; }

        /// <summary>
        /// Initializes a new instance of the BeginRMacSessionCommand class.
        /// </summary>
        /// <param name="cla">The command class byte.</param>
        /// <param name="p1">The P1 parameter (0x10 for R-MAC, 0x30 for R-ENCRYPTION and R-MAC).</param>
        /// <param name="data">Optional data field.</param>
        /// <param name="mac">Optional MAC value (8 bytes).</param>
        public BeginRMacSessionCommand(byte cla, byte p1, byte[]? data = null, byte[]? mac = null)
        {
            if (cla != Cla80 && cla != ClaC0 && cla != ClaE0)
            {
                throw new ArgumentException("Invalid CLA byte.", nameof(cla));
            }

            if (mac != null && mac.Length != 8)
            {
                throw new ArgumentException("MAC must be 8 bytes.", nameof(mac));
            }

            Cla = cla;
            P1 = p1;
            Data = data != null ? (byte[])data.Clone() : null;
            Mac = mac != null ? (byte[])mac.Clone() : null;
        }

        /// <summary>
        /// Converts this command to an APDU byte array.
        /// </summary>
        /// <returns>The APDU command bytes.</returns>
        public byte[] ToApdu()
        {
            var dataLength = (Data?.Length ?? 0) + (Mac?.Length ?? 0);
            var apdu = new byte[5 + dataLength];

            apdu[0] = Cla;
            apdu[1] = Ins;
            apdu[2] = P1;
            apdu[3] = 0x01; // P2
            apdu[4] = (byte)dataLength; // Lc

            var offset = 5;

            // Copy data if present
            if (Data != null)
            {
                Array.Copy(Data, 0, apdu, offset, Data.Length);
                offset += Data.Length;
            }

            // Copy MAC if present
            if (Mac != null)
            {
                Array.Copy(Mac, 0, apdu, offset, Mac.Length);
            }

            return apdu;
        }
    }

    /// <summary>
    /// Represents the END R-MAC SESSION command.
    /// </summary>
    public class EndRMacSessionCommand
    {
        /// <summary>
        /// The command class byte options.
        /// </summary>
        public const byte Cla80 = 0x80;
        public const byte ClaC0 = 0xC0;
        public const byte ClaE0 = 0xE0;

        /// <summary>
        /// The command instruction byte.
        /// </summary>
        public const byte Ins = 0x78;

        /// <summary>
        /// Gets the command class byte.
        /// </summary>
        public byte Cla { get; }

        /// <summary>
        /// Gets the P2 parameter.
        /// </summary>
        public byte P2 { get; }

        /// <summary>
        /// Gets the MAC value (optional).
        /// </summary>
        public byte[]? Mac { get; }

        /// <summary>
        /// Initializes a new instance of the EndRMacSessionCommand class.
        /// </summary>
        /// <param name="cla">The command class byte.</param>
        /// <param name="p2">The P2 parameter (0x03 to end session and return R-MAC).</param>
        /// <param name="mac">Optional C-MAC value (8 bytes).</param>
        public EndRMacSessionCommand(byte cla, byte p2, byte[]? mac = null)
        {
            if (cla != Cla80 && cla != ClaC0 && cla != ClaE0)
            {
                throw new ArgumentException("Invalid CLA byte.", nameof(cla));
            }

            if (mac != null && mac.Length != 8)
            {
                throw new ArgumentException("MAC must be 8 bytes.", nameof(mac));
            }

            Cla = cla;
            P2 = p2;
            Mac = mac != null ? (byte[])mac.Clone() : null;
        }

        /// <summary>
        /// Converts this command to an APDU byte array.
        /// </summary>
        /// <returns>The APDU command bytes.</returns>
        public byte[] ToApdu()
        {
            var dataLength = Mac?.Length ?? 0;
            var apdu = new byte[5 + dataLength];

            apdu[0] = Cla;
            apdu[1] = Ins;
            apdu[2] = 0x00; // P1
            apdu[3] = P2;
            apdu[4] = (byte)dataLength; // Lc

            // Copy MAC if present
            if (Mac != null)
            {
                Array.Copy(Mac, 0, apdu, 5, Mac.Length);
            }

            return apdu;
        }
    }

    /// <summary>
    /// Represents the response to an END R-MAC SESSION command.
    /// </summary>
    public class EndRMacSessionResponse
    {
        /// <summary>
        /// Gets the R-MAC value.
        /// </summary>
        public byte[] RMac { get; }

        /// <summary>
        /// Initializes a new instance of the EndRMacSessionResponse class.
        /// </summary>
        /// <param name="rMac">The R-MAC value (8 bytes).</param>
        public EndRMacSessionResponse(byte[] rMac)
        {
            if (rMac?.Length != 8)
            {
                throw new ArgumentException("R-MAC must be 8 bytes.", nameof(rMac));
            }

            RMac = (byte[])rMac.Clone();
        }

        /// <summary>
        /// Parses an END R-MAC SESSION response.
        /// </summary>
        /// <param name="response">The response data (excluding status word).</param>
        /// <returns>The parsed response.</returns>
        public static EndRMacSessionResponse Parse(byte[] response)
        {
            if (response == null || response.Length != 8)
            {
                throw new ArgumentException("Response must be 8 bytes.", nameof(response));
            }

            return new EndRMacSessionResponse(response);
        }
    }
}
