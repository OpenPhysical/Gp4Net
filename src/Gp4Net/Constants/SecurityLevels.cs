// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;

namespace Gp4Net.Constants
{
    /// <summary>
    /// Security levels for Secure Channel Protocol as defined in GlobalPlatform specifications.
    /// </summary>
    [Flags]
    public enum SecurityLevel : byte
    {
        /// <summary>
        /// No secure messaging.
        /// </summary>
        None = 0x00,

        /// <summary>
        /// C-MAC on APDU command.
        /// </summary>
        CMac = 0x01,

        /// <summary>
        /// C-DECRYPTION and C-MAC on APDU command.
        /// </summary>
        CMacAndCDecryption = 0x03,

        /// <summary>
        /// R-MAC on APDU response.
        /// </summary>
        RMac = 0x10,

        /// <summary>
        /// R-ENCRYPTION on APDU response.
        /// </summary>
        REncryption = 0x20,

        /// <summary>
        /// C-MAC and R-MAC.
        /// </summary>
        CMacAndRMac = 0x11,

        /// <summary>
        /// C-DECRYPTION, C-MAC and R-MAC.
        /// </summary>
        CMacCDecryptionAndRMac = 0x13,

        /// <summary>
        /// C-DECRYPTION, C-MAC, R-MAC and R-ENCRYPTION.
        /// </summary>
        FullSecureMessaging = 0x33
    }

    /// <summary>
    /// Extension methods for SecurityLevel enum.
    /// </summary>
    public static class SecurityLevelExtensions
    {
        /// <summary>
        /// Checks if C-MAC is enabled.
        /// </summary>
        public static bool HasCMac(this SecurityLevel level)
            => (level & SecurityLevel.CMac) == SecurityLevel.CMac;

        /// <summary>
        /// Checks if C-DECRYPTION is enabled.
        /// </summary>
        public static bool HasCDecryption(this SecurityLevel level)
            => (level & SecurityLevel.CMacAndCDecryption) == SecurityLevel.CMacAndCDecryption;

        /// <summary>
        /// Checks if R-MAC is enabled.
        /// </summary>
        public static bool HasRMac(this SecurityLevel level)
            => (level & SecurityLevel.RMac) == SecurityLevel.RMac;

        /// <summary>
        /// Checks if R-ENCRYPTION is enabled.
        /// </summary>
        public static bool HasREncryption(this SecurityLevel level)
            => (level & SecurityLevel.REncryption) == SecurityLevel.REncryption;
    }
}
