// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants
{
    /// <summary>
    /// Key derivation constants as defined in GlobalPlatform Card Specification.
    /// </summary>
    [PublicAPI]
    public static class DerivationConstants
    {
        /// <summary>
        /// Derivation constant for card cryptogram generation.
        /// </summary>
        public const byte CardCryptogram = 0x00;

        /// <summary>
        /// Derivation constant for host cryptogram generation.
        /// </summary>
        public const byte HostCryptogram = 0x01;

        /// <summary>
        /// Derivation constant for card challenge generation.
        /// </summary>
        public const byte CardChallenge = 0x02;

        /// <summary>
        /// Derivation constant for S-ENC session key.
        /// </summary>
        public const byte SEnc = 0x04;

        /// <summary>
        /// Derivation constant for S-MAC session key.
        /// </summary>
        public const byte SMac = 0x06;

        /// <summary>
        /// Derivation constant for S-RMAC session key.
        /// </summary>
        public const byte SRMac = 0x07;

        /// <summary>
        /// Derivation constant for data encryption session key (SCP02).
        /// </summary>
        public const byte DataEncryption = 0x82;

        /// <summary>
        /// Label for SCP03 key derivation.
        /// </summary>
        public static readonly byte[] Scp03Label = new byte[]
        {
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        };

        /// <summary>
        /// Separator for SCP03 key derivation.
        /// </summary>
        public const byte Scp03Separator = 0x00;
    }
}
