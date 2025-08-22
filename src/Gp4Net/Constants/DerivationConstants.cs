// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants;

/// <summary>
/// Key derivation constants as defined in GlobalPlatform Card Specification.
/// Per GP SCP03 v1.1.1 Table 4-1 "Data Derivation Constants" and
/// GP Card Specification v2.3.1 Table E-3 "SCP02 Derivation Constants".
/// </summary>
[PublicAPI]
public static class DerivationConstants
{
    /// <summary>
    /// Derivation constant for card cryptogram generation.
    /// Per GP SCP03 v1.1.1 Table 4-1: "0x00 - card cryptogram".
    /// </summary>
    public const byte CardCryptogram = 0x00;

    /// <summary>
    /// Derivation constant for host cryptogram generation.
    /// Per GP SCP03 v1.1.1 Table 4-1: "0x01 - host cryptogram".
    /// </summary>
    public const byte HostCryptogram = 0x01;

    /// <summary>
    /// Derivation constant for card challenge generation.
    /// Per GP SCP03 v1.1.1 Table 4-1: "0x02 - card challenge generation".
    /// </summary>
    public const byte CardChallenge = 0x02;

    /// <summary>
    /// Derivation constant for S-ENC session key.
    /// Per GP SCP03 v1.1.1 Table 4-1: "0x04 - derivation of S-ENC".
    /// </summary>
    public const byte SEnc = 0x04;

    /// <summary>
    /// Derivation constant for S-MAC session key.
    /// Per GP SCP03 v1.1.1 Table 4-1: "0x06 - derivation of S-MAC".
    /// </summary>
    public const byte SMac = 0x06;

    /// <summary>
    /// Derivation constant for S-RMAC session key.
    /// Per GP SCP03 v1.1.1 Table 4-1: "0x07 - derivation of S-RMAC".
    /// </summary>
    public const byte SrMac = 0x07;

    /// <summary>
    /// Derivation constant for data encryption session key (SCP02).
    /// Per GP Card Specification v2.3.1 Table E-3: "0x82 - S-ENC".
    /// </summary>
    public const byte DataEncryption = 0x82;

    /// <summary>
    /// SCP02-specific derivation constants as defined in GlobalPlatform Card Specification Appendix E.
    /// These are 2-byte constants used for SCP02 key derivation.
    /// </summary>
    public static class Scp02
    {
        /// <summary>
        /// SCP02 C-MAC session key derivation constant (0x0101).
        /// </summary>
        public static readonly byte[] CMac = [0x01, 0x01];

        /// <summary>
        /// SCP02 R-MAC session key derivation constant (0x0102).
        /// </summary>
        public static readonly byte[] RMac = [0x01, 0x02];

        /// <summary>
        /// SCP02 data encryption (DEK) session key derivation constant (0x0181).
        /// </summary>
        public static readonly byte[] DataEncryptionKey = [0x01, 0x81];

        /// <summary>
        /// SCP02 secure channel encryption (S-ENC) session key derivation constant (0x0182).
        /// </summary>
        public static readonly byte[] SecureChannelEncryption = [0x01, 0x82];
    }

    /// <summary>
    /// Label for SCP03 key derivation.
    /// Per GP SCP03 v1.1.1 Section 4.1.5: "A 12 byte 'label' consisting of 11 bytes with value '00'
    /// followed by a one byte derivation constant".
    /// </summary>
    public static readonly byte[] Scp03Label =
    [
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
        0x00
    ];

    /// <summary>
    /// Separator for SCP03 key derivation.
    /// </summary>
    public const byte Scp03Separator = 0x00;
}
