// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants;

public static partial class Constants
{
    /// <summary>
    /// Cryptographic constants for GlobalPlatform secure channel protocols.
    /// Consolidates ALL crypto-related constants from CryptographicConstants.cs and DerivationConstants.cs
    /// Reference: GlobalPlatform Card Specification v2.3.1, SCP03 v1.1.1, and cryptographic standards
    /// </summary>
    [PublicAPI]
    public static class Cryptography
    {
        /// <summary>
        /// Symmetric encryption key lengths and block sizes.
        /// Reference: NIST SP 800-38A, FIPS 46-3, and GlobalPlatform specifications
        /// </summary>
        public static class KeySizes
        {
            /// <summary>
            /// Triple DES key length for 2-key format (K1||K2||K1) - 16 bytes.
            /// Commonly used in SCP02 for backward compatibility.
            /// Reference: FIPS 46-3, Section 3.2
            /// </summary>
            public const int Des3KeyLength16 = 16;

            /// <summary>
            /// Triple DES key length for 3-key format (K1||K2||K3) - 24 bytes.
            /// Full 3DES key size providing maximum security.
            /// Reference: FIPS 46-3, Section 3.3
            /// </summary>
            public const int Des3KeyLength24 = 24;

            /// <summary>
            /// AES key length for 128-bit keys (16 bytes).
            /// Standard AES key size used in SCP03.
            /// Reference: FIPS 197, Section 5
            /// </summary>
            public const int AesKeyLength128 = 16;

            /// <summary>
            /// AES key length for 192-bit keys (24 bytes).
            /// Extended AES key size for enhanced security.
            /// Reference: FIPS 197, Section 5
            /// </summary>
            public const int AesKeyLength192 = 24;

            /// <summary>
            /// AES key length for 256-bit keys (32 bytes).
            /// Maximum AES key size providing highest security.
            /// Reference: FIPS 197, Section 5
            /// </summary>
            public const int AesKeyLength256 = 32;
        }

        /// <summary>
        /// Block cipher block sizes for different algorithms.
        /// Reference: FIPS standards and cryptographic algorithm specifications
        /// </summary>
        public static class BlockSizes
        {
            /// <summary>
            /// AES block size in bytes (16 bytes).
            /// Fixed block size for AES algorithm used in SCP03.
            /// Reference: FIPS 197, Section 5.1
            /// </summary>
            public const int AesBlockSize = 16;

            /// <summary>
            /// DES/3DES block size in bytes (8 bytes).
            /// Fixed block size for DES family algorithms used in SCP02.
            /// Reference: FIPS 46-3, Section 2.1
            /// </summary>
            public const int DesBlockSize = 8;
        }

        /// <summary>
        /// Message Authentication Code (MAC) lengths and parameters.
        /// Reference: GlobalPlatform specifications and NIST standards
        /// </summary>
        public static class MacParameters
        {
            /// <summary>
            /// CMAC (Cipher-based Message Authentication Code) length for 3DES (8 bytes).
            /// Used in SCP02 for command and response authentication.
            /// Reference: GP Card Specification v2.3.1, Appendix E
            /// </summary>
            public const int CmacLength = 8;

            /// <summary>
            /// CMAC length for AES-based secure channels (16 bytes).
            /// Used in SCP03 for command and response authentication.
            /// Reference: GP SCP03 v1.1.1, Section 4.2
            /// </summary>
            public const int AesCmacLength = 16;

            /// <summary>
            /// Default MAC chaining value for secure channel initialization.
            /// Zero-filled array used as initial MAC chaining value.
            /// Reference: GP Card Specification v2.3.1, Section E.1
            /// </summary>
            public static readonly byte[] DefaultMacChainingValue = new byte[BlockSizes.DesBlockSize];
        }

        /// <summary>
        /// Sequence counter parameters for replay attack prevention.
        /// Reference: GlobalPlatform specifications for SCP02 and SCP03
        /// </summary>
        public static class SequenceCounters
        {
            /// <summary>
            /// SCP02 sequence counter length for 2-byte format (2 bytes).
            /// Used to prevent replay attacks in SCP02 protocol.
            /// Reference: GP Card Specification v2.3.1, Appendix E.2
            /// </summary>
            public const int SequenceCounterLength2 = 2;

            /// <summary>
            /// SCP03 sequence counter length for 3-byte format (3 bytes).
            /// Used to prevent replay attacks in SCP03 protocol.
            /// Reference: GP SCP03 v1.1.1, Section 4.3
            /// </summary>
            public const int SequenceCounterLength3 = 3;
        }

        /// <summary>
        /// Encryption and padding parameters.
        /// Reference: ISO 7816-4 and cryptographic standards
        /// </summary>
        public static class EncryptionParameters
        {
            /// <summary>
            /// IV (Initialization Vector) length for encryption operations (16 bytes).
            /// Standard IV length for AES block cipher operations.
            /// Reference: NIST SP 800-38A, Section 4
            /// </summary>
            public const int EncryptionIvLength = 16;

            /// <summary>
            /// ISO 7816-4 padding marker byte (0x80).
            /// Used to pad data to block boundaries in secure channels.
            /// Reference: ISO 7816-4, Section 5.2.2
            /// </summary>
            public const byte Iso7816PaddingMarker = 0x80;

            /// <summary>
            /// Key check value length as defined by GlobalPlatform (3 bytes).
            /// Used to verify key correctness during key loading.
            /// Reference: GP Card Specification v2.3.1, Section 4.1.3
            /// </summary>
            public const int KeyCheckValueLength = 3;
        }

        /// <summary>
        /// Key derivation constants as defined in GlobalPlatform Card Specification.
        /// Reference: GP SCP03 v1.1.1 Table 4-1 and GP Card Specification v2.3.1 Table E-3
        /// </summary>
        public static class KeyDerivation
        {
            /// <summary>
            /// Single-byte derivation constants for SCP03.
            /// Reference: GP SCP03 v1.1.1, Table 4-1 "Data Derivation Constants"
            /// </summary>
            public static class Scp03Constants
            {
                /// <summary>
                /// Derivation constant for card cryptogram generation (0x00).
                /// Reference: GP SCP03 v1.1.1 Table 4-1: "0x00 - card cryptogram"
                /// </summary>
                public const byte CardCryptogram = 0x00;

                /// <summary>
                /// Derivation constant for host cryptogram generation (0x01).
                /// Reference: GP SCP03 v1.1.1 Table 4-1: "0x01 - host cryptogram"
                /// </summary>
                public const byte HostCryptogram = 0x01;

                /// <summary>
                /// Derivation constant for card challenge generation (0x02).
                /// Reference: GP SCP03 v1.1.1 Table 4-1: "0x02 - card challenge generation"
                /// </summary>
                public const byte CardChallenge = 0x02;

                /// <summary>
                /// Derivation constant for S-ENC session key (0x04).
                /// Reference: GP SCP03 v1.1.1 Table 4-1: "0x04 - derivation of S-ENC"
                /// </summary>
                public const byte SEnc = 0x04;

                /// <summary>
                /// Derivation constant for S-MAC session key (0x06).
                /// Reference: GP SCP03 v1.1.1 Table 4-1: "0x06 - derivation of S-MAC"
                /// </summary>
                public const byte SMac = 0x06;

                /// <summary>
                /// Derivation constant for S-RMAC session key (0x07).
                /// Reference: GP SCP03 v1.1.1 Table 4-1: "0x07 - derivation of S-RMAC"
                /// </summary>
                public const byte SrMac = 0x07;

                /// <summary>
                /// Derivation constant for data encryption session key (0x82).
                /// Legacy constant from SCP02 still used in some contexts.
                /// Reference: GP Card Specification v2.3.1 Table E-3: "0x82 - S-ENC"
                /// </summary>
                public const byte DataEncryption = 0x82;

                /// <summary>
                /// Label for SCP03 key derivation (11 zero bytes).
                /// Used as prefix in SCP03 key derivation function.
                /// Reference: GP SCP03 v1.1.1 Section 4.1.5: "A 12 byte 'label' consisting of 
                /// 11 bytes with value '00' followed by a one byte derivation constant"
                /// </summary>
                public static readonly byte[] Label =
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                ];

                /// <summary>
                /// Separator for SCP03 key derivation (0x00).
                /// Used between label and derivation constant in key derivation.
                /// Reference: GP SCP03 v1.1.1, Section 4.1.5
                /// </summary>
                public const byte Separator = 0x00;
            }

            /// <summary>
            /// SCP02-specific derivation constants as defined in GlobalPlatform Card Specification Appendix E.
            /// These are 2-byte constants used for SCP02 key derivation.
            /// Reference: GP Card Specification v2.3.1, Table E-3 "SCP02 Derivation Constants"
            /// </summary>
            public static class Scp02Constants
            {
                /// <summary>
                /// SCP02 C-MAC session key derivation constant (0x0101).
                /// Used to derive command MAC session key from static keys.
                /// Reference: GP Card Specification v2.3.1, Table E-3
                /// </summary>
                public static readonly byte[] CMac = [0x01, 0x01];

                /// <summary>
                /// SCP02 R-MAC session key derivation constant (0x0102).
                /// Used to derive response MAC session key from static keys.
                /// Reference: GP Card Specification v2.3.1, Table E-3
                /// </summary>
                public static readonly byte[] RMac = [0x01, 0x02];

                /// <summary>
                /// SCP02 data encryption (DEK) session key derivation constant (0x0181).
                /// Used to derive data encryption key from static keys.
                /// Reference: GP Card Specification v2.3.1, Table E-3
                /// </summary>
                public static readonly byte[] DataEncryptionKey = [0x01, 0x81];

                /// <summary>
                /// SCP02 secure channel encryption (S-ENC) session key derivation constant (0x0182).
                /// Used to derive secure channel encryption key from static keys.
                /// Reference: GP Card Specification v2.3.1, Table E-3
                /// </summary>
                public static readonly byte[] SecureChannelEncryption = [0x01, 0x82];
            }
        }
    }
}