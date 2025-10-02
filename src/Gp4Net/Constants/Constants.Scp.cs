// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants;

/// <summary>
/// Secure Channel Protocol (SCP) constants per GlobalPlatform Card Specification v2.3.1 Appendix E.
/// Consolidates all SCP02 and SCP03 constants from scattered protocol classes.
/// Reference: GlobalPlatform Card Specification v2.3.1 Appendix E "Secure Channel Protocol"
/// </summary>
public static partial class Constants
{
    /// <summary>
    /// Secure Channel Protocol constants for SCP02 and SCP03 implementations.
    /// All constants are organized by protocol version and operation type.
    /// </summary>
    [PublicAPI]
    public static class Scp
    {
        /// <summary>
        /// SCP02 protocol constants per GP Card Spec v2.3.1 Section E.4.
        /// Triple DES based secure channel protocol.
        /// </summary>
        [PublicAPI]
        public static class Scp02
        {
            /// <summary>SCP02 protocol version identifier.</summary>
            public const byte PROTOCOL_VERSION = 0x02;

            /// <summary>3DES block size for SCP02 operations (8 bytes).</summary>
            public const int BLOCK_SIZE = 8;

            /// <summary>MAC size for SCP02 operations (8 bytes).</summary>
            public const int MAC_SIZE = 8;

            /// <summary>MAC chaining value size for SCP02 (8 bytes).</summary>
            public const int CHAINING_VALUE_SIZE = 8;

            /// <summary>Card challenge length in INITIALIZE UPDATE response (6 bytes).</summary>
            public const int CARD_CHALLENGE_LENGTH = 6;

            /// <summary>Host challenge length for INITIALIZE UPDATE command (8 bytes).</summary>
            public const int HOST_CHALLENGE_LENGTH = 8;

            /// <summary>Session key size for SCP02 (16 bytes for 3DES).</summary>
            public const int SESSION_KEY_SIZE = 16;

            /// <summary>Cryptogram size for card/host cryptograms (8 bytes).</summary>
            public const int CRYPTOGRAM_SIZE = 8;

            /// <summary>Sequence counter size for key derivation (2 bytes).</summary>
            public const int SEQUENCE_COUNTER_SIZE = 2;

            /// <summary>Key derivation data size for SCP02 (16 bytes).</summary>
            public const int KEY_DERIVATION_DATA_SIZE = 16;

            /// <summary>Cryptogram data size for SCP02 (24 bytes).</summary>
            public const int CRYPTOGRAM_DATA_SIZE = 24;

            /// <summary>
            /// SCP02 key derivation constants per GP Card Spec v2.3.1 Figure E-2.
            /// Used for deriving session keys from static base keys.
            /// </summary>
            [PublicAPI]
            public static class KeyDerivationConstants
            {
                /// <summary>S-ENC key derivation constant.</summary>
                public static readonly byte[] SEnc = [0x01, 0x82];

                /// <summary>S-MAC key derivation constant.</summary>
                public static readonly byte[] SMac = [0x01, 0x01];

                /// <summary>S-RMAC key derivation constant.</summary>
                public static readonly byte[] SrMac = [0x01, 0x02];

                /// <summary>S-DEK key derivation constant.</summary>
                public static readonly byte[] SDek = [0x01, 0x81];
            }

            /// <summary>
            /// SCP02 valid implementation parameters per GP Card Spec v2.3.1 Table E-1.
            /// Each i-parameter defines specific security features and behavior.
            /// </summary>
            [PublicAPI]
            public static class Implementations
            {
                /// <summary>SCP02 i=00 - No R-MAC, no R-ENC.</summary>
                public const byte I00 = 0x00;

                /// <summary>SCP02 i=02 - R-MAC only.</summary>
                public const byte I02 = 0x02;

                /// <summary>SCP02 i=04 - R-ENC only.</summary>
                public const byte I04 = 0x04;

                /// <summary>SCP02 i=05 - R-MAC and R-ENC.</summary>
                public const byte I05 = 0x05;

                /// <summary>SCP02 i=0A - R-MAC only, challenge verification.</summary>
                public const byte I0_A = 0x0A;

                /// <summary>SCP02 i=15 - R-MAC and R-ENC with different padding.</summary>
                public const byte I15 = 0x15;

                /// <summary>SCP02 i=35 - R-MAC and R-ENC with enhanced features.</summary>
                public const byte I35 = 0x35;

                /// <summary>SCP02 i=55 - Enhanced security with R-MAC and R-ENC.</summary>
                public const byte I55 = 0x55;

                /// <summary>SCP02 i=75 - Maximum security with all features.</summary>
                public const byte I75 = 0x75;

                /// <summary>All valid SCP02 implementation parameters.</summary>
                public static readonly byte[] All =
                [
                    I00,
                    I02,
                    I04,
                    I05,
                    I0_A,
                    0x14,
                    I15,
                    0x1A,
                    0x24,
                    0x25,
                    0x2A,
                    0x34,
                    I35,
                    0x3A,
                    0x44,
                    0x45,
                    0x4A,
                    0x54,
                    I55,
                    0x64,
                    0x65,
                    0x6A,
                    0x74,
                    I75,
                    0x7A,
                ];
            }
        }

        /// <summary>
        /// SCP03 protocol constants per GP Card Spec v2.3.1 Section E.5.
        /// AES based secure channel protocol.
        /// </summary>
        [PublicAPI]
        public static class Scp03
        {
            /// <summary>SCP03 protocol version identifier.</summary>
            public const byte PROTOCOL_VERSION = 0x03;

            /// <summary>AES block size for SCP03 operations (16 bytes).</summary>
            public const int BLOCK_SIZE = 16;

            /// <summary>MAC size for SCP03 operations (8 bytes, truncated from 16).</summary>
            public const int MAC_SIZE = 8;

            /// <summary>Full MAC size before truncation (16 bytes).</summary>
            public const int FULL_MAC_SIZE = 16;

            /// <summary>MAC chaining value size for SCP03 (16 bytes).</summary>
            public const int CHAINING_VALUE_SIZE = 16;

            /// <summary>Card challenge length in INITIALIZE UPDATE response (8 bytes).</summary>
            public const int CARD_CHALLENGE_LENGTH = 8;

            /// <summary>Host challenge length for INITIALIZE UPDATE command (8 bytes).</summary>
            public const int HOST_CHALLENGE_LENGTH = 8;

            /// <summary>Session key size for SCP03 (16 bytes for AES-128).</summary>
            public const int SESSION_KEY_SIZE = 16;

            /// <summary>Cryptogram size for card/host cryptograms (8 bytes).</summary>
            public const int CRYPTOGRAM_SIZE = 8;

            /// <summary>KDF counter size for NIST SP 800-108 derivation (4 bytes).</summary>
            public const int KDF_COUNTER_SIZE = 4;

            /// <summary>KDF label size for key derivation (variable).</summary>
            public const int KDF_LABEL_MAX_SIZE = 32;

            /// <summary>
            /// Key derivation label constants for SCP03.
            /// Used with NIST SP 800-108 KDF in Counter Mode with CMAC-AES PRF.
            /// Per GlobalPlatform Card Specification v2.3 - SCP03 Amendment D v1.2.
            /// Table 4-1: Data Derivation Constants.
            /// </summary>
            [PublicAPI]
            public enum KeyDerivationLabel : byte
            {
                /// <summary>
                /// S-ENC key derivation label.
                /// Used for deriving the session encryption key.
                /// </summary>
                SEnc = 0x04,

                /// <summary>
                /// S-MAC key derivation label.
                /// Used for deriving the session MAC key.
                /// </summary>
                SMac = 0x06,

                /// <summary>
                /// S-RMAC key derivation label.
                /// Used for deriving the session response MAC key.
                /// </summary>
                SRMac = 0x07,

                /// <summary>
                /// S-DEK key derivation label.
                /// Used for deriving the session data encryption key.
                /// </summary>
                SDek = 0x08,
            }

            /// <summary>
            /// Cryptogram derivation constants for SCP03.
            /// Per GlobalPlatform Card Specification v2.3 - SCP03 Amendment D v1.2.
            /// Table 4-1: Data Derivation Constants.
            /// </summary>
            [PublicAPI]
            public static class CryptogramDerivation
            {
                /// <summary>Card cryptogram derivation constant (0x00).</summary>
                public const byte CardCryptogram = 0x00;

                /// <summary>Host cryptogram derivation constant (0x01).</summary>
                public const byte HostCryptogram = 0x01;
            }

            /// <summary>
            /// SCP03 valid implementation parameters per GP Card Spec v2.3.1 Table E-2.
            /// Each i-parameter defines specific security features and behavior.
            /// </summary>
            [PublicAPI]
            public static class Implementations
            {
                /// <summary>SCP03 i=00 - No R-MAC, no R-ENC.</summary>
                public const byte I00 = 0x00;

                /// <summary>SCP03 i=10 - R-MAC only.</summary>
                public const byte I10 = 0x10;

                /// <summary>SCP03 i=11 - R-MAC with enhanced features.</summary>
                public const byte I11 = 0x11;

                /// <summary>SCP03 i=20 - R-ENC only.</summary>
                public const byte I20 = 0x20;

                /// <summary>SCP03 i=60 - R-MAC and R-ENC with random card challenge.</summary>
                public const byte I60 = 0x60;

                /// <summary>SCP03 i=70 - R-MAC and R-ENC with pseudo-random card challenge.</summary>
                public const byte I70 = 0x70;

                /// <summary>All valid SCP03 implementation parameters.</summary>
                public static readonly byte[] All = [I00, I10, I11, I20, I60, I70];
            }
        }

        /// <summary>
        /// Common SCP constants used across both SCP02 and SCP03.
        /// </summary>
        [PublicAPI]
        public static class Common
        {
            /// <summary>INITIALIZE UPDATE command INS byte.</summary>
            public const byte INITIALIZE_UPDATE_INS = 0x50;

            /// <summary>EXTERNAL AUTHENTICATE command INS byte.</summary>
            public const byte EXTERNAL_AUTHENTICATE_INS = 0x82;

            /// <summary>Secure messaging CLA bit mask.</summary>
            public const byte SECURE_MESSAGING_CLA_BIT = 0x04;

            /// <summary>Standard CLA byte for GP commands.</summary>
            public const byte STANDARD_CLA = 0x80;

            /// <summary>Secure CLA byte for GP commands (with secure messaging bit).</summary>
            public const byte SECURE_CLA = STANDARD_CLA | SECURE_MESSAGING_CLA_BIT;

            /// <summary>Zero initialization vector size (8 bytes for 3DES, 16 bytes for AES).</summary>
            public static readonly byte[] ZeroIv8 = new byte[8];

            /// <summary>Zero initialization vector size (16 bytes for AES).</summary>
            public static readonly byte[] ZeroIv16 = new byte[16];

            /// <summary>Zero MAC chaining value for SCP02 (8 bytes).</summary>
            public static readonly byte[] ZeroChaining8 = new byte[8];

            /// <summary>Zero MAC chaining value for SCP03 (16 bytes).</summary>
            public static readonly byte[] ZeroChaining16 = new byte[16];

            /// <summary>Cryptogram data size for SCP02 (24 bytes).</summary>
            public const int CRYPTOGRAM_DATA_SIZE_24 = 24;

            /// <summary>IV counter offset in SCP03 (12 bytes).</summary>
            public const int IV_COUNTER_OFFSET = 12;

            /// <summary>ISO 7816-4 padding byte (0x80).</summary>
            public const byte ISO7816_PADDING_BYTE = 0x80;

            /// <summary>MAC truncation size for both SCP02 and SCP03 (8 bytes).</summary>
            public const int MAC_TRUNCATION_SIZE = 8;

            /// <summary>AES-CMAC block size in bits (128 bits = 16 bytes).</summary>
            public const int AES_CMAC_BLOCK_BITS = 128;

            /// <summary>Cryptogram data extraction offset for SCP02 (8 bytes).</summary>
            public const int CRYPTOGRAM_EXTRACTION_OFFSET = 8;

            /// <summary>Cryptogram data extraction length for SCP02 (8 bytes).</summary>
            public const int CRYPTOGRAM_EXTRACTION_LENGTH = 8;
        }

        /// <summary>
        /// Status words that affect secure channel processing.
        /// Only success and warning status words receive response security processing.
        /// </summary>
        [PublicAPI]
        public static class StatusWords
        {
            /// <summary>Warning status word mask (62xx).</summary>
            public const ushort WARNING_MASK = 0xFF00;

            /// <summary>Warning status word value (6200).</summary>
            public const ushort WARNING62 = 0x6200;

            /// <summary>Warning status word value (6300).</summary>
            public const ushort WARNING63 = 0x6300;

            /// <summary>
            /// Checks if a status word should receive response security processing.
            /// Per GP specification, only success and warning responses are secured.
            /// </summary>
            /// <param name="statusWord">The status word to check.</param>
            /// <returns>True if response security should be applied.</returns>
            public static bool ShouldApplyResponseSecurity(ushort statusWord) =>
                statusWord == Constants.StatusWords.Success
                || (statusWord & WARNING_MASK) == WARNING62
                || (statusWord & WARNING_MASK) == WARNING63;
        }
    }
}
