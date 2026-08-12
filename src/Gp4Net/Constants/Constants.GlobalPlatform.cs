// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Immutable;
using JetBrains.Annotations;

namespace Gp4Net.Constants;

public static partial class Constants
{
    /// <summary>
    /// GlobalPlatform card specification constants.
    /// References: GP Card Specification v2.2, GP Card Specification v2.3.1
    /// </summary>
    [PublicAPI]
    public static class GlobalPlatform
    {
        /// <summary>
        /// APDU class bytes for GlobalPlatform commands.
        /// Reference: GP Card Specification v2.3.1, Section 11.1.1
        /// </summary>
        public static class Cla
        {
            /// <summary>Standard ISO 7816-4 CLA for non-secured commands (0x00).</summary>
            public const byte STANDARD = 0x00;

            /// <summary>GlobalPlatform CLA for non-secured commands (0x80).</summary>
            public const byte GP_STANDARD = 0x80;

            /// <summary>SCP02/SCP03 secured CLA with MAC (0x84).</summary>
            public const byte SECURED = 0x84;

            /// <summary>R-MAC session CLA with secure messaging (0xC0).</summary>
            public const byte R_MAC_SECURE = 0xC0;

            /// <summary>R-MAC session CLA with encryption (0xE0).</summary>
            public const byte R_MAC_ENCRYPTED = 0xE0;
        }

        /// <summary>
        /// APDU instruction bytes for GlobalPlatform-specific commands.
        /// Reference: GP Card Specification v2.3.1, Section 11
        /// NOTE: ISO 7816-4 standard instructions (SELECT, GET_DATA, etc.) are defined in Apdu.Instructions
        /// </summary>
        public static class Ins
        {
            // ISO 7816-4 instructions are in Apdu.Instructions - use those for:
            // - SELECT (0xA4) → Apdu.Instructions.SELECT
            // - EXTERNAL_AUTHENTICATE (0x82) → Apdu.Instructions.EXTERNAL_AUTHENTICATE
            // - GET_DATA (0xCA) → Apdu.Instructions.GET_DATA
            // - GET_RESPONSE (0xC0) → Apdu.Instructions.GET_RESPONSE
            // - MANAGE_CHANNEL (0x70) → Apdu.Instructions.MANAGE_CHANNEL

            /// <summary>INITIALIZE UPDATE instruction per GP Card Specification (0x50).</summary>
            public const byte INITIALIZE_UPDATE = 0x50;

            /// <summary>GET STATUS instruction per GP Card Specification (0xF2).</summary>
            public const byte GET_STATUS = 0xF2;

            /// <summary>INSTALL instruction per GP Card Specification (0xE6).</summary>
            public const byte INSTALL = 0xE6;

            /// <summary>LOAD instruction per GP Card Specification (0xE8).</summary>
            public const byte LOAD = 0xE8;

            /// <summary>DELETE instruction per GP Card Specification (0xE4).</summary>
            public const byte DELETE = 0xE4;

            /// <summary>PUT KEY instruction per GP Card Specification (0xD8).</summary>
            public const byte PUT_KEY = 0xD8;

            /// <summary>SET STATUS instruction per GP Card Specification (0xF0).</summary>
            public const byte SET_STATUS = 0xF0;

            /// <summary>STORE DATA instruction per GP Card Specification (0xE2).</summary>
            public const byte STORE_DATA = 0xE2;

            /// <summary>BEGIN R-MAC SESSION instruction per GP Card Specification (0x7A).</summary>
            public const byte BEGIN_R_MAC_SESSION = 0x7A;

            /// <summary>END R-MAC SESSION instruction per GP Card Specification (0x78).</summary>
            public const byte END_R_MAC_SESSION = 0x78;
        }

        /// <summary>
        /// ISO 7816-4 and GlobalPlatform status words.
        /// Reference: ISO 7816-4, GP Card Specification v2.3.1
        /// </summary>
        public static class StatusWords
        {
            /// <summary>Success status word (0x9000).</summary>
            public const ushort SUCCESS = 0x9000;

            /// <summary>More data available - GET RESPONSE required (0x61XX).</summary>
            public const byte MORE_DATA = 0x61;

            /// <summary>Proprietary response continuation available (0x9FXX).</summary>
            public const byte PROPRIETARY_CONTINUATION = 0x9F;

            /// <summary>Warning - card state unchanged (0x62XX).</summary>
            public const byte WARNING_UNCHANGED = 0x62;

            /// <summary>Warning - card state changed (0x63XX).</summary>
            public const byte WARNING_CHANGED = 0x63;

            /// <summary>Execution error - card state unchanged (0x64XX).</summary>
            public const byte EXECUTION_ERROR = 0x64;

            /// <summary>Execution error - card state changed (0x65XX).</summary>
            public const byte EXECUTION_ERROR_CHANGED = 0x65;

            /// <summary>Security-related error (0x69XX).</summary>
            public const byte SECURITY_ERROR = 0x69;

            /// <summary>Wrong parameters P1 P2 (0x6AXX).</summary>
            public const byte WRONG_PARAMETERS = 0x6A;

            /// <summary>Wrong instruction parameters (0x6BXX).</summary>
            public const byte WRONG_INSTRUCTION = 0x6B;

            /// <summary>Class not supported (0x6EXX).</summary>
            public const byte CLASS_NOT_SUPPORTED = 0x6E;

            /// <summary>Instruction not supported (0x6DXX).</summary>
            public const byte INSTRUCTION_NOT_SUPPORTED = 0x6D;
        }

        /// <summary>
        /// Secure Channel Protocol identifiers and versions.
        /// Reference: GP Secure Channel Protocol 02, GP Secure Channel Protocol 03
        /// </summary>
        public static class Protocols
        {
            /// <summary>SCP02 protocol identifier (0x02).</summary>
            public const byte SCP02 = 0x02;

            /// <summary>SCP03 protocol identifier (0x03).</summary>
            public const byte SCP03 = 0x03;

            /// <summary>Default key version number (0x00).</summary>
            public const byte DEFAULT_KEY_VERSION = 0x00;
        }

        // NOTE: Security level flags are defined once in Gp4Net.Domain.SecurityLevel.
        // This previous duplicate static class was removed to eliminate DRY violations.
        // Reference: GP SCP02, GP SCP03 specifications

        /// <summary>
        /// Application lifecycle states per GlobalPlatform specification.
        /// Reference: GP Card Specification v2.3.1, Section 3.2
        /// </summary>
        public static class LifecycleStates
        {
            /// <summary>LOADED state - application installed but not selectable (0x01).</summary>
            public const byte LOADED = 0x01;

            /// <summary>INSTALLED state - application selectable but not active (0x03).</summary>
            public const byte INSTALLED = 0x03;

            /// <summary>SELECTABLE state - application can be selected and executed (0x07).</summary>
            public const byte SELECTABLE = 0x07;

            /// <summary>LOCKED state - application locked and non-functional (0x83).</summary>
            public const byte LOCKED = 0x83;
        }

        /// <summary>
        /// Privilege bits for GlobalPlatform applications and security domains.
        /// Reference: GP Card Specification v2.3.1, Section 5.1.1
        /// </summary>
        public static class Privileges
        {
            /// <summary>Security Domain privilege (0x80).</summary>
            public const byte SECURITY_DOMAIN = 0x80;

            /// <summary>DAP Verification privilege (0x40).</summary>
            public const byte DAP_VERIFICATION = 0x40;

            /// <summary>Delegated Management privilege (0x20).</summary>
            public const byte DELEGATED_MANAGEMENT = 0x20;

            /// <summary>Card Lock privilege (0x10).</summary>
            public const byte CARD_LOCK = 0x10;

            /// <summary>Card Terminate privilege (0x08).</summary>
            public const byte CARD_TERMINATE = 0x08;

            /// <summary>Card Reset privilege (0x04).</summary>
            public const byte CARD_RESET = 0x04;

            /// <summary>CVM Management privilege (0x02).</summary>
            public const byte CVM_MANAGEMENT = 0x02;

            /// <summary>Mandated DAP Verification privilege (0x01).</summary>
            public const byte MANDATED_DAP_VERIFICATION = 0x01;
        }

        /// <summary>
        /// Cryptographic constants for GlobalPlatform operations.
        /// Reference: GP SCP02, GP SCP03 specifications
        /// </summary>
        public static class Crypto
        {
            /// <summary>AES block size in bytes (16).</summary>
            public const int AES_BLOCK_SIZE = 16;

            /// <summary>3DES block size in bytes (8).</summary>
            public const int TRIPLE_DES_BLOCK_SIZE = 8;

            /// <summary>Single DES block size in bytes (8).</summary>
            public const int DES_BLOCK_SIZE = 8;

            /// <summary>AES key size for SCP03 in bytes (16).</summary>
            public const int AES_KEY_SIZE = 16;

            /// <summary>3DES key size for SCP02 (2-key) in bytes (16).</summary>
            public const int TRIPLE_DES_KEY_SIZE2_KEY = 16;

            /// <summary>3DES key size for SCP02 (3-key) in bytes (24).</summary>
            public const int TRIPLE_DES_KEY_SIZE3_KEY = 24;

            /// <summary>Single DES key size in bytes (8).</summary>
            public const int DES_KEY_SIZE = 8;

            /// <summary>MAC size for SCP protocols in bytes (8).</summary>
            public const int MAC_SIZE = 8;

            /// <summary>Cryptogram size for SCP protocols in bytes (8).</summary>
            public const int CRYPTOGRAM_SIZE = 8;

            /// <summary>Host challenge size in bytes (8).</summary>
            public const int HOST_CHALLENGE_SIZE = 8;

            /// <summary>Card challenge size for SCP03 in bytes (8).</summary>
            public const int CARD_CHALLENGE_SIZE_SCP03 = 8;

            /// <summary>Card challenge size for SCP02 in bytes (6).</summary>
            public const int CARD_CHALLENGE_SIZE_SCP02 = 6;

            /// <summary>Sequence counter size for SCP03 in bytes (16).</summary>
            public const int SEQUENCE_COUNTER_SIZE_SCP03 = 16;

            /// <summary>Sequence counter size for SCP02 in bytes (2).</summary>
            public const int SEQUENCE_COUNTER_SIZE_SCP02 = 2;
        }

        /// <summary>
        /// Key derivation constants for Secure Channel Protocol.
        /// Reference: GP SCP02 specification, Section 4.1.5
        /// </summary>
        public static class KeyDerivation
        {
            /// <summary>S-ENC key derivation constant for SCP02 (0x0182).</summary>
            public const ushort SCP02_S_ENC = 0x0182;

            /// <summary>S-MAC key derivation constant for SCP02 (0x0101).</summary>
            public const ushort SCP02_S_MAC = 0x0101;

            /// <summary>S-DEK key derivation constant for SCP02 (0x0181).</summary>
            public const ushort SCP02_S_DEK = 0x0181;
        }

        /// <summary>
        /// INSTALL command parameters.
        /// Reference: GP Card Specification v2.3.1, Section 11.5
        /// </summary>
        public static class InstallParameters
        {
            /// <summary>Install for load P1 parameter (0x02).</summary>
            public const byte INSTALL_FOR_LOAD = 0x02;

            /// <summary>Install for install P1 parameter (0x0C).</summary>
            public const byte INSTALL_FOR_INSTALL = 0x0C;

            /// <summary>Make selectable P1 parameter (0x08).</summary>
            public const byte MAKE_SELECTABLE = 0x08;
        }

        /// <summary>
        /// TLV tags used in GlobalPlatform data objects.
        /// Reference: GP Card Specification v2.3.1, Appendix E
        /// </summary>
        public static class Tags
        {
            /// <summary>Card capabilities data object tag (0x67).</summary>
            public const byte CARD_CAPABILITIES = 0x67;

            /// <summary>Key information template tag (0xE0).</summary>
            public const byte KEY_INFORMATION = 0xE0;

            /// <summary>Security domain data tag (0x73).</summary>
            public const byte SECURITY_DOMAIN = 0x73;

            /// <summary>Card production lifecycle data (CPLC) tag (0x9F7F).</summary>
            public const ushort CPLC_DATA = 0x9F7F;

            /// <summary>Issuer identification number tag (0x42).</summary>
            public const byte ISSUER_ID = 0x42;

            /// <summary>Application identifier (AID) tag (0x4F).</summary>
            public const byte APPLICATION_ID = 0x4F;

            /// <summary>CAP data TLV tag for LOAD command (0xC4).</summary>
            public const byte CAP_DATA_TLV_TAG = 0xC4;

            /// <summary>Security domain privileges tag (0xC5).</summary>
            public const byte SECURITY_DOMAIN_PRIVILEGES = 0xC5;
        }

        /// <summary>
        /// Expected response lengths for GlobalPlatform commands.
        /// Reference: GP Card Specification v2.3.1
        /// </summary>
        public static class ResponseLengths
        {
            /// <summary>Expected INITIALIZE UPDATE response length for SCP02 (28 bytes).</summary>
            public const int INITIALIZE_UPDATE_SCP02 = 28;

            /// <summary>Expected INITIALIZE UPDATE response length for SCP03 (32 bytes).</summary>
            public const int INITIALIZE_UPDATE_SCP03 = 32;

            /// <summary>EXTERNAL AUTHENTICATE command data length (8 bytes).</summary>
            public const int EXTERNAL_AUTHENTICATE = 8;

            /// <summary>CPLC data length (42 bytes).</summary>
            public const int CPLC_DATA = 42;
        }

        /// <summary>
        /// APDU format constants and limits.
        /// Reference: ISO 7816-4
        /// </summary>
        public static class ApduLimits
        {
            /// <summary>Maximum APDU data length for short format (255 bytes).</summary>
            public const int MAX_SHORT_DATA_LENGTH = 255;

            /// <summary>Default load block size for LOAD commands (245 bytes).</summary>
            public const int DEFAULT_LOAD_BLOCK_SIZE = 245;
        }

        /// <summary>
        /// Padding constants for cryptographic operations.
        /// Reference: ISO 7816-4, PKCS#7
        /// </summary>
        public static class Padding
        {
            /// <summary>ISO 7816-4 padding start byte (0x80).</summary>
            public const byte ISO7816_START = 0x80;

            /// <summary>ISO 7816-4 padding continuation byte (0x00).</summary>
            public const byte ISO7816_CONTINUATION = 0x00;

            /// <summary>PKCS#7 padding maximum value (0xFF).</summary>
            public const byte PKCS7_MAX = 0xFF;
        }

        /// <summary>
        /// Security requirements for GlobalPlatform commands.
        /// Reference: GlobalPlatform Card Specification v2.3.1 Appendix E
        /// </summary>
        public static class SecurityRequirements
        {
            /// <summary>
            /// Commands that never require secure channel establishment per GP specification.
            /// These commands can be executed without an authenticated secure channel.
            /// </summary>
            public static readonly ImmutableHashSet<byte> OpenAccessCommands =
                ImmutableHashSet.Create(
                    Apdu.Instructions.SELECT, // 0xA4 - Application/ISD selection
                    Ins.INITIALIZE_UPDATE, // 0x50 - Start secure channel establishment
                    Apdu.Instructions.EXTERNAL_AUTHENTICATE // 0x82 - Complete secure channel establishment
                );

            /// <summary>
            /// Commands that require Command MAC (C-MAC) security level.
            /// Reference: GP Card Specification v2.3.1 Table E-1
            /// </summary>
            public static readonly ImmutableHashSet<byte> CommandMacRequiredCommands =
                ImmutableHashSet.Create(
                    Ins.INSTALL, // 0xE6 - Application installation/removal
                    Ins.LOAD, // 0xE8 - Load CAP file
                    Ins.DELETE, // 0xE4 - Delete application/package
                    Ins.PUT_KEY, // 0xD8 - Add/update keys
                    Ins.STORE_DATA, // 0xE2 - Store card data
                    Ins.GET_STATUS // 0xF2 - Query application status
                );
        }

        /// <summary>
        /// Common byte values used throughout GlobalPlatform operations.
        /// </summary>
        public static class CommonBytes
        {
            /// <summary>Zero byte constant (0x00).</summary>
            public const byte ZERO = 0x00;

            /// <summary>Maximum byte value (0xFF).</summary>
            public const byte MAX = 0xFF;

            /// <summary>Bit mask for lower nibble (0x0F).</summary>
            public const byte LOWER_NIBBLE_MASK = 0x0F;

            /// <summary>Bit mask for upper nibble (0xF0).</summary>
            public const byte UPPER_NIBBLE_MASK = 0xF0;
        }

        /// <summary>
        /// Well-known Application Identifiers (AIDs) for testing and development.
        /// Reference: GP Test Configuration Guide
        /// </summary>
        public static class Aids
        {
            /// <summary>Standard Issuer Security Domain (ISD) AID.</summary>
            public static readonly byte[] IsdDefault = Convert.FromHexString("A000000003000000");

            /// <summary>Common test application AID.</summary>
            public static readonly byte[] TestApplication = Convert.FromHexString(
                "A000000001020304"
            );

            /// <summary>OpenFIPS201 applet AID.</summary>
            public static readonly byte[] OpenFips201 = Convert.FromHexString(
                "A000000308000010000100"
            );

            /// <summary>OpenFIPS201 package AID.</summary>
            public static readonly byte[] OpenFips201Package = Convert.FromHexString(
                "A0000003080000100001"
            );
        }

        /// <summary>
        /// Standard GlobalPlatform test keys for development and testing.
        /// Reference: GP Test Configuration Guide
        /// </summary>
        public static class TestKeys
        {
            /// <summary>
            /// Standard GlobalPlatform test key (404142434445464748494A4B4C4D4E4F).
            /// Used as ENC, MAC, and DEK keys in test environments.
            /// </summary>
            public static readonly byte[] StandardTestKey = Convert.FromHexString(
                "404142434445464748494A4B4C4D4E4F"
            );
        }

        /// <summary>
        /// R-MAC session parameters for BEGIN and END R-MAC SESSION commands.
        /// Reference: GP Card Specification v2.3.1, Section 11.10
        /// </summary>
        public static class RMacParameters
        {
            /// <summary>P1 parameter for R-MAC only security level (0x10).</summary>
            public const byte P1_RMAC_ONLY = 0x10;

            /// <summary>P1 parameter for R-MAC and encryption security level (0x30).</summary>
            public const byte P1_RMAC_ENCRYPTION = 0x30;

            /// <summary>P2 parameter to begin R-MAC session (0x01).</summary>
            public const byte P2_BEGIN_SESSION = 0x01;

            /// <summary>P2 parameter to end R-MAC session (0x00).</summary>
            public const byte P2_END_SESSION = 0x00;

            /// <summary>P2 parameter to end R-MAC session and return R-MAC (0x03).</summary>
            public const byte P2_END_SESSION_RETURN_RMAC = 0x03;

            /// <summary>P1 parameter for END R-MAC SESSION command (0x00).</summary>
            public const byte P1_END_SESSION = 0x00;
        }

        /// <summary>
        /// GlobalPlatform application lifecycle states.
        /// Reference: GP Card Specification v2.3.1, Section 6.3
        /// </summary>
        public enum LifecycleState : byte
        {
            /// <summary>
            /// Loaded state - application loaded but not installed.
            /// </summary>
            Loaded = 0x01,

            /// <summary>
            /// Installed state - application installed but not selectable.
            /// </summary>
            Installed = 0x03,

            /// <summary>
            /// Selectable state - application can be selected.
            /// </summary>
            Selectable = 0x07,

            /// <summary>
            /// Personalized state - application is personalized.
            /// </summary>
            Personalized = 0x0F,

            /// <summary>
            /// Locked state - application is locked.
            /// </summary>
            Locked = 0x7F,

            /// <summary>
            /// Terminated state - application is terminated.
            /// </summary>
            Terminated = 0xFF,

            /// <summary>
            /// Unknown state.
            /// </summary>
            Unknown = 0x00,
        }

        /// <summary>
        /// GlobalPlatform privileges per GP Card Specification v2.3.1.
        /// Wire format: [Byte1][Byte2][Byte3] maps directly to uint little-endian.
        /// Reference: GP Card Specification v2.3.1, Section 6.6.1 and Tables 11-7, 11-8, 11-9
        /// </summary>
        [Flags]
        public enum Privilege : uint
        {
            /// <summary>
            /// No privileges.
            /// </summary>
            None = 0x00000000,

            // Byte 1 privileges (LSB on wire, bits 7-0)
            /// <summary>
            /// Mandated DAP verification privilege (bit 0 of byte 1).
            /// Only valid when DAP Verification is also set.
            /// </summary>
            MandatedDapVerification = 0x00000001,

            /// <summary>
            /// CVM management privilege (bit 1 of byte 1).
            /// </summary>
            CvmManagement = 0x00000002,

            /// <summary>
            /// Card reset privilege (bit 2 of byte 1).
            /// Previously called "Default Selected".
            /// </summary>
            CardReset = 0x00000004,

            /// <summary>
            /// Card terminate privilege (bit 3 of byte 1).
            /// </summary>
            CardTerminate = 0x00000008,

            /// <summary>
            /// Card lock privilege (bit 4 of byte 1).
            /// </summary>
            CardLock = 0x00000010,

            /// <summary>
            /// Delegated management privilege (bit 5 of byte 1).
            /// Security Domain privilege must also be set.
            /// </summary>
            DelegatedManagement = 0x00000020,

            /// <summary>
            /// DAP verification privilege (bit 6 of byte 1).
            /// Security Domain privilege must also be set.
            /// </summary>
            DapVerification = 0x00000040,

            /// <summary>
            /// Security domain privilege (bit 7 of byte 1).
            /// </summary>
            SecurityDomain = 0x00000080,

            // Byte 2 privileges (middle byte on wire, bits 15-8)
            /// <summary>
            /// Global service privilege (bit 0 of byte 2).
            /// </summary>
            GlobalService = 0x00000100,

            /// <summary>
            /// Final application privilege (bit 1 of byte 2).
            /// </summary>
            FinalApplication = 0x00000200,

            /// <summary>
            /// Global registry privilege (bit 2 of byte 2).
            /// </summary>
            GlobalRegistry = 0x00000400,

            /// <summary>
            /// Global lock privilege (bit 3 of byte 2).
            /// </summary>
            GlobalLock = 0x00000800,

            /// <summary>
            /// Global delete privilege (bit 4 of byte 2).
            /// </summary>
            GlobalDelete = 0x00001000,

            /// <summary>
            /// Token verification privilege (bit 5 of byte 2).
            /// </summary>
            TokenVerification = 0x00002000,

            /// <summary>
            /// Authorized management privilege (bit 6 of byte 2).
            /// Security Domain privilege must also be set.
            /// </summary>
            AuthorizedManagement = 0x00004000,

            /// <summary>
            /// Trusted path privilege (bit 7 of byte 2).
            /// </summary>
            TrustedPath = 0x00008000,

            // Byte 3 privileges (MSB on wire, bits 23-16)
            /// <summary>
            /// Receipt generation privilege (bit 7 of byte 3).
            /// </summary>
            ReceiptGeneration = 0x00800000,

            /// <summary>
            /// Ciphered Load File Data Block privilege (bit 6 of byte 3).
            /// </summary>
            CipheredLoadFileDataBlock = 0x00400000,

            /// <summary>
            /// Contactless activation privilege (bit 5 of byte 3).
            /// </summary>
            ContactlessActivation = 0x00200000,

            /// <summary>
            /// Contactless self-activation privilege (bit 4 of byte 3).
            /// </summary>
            ContactlessSelfActivation = 0x00100000,
        }
    }
}
