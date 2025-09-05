// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
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
            public const byte Standard = 0x00;

            /// <summary>GlobalPlatform CLA for non-secured commands (0x80).</summary>
            public const byte GpStandard = 0x80;

            /// <summary>SCP02/SCP03 secured CLA with MAC (0x84).</summary>
            public const byte Secured = 0x84;

            /// <summary>R-MAC session CLA with secure messaging (0xC0).</summary>
            public const byte RMacSecure = 0xC0;

            /// <summary>R-MAC session CLA with encryption (0xE0).</summary>
            public const byte RMacEncrypted = 0xE0;
        }

        /// <summary>
        /// APDU instruction bytes for GlobalPlatform commands.
        /// Reference: GP Card Specification v2.3.1, Section 11
        /// </summary>
        public static class Ins
        {
            /// <summary>SELECT instruction per ISO 7816-4 (0xA4).</summary>
            public const byte Select = 0xA4;

            /// <summary>INITIALIZE UPDATE instruction per GP Card Specification (0x50).</summary>
            public const byte InitializeUpdate = 0x50;

            /// <summary>EXTERNAL AUTHENTICATE instruction per GP Card Specification (0x82).</summary>
            public const byte ExternalAuthenticate = 0x82;

            /// <summary>GET DATA instruction per ISO 7816-4 (0xCA).</summary>
            public const byte GetData = 0xCA;

            /// <summary>GET STATUS instruction per GP Card Specification (0xF2).</summary>
            public const byte GetStatus = 0xF2;

            /// <summary>INSTALL instruction per GP Card Specification (0xE6).</summary>
            public const byte Install = 0xE6;

            /// <summary>LOAD instruction per GP Card Specification (0xE8).</summary>
            public const byte Load = 0xE8;

            /// <summary>DELETE instruction per GP Card Specification (0xE4).</summary>
            public const byte Delete = 0xE4;

            /// <summary>PUT KEY instruction per GP Card Specification (0xD8).</summary>
            public const byte PutKey = 0xD8;

            /// <summary>SET STATUS instruction per GP Card Specification (0xF0).</summary>
            public const byte SetStatus = 0xF0;

            /// <summary>STORE DATA instruction per GP Card Specification (0xE2).</summary>
            public const byte StoreData = 0xE2;

            /// <summary>GET RESPONSE instruction per ISO 7816-4 (0xC0).</summary>
            public const byte GetResponse = 0xC0;

            /// <summary>BEGIN R-MAC SESSION instruction per GP Card Specification (0x7A).</summary>
            public const byte BeginRMacSession = 0x7A;

            /// <summary>END R-MAC SESSION instruction per GP Card Specification (0x78).</summary>
            public const byte EndRMacSession = 0x78;
        }

        /// <summary>
        /// ISO 7816-4 and GlobalPlatform status words.
        /// Reference: ISO 7816-4, GP Card Specification v2.3.1
        /// </summary>
        public static class StatusWords
        {
            /// <summary>Success status word (0x9000).</summary>
            public const ushort Success = 0x9000;

            /// <summary>More data available - GET RESPONSE required (0x61XX).</summary>
            public const byte MoreData = 0x61;

            /// <summary>Proprietary response continuation available (0x9FXX).</summary>
            public const byte ProprietaryContinuation = 0x9F;

            /// <summary>Warning - card state unchanged (0x62XX).</summary>
            public const byte WarningUnchanged = 0x62;

            /// <summary>Warning - card state changed (0x63XX).</summary>
            public const byte WarningChanged = 0x63;

            /// <summary>Execution error - card state unchanged (0x64XX).</summary>
            public const byte ExecutionError = 0x64;

            /// <summary>Execution error - card state changed (0x65XX).</summary>
            public const byte ExecutionErrorChanged = 0x65;

            /// <summary>Security-related error (0x69XX).</summary>
            public const byte SecurityError = 0x69;

            /// <summary>Wrong parameters P1 P2 (0x6AXX).</summary>
            public const byte WrongParameters = 0x6A;

            /// <summary>Wrong instruction parameters (0x6BXX).</summary>
            public const byte WrongInstruction = 0x6B;

            /// <summary>Class not supported (0x6EXX).</summary>
            public const byte ClassNotSupported = 0x6E;

            /// <summary>Instruction not supported (0x6DXX).</summary>
            public const byte InstructionNotSupported = 0x6D;
        }

        /// <summary>
        /// Secure Channel Protocol identifiers and versions.
        /// Reference: GP Secure Channel Protocol 02, GP Secure Channel Protocol 03
        /// </summary>
        public static class Protocols
        {
            /// <summary>SCP02 protocol identifier (0x02).</summary>
            public const byte Scp02 = 0x02;

            /// <summary>SCP03 protocol identifier (0x03).</summary>
            public const byte Scp03 = 0x03;

            /// <summary>Default key version number (0x00).</summary>
            public const byte DefaultKeyVersion = 0x00;
        }

        /// <summary>
        /// Security levels for Secure Channel Protocol.
        /// Reference: GP SCP02, GP SCP03 specifications
        /// </summary>
        public static class SecurityLevels
        {
            /// <summary>No security - plain commands (0x00).</summary>
            public const byte None = 0x00;

            /// <summary>MAC only - command integrity (0x01).</summary>
            public const byte MacOnly = 0x01;

            /// <summary>MAC + ENC - command integrity and confidentiality (0x03).</summary>
            public const byte MacAndEncryption = 0x03;

            /// <summary>Full security - C-MAC + C-ENC + R-MAC (0x33).</summary>
            public const byte Full = 0x33;
        }

        /// <summary>
        /// Application lifecycle states per GlobalPlatform specification.
        /// Reference: GP Card Specification v2.3.1, Section 3.2
        /// </summary>
        public static class LifecycleStates
        {
            /// <summary>LOADED state - application installed but not selectable (0x01).</summary>
            public const byte Loaded = 0x01;

            /// <summary>INSTALLED state - application selectable but not active (0x03).</summary>
            public const byte Installed = 0x03;

            /// <summary>SELECTABLE state - application can be selected and executed (0x07).</summary>
            public const byte Selectable = 0x07;

            /// <summary>LOCKED state - application locked and non-functional (0x83).</summary>
            public const byte Locked = 0x83;
        }

        /// <summary>
        /// Privilege bits for GlobalPlatform applications and security domains.
        /// Reference: GP Card Specification v2.3.1, Section 5.1.1
        /// </summary>
        public static class Privileges
        {
            /// <summary>Security Domain privilege (0x80).</summary>
            public const byte SecurityDomain = 0x80;

            /// <summary>DAP Verification privilege (0x40).</summary>
            public const byte DapVerification = 0x40;

            /// <summary>Delegated Management privilege (0x20).</summary>
            public const byte DelegatedManagement = 0x20;

            /// <summary>Card Lock privilege (0x10).</summary>
            public const byte CardLock = 0x10;

            /// <summary>Card Terminate privilege (0x08).</summary>
            public const byte CardTerminate = 0x08;

            /// <summary>Card Reset privilege (0x04).</summary>
            public const byte CardReset = 0x04;

            /// <summary>CVM Management privilege (0x02).</summary>
            public const byte CvmManagement = 0x02;

            /// <summary>Mandated DAP Verification privilege (0x01).</summary>
            public const byte MandatedDapVerification = 0x01;
        }

        /// <summary>
        /// Cryptographic constants for GlobalPlatform operations.
        /// Reference: GP SCP02, GP SCP03 specifications
        /// </summary>
        public static class Crypto
        {
            /// <summary>AES block size in bytes (16).</summary>
            public const int AesBlockSize = 16;

            /// <summary>3DES block size in bytes (8).</summary>
            public const int TripleDesBlockSize = 8;

            /// <summary>Single DES block size in bytes (8).</summary>
            public const int DesBlockSize = 8;

            /// <summary>AES key size for SCP03 in bytes (16).</summary>
            public const int AesKeySize = 16;

            /// <summary>3DES key size for SCP02 (2-key) in bytes (16).</summary>
            public const int TripleDesKeySize2Key = 16;

            /// <summary>3DES key size for SCP02 (3-key) in bytes (24).</summary>
            public const int TripleDesKeySize3Key = 24;

            /// <summary>Single DES key size in bytes (8).</summary>
            public const int DesKeySize = 8;

            /// <summary>MAC size for SCP protocols in bytes (8).</summary>
            public const int MacSize = 8;

            /// <summary>Cryptogram size for SCP protocols in bytes (8).</summary>
            public const int CryptogramSize = 8;

            /// <summary>Host challenge size in bytes (8).</summary>
            public const int HostChallengeSize = 8;

            /// <summary>Card challenge size for SCP03 in bytes (8).</summary>
            public const int CardChallengeSizeScp03 = 8;

            /// <summary>Card challenge size for SCP02 in bytes (6).</summary>
            public const int CardChallengeSizeScp02 = 6;

            /// <summary>Sequence counter size for SCP03 in bytes (16).</summary>
            public const int SequenceCounterSizeScp03 = 16;

            /// <summary>Sequence counter size for SCP02 in bytes (2).</summary>
            public const int SequenceCounterSizeScp02 = 2;
        }

        /// <summary>
        /// Key derivation constants for Secure Channel Protocol.
        /// Reference: GP SCP02 specification, Section 4.1.5
        /// </summary>
        public static class KeyDerivation
        {
            /// <summary>S-ENC key derivation constant for SCP02 (0x0182).</summary>
            public const ushort Scp02SEnc = 0x0182;

            /// <summary>S-MAC key derivation constant for SCP02 (0x0101).</summary>
            public const ushort Scp02SMac = 0x0101;

            /// <summary>S-DEK key derivation constant for SCP02 (0x0181).</summary>
            public const ushort Scp02SDek = 0x0181;
        }

        /// <summary>
        /// INSTALL command parameters.
        /// Reference: GP Card Specification v2.3.1, Section 11.5
        /// </summary>
        public static class InstallParameters
        {
            /// <summary>Install for load P1 parameter (0x02).</summary>
            public const byte InstallForLoad = 0x02;

            /// <summary>Install for install P1 parameter (0x0C).</summary>
            public const byte InstallForInstall = 0x0C;

            /// <summary>Make selectable P1 parameter (0x08).</summary>
            public const byte MakeSelectable = 0x08;
        }

        /// <summary>
        /// TLV tags used in GlobalPlatform data objects.
        /// Reference: GP Card Specification v2.3.1, Appendix E
        /// </summary>
        public static class Tags
        {
            /// <summary>Card capabilities data object tag (0x67).</summary>
            public const byte CardCapabilities = 0x67;

            /// <summary>Key information template tag (0xE0).</summary>
            public const byte KeyInformation = 0xE0;

            /// <summary>Security domain data tag (0x73).</summary>
            public const byte SecurityDomain = 0x73;

            /// <summary>Card production lifecycle data (CPLC) tag (0x9F7F).</summary>
            public const ushort CplcData = 0x9F7F;

            /// <summary>Issuer identification number tag (0x42).</summary>
            public const byte IssuerId = 0x42;

            /// <summary>Application identifier (AID) tag (0x4F).</summary>
            public const byte ApplicationId = 0x4F;
        }

        /// <summary>
        /// Expected response lengths for GlobalPlatform commands.
        /// Reference: GP Card Specification v2.3.1
        /// </summary>
        public static class ResponseLengths
        {
            /// <summary>Expected INITIALIZE UPDATE response length for SCP02 (28 bytes).</summary>
            public const int InitializeUpdateScp02 = 28;

            /// <summary>Expected INITIALIZE UPDATE response length for SCP03 (32 bytes).</summary>
            public const int InitializeUpdateScp03 = 32;

            /// <summary>EXTERNAL AUTHENTICATE command data length (8 bytes).</summary>
            public const int ExternalAuthenticate = 8;

            /// <summary>CPLC data length (42 bytes).</summary>
            public const int CplcData = 42;
        }

        /// <summary>
        /// APDU format constants and limits.
        /// Reference: ISO 7816-4
        /// </summary>
        public static class ApduLimits
        {
            /// <summary>Maximum APDU data length for short format (255 bytes).</summary>
            public const int MaxShortDataLength = 255;

            /// <summary>Default load block size for LOAD commands (245 bytes).</summary>
            public const int DefaultLoadBlockSize = 245;
        }

        /// <summary>
        /// Padding constants for cryptographic operations.
        /// Reference: ISO 7816-4, PKCS#7
        /// </summary>
        public static class Padding
        {
            /// <summary>ISO 7816-4 padding start byte (0x80).</summary>
            public const byte Iso7816Start = 0x80;

            /// <summary>ISO 7816-4 padding continuation byte (0x00).</summary>
            public const byte Iso7816Continuation = 0x00;

            /// <summary>PKCS#7 padding maximum value (0xFF).</summary>
            public const byte Pkcs7Max = 0xFF;
        }

        /// <summary>
        /// Common byte values used throughout GlobalPlatform operations.
        /// </summary>
        public static class CommonBytes
        {
            /// <summary>Zero byte constant (0x00).</summary>
            public const byte Zero = 0x00;

            /// <summary>Maximum byte value (0xFF).</summary>
            public const byte Max = 0xFF;

            /// <summary>Bit mask for lower nibble (0x0F).</summary>
            public const byte LowerNibbleMask = 0x0F;

            /// <summary>Bit mask for upper nibble (0xF0).</summary>
            public const byte UpperNibbleMask = 0xF0;
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
            public static readonly byte[] TestApplication = Convert.FromHexString("A000000001020304");

            /// <summary>OpenFIPS201 applet AID.</summary>
            public static readonly byte[] OpenFips201 = Convert.FromHexString("A000000308000010000100");

            /// <summary>OpenFIPS201 package AID.</summary>
            public static readonly byte[] OpenFips201Package = Convert.FromHexString("A0000003080000100001");
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
            public static readonly byte[] StandardTestKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
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
            /// Receipt generation privilege (bit 0 of byte 3).
            /// </summary>
            ReceiptGeneration = 0x00010000,

            /// <summary>
            /// Ciphered Load File Data Block privilege (bit 1 of byte 3).
            /// </summary>
            CipheredLoadFileDataBlock = 0x00020000,

            /// <summary>
            /// Contactless activation privilege (bit 2 of byte 3).
            /// </summary>
            ContactlessActivation = 0x00040000,

            /// <summary>
            /// Contactless self-activation privilege (bit 3 of byte 3).
            /// </summary>
            ContactlessSelfActivation = 0x00080000,
        }
    }
}
