// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using JetBrains.Annotations;

namespace Gp4Net.Constants;

public static partial class Constants
{
    /// <summary>
    /// APDU format constants and specifications as defined by ISO 7816-4.
    /// Consolidates ALL APDU-related constants from across the codebase.
    /// Reference: ISO 7816-4 - Organization, security and commands for interchange
    /// </summary>
    [PublicAPI]
    public static class Apdu
    {
        /// <summary>
        /// APDU format length constants and limits.
        /// Reference: ISO 7816-4, Section 5.1
        /// </summary>
        public static class Formats
        {
            /// <summary>Maximum length for Lc field in short APDU format (255 bytes).</summary>
            public const int MaxShortLengthLc = 255;

            /// <summary>Maximum length for Le field in short APDU format (256 bytes).</summary>
            public const int MaxShortLengthLe = 256;

            /// <summary>Maximum length for extended APDU format (65536 bytes).</summary>
            public const int MaxExtendedLength = 65536;

            /// <summary>Maximum data length for single APDU in extended format (65535 bytes).</summary>
            public const int MaxApduDataLength = 65535;

            /// <summary>Standard APDU header length - CLA, INS, P1, P2 (4 bytes).</summary>
            public const int ApduHeaderLength = 4;

            /// <summary>Length field size for short APDU format (1 byte).</summary>
            public const int ShortApduLcLength = 1;

            /// <summary>Length field size for extended APDU format (3 bytes).</summary>
            public const int ExtendedApduLcLength = 3;

            /// <summary>Minimum APDU length - header only (4 bytes).</summary>
            public const int MinApduLength = ApduHeaderLength;

            /// <summary>Threshold for switching from short to extended APDU format (256 bytes).</summary>
            public const int ExtendedLengthThreshold = 256;
        }

        /// <summary>
        /// Command chaining and response handling limits.
        /// Protects against malicious cards and memory exhaustion attacks.
        /// Reference: ISO 7816-4, Section 5.1.3
        /// </summary>
        public static class ChainLimits
        {
            /// <summary>Maximum number of GET RESPONSE chains to prevent infinite loops (128).</summary>
            public const int MaxResponseChainLength = 128;

            /// <summary>Maximum total accumulated response size across all chains (1MB).</summary>
            public const int MaxTotalResponseSize = 1048576;

            /// <summary>Default block size for LOAD command operations (245 bytes).</summary>
            public const int DefaultLoadBlockSize = 245;
        }

        /// <summary>
        /// Well-known identifiers for card types and standard applications.
        /// Reference: Various card manufacturer specifications and ISO 7816-4
        /// </summary>
        public static class WellKnownIdentifiers
        {
            /// <summary>
            /// Standard GlobalPlatform ISD (Issuer Security Domain) AID.
            /// Used by most GP-compliant cards as the default security domain.
            /// Reference: GP Card Specification v2.3.1
            /// </summary>
            public static readonly byte[] StandardGpIsdAid = Convert.FromHexString("A000000151000000");

            /// <summary>
            /// NXP P71 card ATR (Answer To Reset) sequence.
            /// Identifies NXP P71D321 SmartMX3 cards with JavaCard OS.
            /// Reference: NXP P71 Technical Specification
            /// </summary>
            public static readonly byte[] NxpP71Atr = Convert.FromHexString("3BD518FF8191FE1FC38073C821100A");

            /// <summary>
            /// Generic JavaCard ATR for testing purposes.
            /// Minimal ATR suitable for basic card emulation scenarios.
            /// Reference: JavaCard Runtime Environment Specification
            /// </summary>
            public static readonly byte[] GenericJavaCardAtr = Convert.FromHexString("3B00");
        }

        /// <summary>
        /// APDU class byte definitions for different command categories.
        /// Reference: ISO 7816-4, Section 5.4.1
        /// </summary>
        public static class Classes
        {
            /// <summary>Standard ISO 7816-4 class for basic interindustry commands (0x00).</summary>
            public const byte Standard = 0x00;

            /// <summary>First interindustry class (0x00-0x0F range).</summary>
            public const byte InterIndustryFirst = 0x00;

            /// <summary>Last interindustry class (0x00-0x0F range).</summary>
            public const byte InterIndustryLast = 0x0F;

            /// <summary>First proprietary class (0x80-0xFF range).</summary>
            public const byte ProprietaryFirst = 0x80;

            /// <summary>Last proprietary class (0x80-0xFF range).</summary>
            public const byte ProprietaryLast = 0xFF;
        }

        /// <summary>
        /// Standard instruction bytes as defined by ISO 7816-4.
        /// Reference: ISO 7816-4, Section 6
        /// </summary>
        public static class Instructions
        {
            /// <summary>SELECT instruction for file/application selection (0xA4).</summary>
            public const byte Select = 0xA4;

            /// <summary>READ BINARY instruction for transparent file reading (0xB0).</summary>
            public const byte ReadBinary = 0xB0;

            /// <summary>WRITE BINARY instruction for transparent file writing (0xD0).</summary>
            public const byte WriteBinary = 0xD0;

            /// <summary>READ RECORD instruction for record file reading (0xB2).</summary>
            public const byte ReadRecord = 0xB2;

            /// <summary>WRITE RECORD instruction for record file writing (0xD2).</summary>
            public const byte WriteRecord = 0xD2;

            /// <summary>GET DATA instruction for structured data retrieval (0xCA).</summary>
            public const byte GetData = 0xCA;

            /// <summary>PUT DATA instruction for structured data storage (0xDA).</summary>
            public const byte PutData = 0xDA;

            /// <summary>VERIFY instruction for PIN/password verification (0x20).</summary>
            public const byte Verify = 0x20;

            /// <summary>CHANGE REFERENCE DATA instruction for PIN/password change (0x24).</summary>
            public const byte ChangeReferenceData = 0x24;

            /// <summary>RESET RETRY COUNTER instruction (0x2C).</summary>
            public const byte ResetRetryCounter = 0x2C;

            /// <summary>GET CHALLENGE instruction for random number generation (0x84).</summary>
            public const byte GetChallenge = 0x84;

            /// <summary>INTERNAL AUTHENTICATE instruction (0x88).</summary>
            public const byte InternalAuthenticate = 0x88;

            /// <summary>EXTERNAL AUTHENTICATE instruction (0x82).</summary>
            public const byte ExternalAuthenticate = 0x82;

            /// <summary>GET RESPONSE instruction for additional response data (0xC0).</summary>
            public const byte GetResponse = 0xC0;

            /// <summary>ENVELOPE instruction for command encapsulation (0xC2).</summary>
            public const byte Envelope = 0xC2;

            /// <summary>MANAGE CHANNEL instruction for logical channel management (0x70).</summary>
            public const byte ManageChannel = 0x70;
        }

        /// <summary>
        /// SELECT command P1 parameter values.
        /// Reference: ISO 7816-4, Section 6.9.1
        /// </summary>
        public static class SelectP1
        {
            /// <summary>Select MF, DF or EF by file identifier (0x00).</summary>
            public const byte SelectByFileId = 0x00;

            /// <summary>Select child DF by file identifier (0x01).</summary>
            public const byte SelectChildDf = 0x01;

            /// <summary>Select EF under current DF by file identifier (0x02).</summary>
            public const byte SelectEfUnderCurrentDf = 0x02;

            /// <summary>Select parent DF of current DF (0x03).</summary>
            public const byte SelectParentDf = 0x03;

            /// <summary>Select by DF name (AID) (0x04).</summary>
            public const byte SelectByName = 0x04;

            /// <summary>Select from MF by path (0x08).</summary>
            public const byte SelectFromMfByPath = 0x08;

            /// <summary>Select from current DF by path (0x09).</summary>
            public const byte SelectFromCurrentDfByPath = 0x09;
        }

        /// <summary>
        /// SELECT command P2 parameter values.
        /// Reference: ISO 7816-4, Section 6.9.2
        /// </summary>
        public static class SelectP2
        {
            /// <summary>First record of file (0x00).</summary>
            public const byte FirstRecord = 0x00;

            /// <summary>Last record of file (0x01).</summary>
            public const byte LastRecord = 0x01;

            /// <summary>Next record of file (0x02).</summary>
            public const byte NextRecord = 0x02;

            /// <summary>Previous record of file (0x03).</summary>
            public const byte PreviousRecord = 0x03;

            /// <summary>Return FCI template (0x00).</summary>
            public const byte ReturnFci = 0x00;

            /// <summary>Return FCP template (0x04).</summary>
            public const byte ReturnFcp = 0x04;

            /// <summary>Return FMD template (0x08).</summary>
            public const byte ReturnFmd = 0x08;

            /// <summary>No response data (0x0C).</summary>
            public const byte NoResponseData = 0x0C;
        }
    }
}