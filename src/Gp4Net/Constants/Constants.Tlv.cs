// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants;

public static partial class Constants
{
    /// <summary>
    /// TLV (Tag-Length-Value) parsing constants and tag definitions.
    /// Consolidates ALL TLV-related constants from across the codebase.
    /// Reference: ISO 8825-1 (ASN.1 BER), ISO 7816-4, GlobalPlatform specifications
    /// </summary>
    [PublicAPI]
    public static class Tlv
    {
        /// <summary>
        /// TLV parsing constants as defined by ISO 8825-1 (ASN.1 BER).
        /// Reference: ISO 8825-1 - ASN.1 Basic Encoding Rules
        /// </summary>
        public static class Parsing
        {
            /// <summary>Mask to check if tag requires multiple bytes (tag &amp; 0x1F == 0x1F).</summary>
            public const byte MultiByteTagMask = 0x1F;

            /// <summary>Mask to check if length is in long form (first byte &amp; 0x80 != 0).</summary>
            public const byte LongFormLengthMask = 0x80;

            /// <summary>Mask to get number of length bytes in long form (first byte &amp; 0x7F).</summary>
            public const byte LengthBytesMask = 0x7F;

            /// <summary>Mask to check if tag has more bytes following (byte &amp; 0x80 != 0).</summary>
            public const byte SubsequentTagByteMask = 0x80;

            /// <summary>Maximum length that can be encoded in short form (127 bytes).</summary>
            public const int MaxShortFormLength = 127;

            /// <summary>Maximum number of length bytes in long form (4 bytes).</summary>
            public const int MaxLongFormLengthBytes = 4;

            /// <summary>Indefinite length marker (0x80 in length field).</summary>
            public const byte IndefiniteLengthMarker = 0x80;

            /// <summary>End-of-contents octets for indefinite length (0x00 0x00).</summary>
            public static readonly byte[] EndOfContents = [0x00, 0x00];
        }


        /// <summary>
        /// ISO 7816-4 standard TLV tags for file control information.
        /// Reference: ISO 7816-4, Section 5.3.3
        /// </summary>
        public static class Iso7816Tags
        {
            /// <summary>FCI (File Control Information) template tag (0x6F).</summary>
            public const ushort FciTemplate = 0x6F;

            /// <summary>DF (Dedicated File) name tag (0x84).</summary>
            public const byte DfName = 0x84;

            /// <summary>Application label tag (0x50).</summary>
            public const byte ApplicationLabel = 0x50;

            /// <summary>Application priority indicator tag (0x87).</summary>
            public const byte ApplicationPriorityIndicator = 0x87;

            /// <summary>FCI proprietary template tag (0xA5).</summary>
            public const byte FciProprietaryTemplate = 0xA5;

            /// <summary>FCI issuer discretionary data tag (0xBF0C).</summary>
            public const ushort FciIssuerDiscretionaryData = 0xBF0C;

            /// <summary>Application identifier (AID) tag (0x4F).</summary>
            public const byte ApplicationIdentifier = 0x4F;

            /// <summary>Life cycle state tag (0x9F70).</summary>
            public const ushort LifeCycleState = 0x9F70;
        }

        /// <summary>
        /// GlobalPlatform-specific TLV tags.
        /// Reference: GP Card Specification v2.3.1, Appendix E
        /// </summary>
        public static class GlobalPlatformTags
        {
            /// <summary>CAP data TLV tag for LOAD command (0xC4).</summary>
            public const byte CapDataTlvTag = 0xC4;

            /// <summary>Security domain privileges tag (0xC5).</summary>
            public const byte SecurityDomainPrivileges = 0xC5;

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
        }

        /// <summary>
        /// EMV payment application TLV tags.
        /// Reference: EMV Book 3 - Application Specification
        /// </summary>
        public static class EmvTags
        {
            /// <summary>PDOL (Processing Options Data Object List) tag (0x9F38).</summary>
            public const ushort Pdol = 0x9F38;

            /// <summary>Application effective date tag (0x5F25).</summary>
            public const ushort ApplicationEffectiveDate = 0x5F25;

            /// <summary>Application expiration date tag (0x5F24).</summary>
            public const ushort ApplicationExpirationDate = 0x5F24;

            /// <summary>Application version number tag (0x9F08).</summary>
            public const ushort ApplicationVersionNumber = 0x9F08;

            /// <summary>Application usage control tag (0x9F07).</summary>
            public const ushort ApplicationUsageControl = 0x9F07;

            /// <summary>Issuer country code tag (0x5F28).</summary>
            public const ushort IssuerCountryCode = 0x5F28;

            /// <summary>Service code tag (0x5F30).</summary>
            public const ushort ServiceCode = 0x5F30;
        }

        /// <summary>
        /// Custom application-specific TLV tags used internally.
        /// These tags are not part of any standard but used for internal data management.
        /// </summary>
        public static class CustomTags
        {
            /// <summary>Load context data tag for internal card state management (0xFFFF).</summary>
            public const ushort LoadContext = 0xFFFF;

            /// <summary>Extended application data tag (0xFFE0).</summary>
            public const ushort ExtendedApplicationData = 0xFFE0;

            /// <summary>Internal state management tag (0xFFE1).</summary>
            public const ushort InternalStateManagement = 0xFFE1;

            /// <summary>Debug information tag (0xFFE2).</summary>
            public const ushort DebugInformation = 0xFFE2;
        }

        /// <summary>
        /// ASN.1 primitive tag definitions for common data types.
        /// Reference: ISO 8825-1, Section 8.1.2
        /// </summary>
        public static class Asn1PrimitiveTags
        {
            /// <summary>BOOLEAN tag (0x01).</summary>
            public const byte Boolean = 0x01;

            /// <summary>INTEGER tag (0x02).</summary>
            public const byte Integer = 0x02;

            /// <summary>BIT STRING tag (0x03).</summary>
            public const byte BitString = 0x03;

            /// <summary>OCTET STRING tag (0x04).</summary>
            public const byte OctetString = 0x04;

            /// <summary>NULL tag (0x05).</summary>
            public const byte Null = 0x05;

            /// <summary>OBJECT IDENTIFIER tag (0x06).</summary>
            public const byte ObjectIdentifier = 0x06;

            /// <summary>UTF8String tag (0x0C).</summary>
            public const byte Utf8String = 0x0C;

            /// <summary>SEQUENCE tag (0x30).</summary>
            public const byte Sequence = 0x30;

            /// <summary>SET tag (0x31).</summary>
            public const byte Set = 0x31;

            /// <summary>PrintableString tag (0x13).</summary>
            public const byte PrintableString = 0x13;

            /// <summary>IA5String tag (0x16).</summary>
            public const byte Ia5String = 0x16;

            /// <summary>UTCTime tag (0x17).</summary>
            public const byte UtcTime = 0x17;

            /// <summary>GeneralizedTime tag (0x18).</summary>
            public const byte GeneralizedTime = 0x18;
        }

        /// <summary>
        /// Context-specific tag class markers.
        /// Reference: ISO 8825-1, Section 8.1.2
        /// </summary>
        public static class ContextSpecific
        {
            /// <summary>Context-specific class mask (0x80).</summary>
            public const byte ClassMask = 0x80;

            /// <summary>Context-specific constructed mask (0xA0).</summary>
            public const byte ConstructedMask = 0xA0;

            /// <summary>Context-specific tag 0 primitive (0x80).</summary>
            public const byte Tag0Primitive = 0x80;

            /// <summary>Context-specific tag 0 constructed (0xA0).</summary>
            public const byte Tag0Constructed = 0xA0;

            /// <summary>Context-specific tag 1 primitive (0x81).</summary>
            public const byte Tag1Primitive = 0x81;

            /// <summary>Context-specific tag 1 constructed (0xA1).</summary>
            public const byte Tag1Constructed = 0xA1;

            /// <summary>Context-specific tag 2 primitive (0x82).</summary>
            public const byte Tag2Primitive = 0x82;

            /// <summary>Context-specific tag 2 constructed (0xA2).</summary>
            public const byte Tag2Constructed = 0xA2;
        }
    }
}