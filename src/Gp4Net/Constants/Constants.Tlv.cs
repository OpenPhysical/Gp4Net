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
            public const byte MULTI_BYTE_TAG_MASK = 0x1F;

            /// <summary>Mask to check if length is in long form (first byte &amp; 0x80 != 0).</summary>
            public const byte LONG_FORM_LENGTH_MASK = 0x80;

            /// <summary>Mask to get number of length bytes in long form (first byte &amp; 0x7F).</summary>
            public const byte LENGTH_BYTES_MASK = 0x7F;

            /// <summary>Mask to check if tag has more bytes following (byte &amp; 0x80 != 0).</summary>
            public const byte SUBSEQUENT_TAG_BYTE_MASK = 0x80;

            /// <summary>Maximum length that can be encoded in short form (127 bytes).</summary>
            public const int MAX_SHORT_FORM_LENGTH = 127;

            /// <summary>Maximum number of length bytes in long form (4 bytes).</summary>
            public const int MAX_LONG_FORM_LENGTH_BYTES = 4;

            /// <summary>Indefinite length marker (0x80 in length field).</summary>
            public const byte INDEFINITE_LENGTH_MARKER = 0x80;

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
            public const ushort FCI_TEMPLATE = 0x6F;

            /// <summary>DF (Dedicated File) name tag (0x84).</summary>
            public const byte DF_NAME = 0x84;

            /// <summary>Application label tag (0x50).</summary>
            public const byte APPLICATION_LABEL = 0x50;

            /// <summary>Application priority indicator tag (0x87).</summary>
            public const byte APPLICATION_PRIORITY_INDICATOR = 0x87;

            /// <summary>FCI proprietary template tag (0xA5).</summary>
            public const byte FCI_PROPRIETARY_TEMPLATE = 0xA5;

            /// <summary>FCI issuer discretionary data tag (0xBF0C).</summary>
            public const ushort FCI_ISSUER_DISCRETIONARY_DATA = 0xBF0C;

            /// <summary>Application identifier (AID) tag (0x4F).</summary>
            public const byte APPLICATION_IDENTIFIER = 0x4F;

            /// <summary>Life cycle state tag (0x9F70).</summary>
            public const ushort LIFE_CYCLE_STATE = 0x9F70;
        }

        /// <summary>
        /// ASN.1 primitive tag definitions for common data types.
        /// Reference: ISO 8825-1, Section 8.1.2
        /// </summary>
        public static class Asn1PrimitiveTags
        {
            /// <summary>BOOLEAN tag (0x01).</summary>
            public const byte BOOLEAN = 0x01;

            /// <summary>INTEGER tag (0x02).</summary>
            public const byte INTEGER = 0x02;

            /// <summary>BIT STRING tag (0x03).</summary>
            public const byte BIT_STRING = 0x03;

            /// <summary>OCTET STRING tag (0x04).</summary>
            public const byte OCTET_STRING = 0x04;

            /// <summary>NULL tag (0x05).</summary>
            public const byte NULL = 0x05;

            /// <summary>OBJECT IDENTIFIER tag (0x06).</summary>
            public const byte OBJECT_IDENTIFIER = 0x06;

            /// <summary>UTF8String tag (0x0C).</summary>
            public const byte UTF8_STRING = 0x0C;

            /// <summary>SEQUENCE tag (0x30).</summary>
            public const byte SEQUENCE = 0x30;

            /// <summary>SET tag (0x31).</summary>
            public const byte SET = 0x31;

            /// <summary>PrintableString tag (0x13).</summary>
            public const byte PRINTABLE_STRING = 0x13;

            /// <summary>IA5String tag (0x16).</summary>
            public const byte IA5_STRING = 0x16;

            /// <summary>UTCTime tag (0x17).</summary>
            public const byte UTC_TIME = 0x17;

            /// <summary>GeneralizedTime tag (0x18).</summary>
            public const byte GENERALIZED_TIME = 0x18;
        }

        /// <summary>
        /// Context-specific tag class markers.
        /// Reference: ISO 8825-1, Section 8.1.2
        /// </summary>
        public static class ContextSpecific
        {
            /// <summary>Context-specific class mask (0x80).</summary>
            public const byte CLASS_MASK = 0x80;

            /// <summary>Context-specific constructed mask (0xA0).</summary>
            public const byte CONSTRUCTED_MASK = 0xA0;

            /// <summary>Context-specific tag 0 primitive (0x80).</summary>
            public const byte TAG0_PRIMITIVE = 0x80;

            /// <summary>Context-specific tag 0 constructed (0xA0).</summary>
            public const byte TAG0_CONSTRUCTED = 0xA0;

            /// <summary>Context-specific tag 1 primitive (0x81).</summary>
            public const byte TAG1_PRIMITIVE = 0x81;

            /// <summary>Context-specific tag 1 constructed (0xA1).</summary>
            public const byte TAG1_CONSTRUCTED = 0xA1;

            /// <summary>Context-specific tag 2 primitive (0x82).</summary>
            public const byte TAG2_PRIMITIVE = 0x82;

            /// <summary>Context-specific tag 2 constructed (0xA2).</summary>
            public const byte TAG2_CONSTRUCTED = 0xA2;
        }

        /// <summary>
        /// Vendor-specific data object tags.
        /// These are proprietary tags used by specific card manufacturers.
        /// </summary>
        public static class VendorSpecific
        {
            /// <summary>
            /// NXP P71 IDENTIFY data object tag (0xFE).
            /// Used with GET DATA command (P1=0x00, P2=0xFE) to retrieve P71-specific identification data.
            /// The response contains a TLV structure with outer tag 0xFE and inner tag 0xDF28.
            /// Reference: NXP P71D321 documentation
            /// </summary>
            public const byte NXP_P71_IDENTIFY = 0xFE;

            /// <summary>
            /// NXP P71 IDENTIFY response inner tag (0xDF28).
            /// This is the private class tag used inside the IDENTIFY response.
            /// </summary>
            public const ushort NXP_P71_IDENTIFY_RESPONSE_TAG = 0xDF28;
        }
    }
}
