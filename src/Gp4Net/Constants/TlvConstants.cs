// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants
{
    /// <summary>
    /// TLV (Tag-Length-Value) parsing constants as defined by ISO 8825-1.
    /// </summary>
    [PublicAPI]
    public static class TlvConstants
    {
        /// <summary>
        /// Mask to check if tag requires multiple bytes (tag & 0x1F == 0x1F).
        /// </summary>
        public const byte MULTI_BYTE_TAG_MASK = 0x1F;

        /// <summary>
        /// Mask to check if length is in long form (first byte & 0x80 != 0).
        /// </summary>
        public const byte LONG_FORM_LENGTH_MASK = 0x80;

        /// <summary>
        /// Mask to get number of length bytes in long form (first byte & 0x7F).
        /// </summary>
        public const byte LENGTH_BYTES_MASK = 0x7F;

        /// <summary>
        /// Mask to check if tag has more bytes following (byte & 0x80 != 0).
        /// </summary>
        public const byte SUBSEQUENT_TAG_BYTE_MASK = 0x80;

        /// <summary>
        /// Maximum length that can be encoded in short form.
        /// </summary>
        public const int MAX_SHORT_FORM_LENGTH = 127;

        /// <summary>
        /// Maximum number of length bytes in long form.
        /// </summary>
        public const int MAX_LONG_FORM_LENGTH_BYTES = 4;

        /// <summary>
        /// Indefinite length marker (0x80 in length field).
        /// </summary>
        public const byte INDEFINITE_LENGTH_MARKER = 0x80;

        /// <summary>
        /// End-of-contents octets for indefinite length (0x00 0x00).
        /// </summary>
        public static readonly byte[] END_OF_CONTENTS = { 0x00, 0x00 };
    }

    /// <summary>
    /// Standard TLV tag definitions for GlobalPlatform and ISO 7816.
    /// </summary>
    [PublicAPI]
    public static class TlvTags
    {
        /// <summary>
        /// FCI (File Control Information) template tag.
        /// </summary>
        public const ushort FCI_TEMPLATE = 0x6F;

        /// <summary>
        /// DF (Dedicated File) name tag.
        /// </summary>
        public const byte DF_NAME = 0x84;

        /// <summary>
        /// Application label tag.
        /// </summary>
        public const byte APPLICATION_LABEL = 0x50;

        /// <summary>
        /// Application priority indicator tag.
        /// </summary>
        public const byte APPLICATION_PRIORITY_INDICATOR = 0x87;

        /// <summary>
        /// PDOL (Processing Options Data Object List) tag.
        /// </summary>
        public const ushort PDOL = 0x9F38;

        /// <summary>
        /// FCI proprietary template tag.
        /// </summary>
        public const byte FCI_PROPRIETARY_TEMPLATE = 0xA5;

        /// <summary>
        /// FCI issuer discretionary data tag.
        /// </summary>
        public const ushort FCI_ISSUER_DISCRETIONARY_DATA = 0xBF0C;

        /// <summary>
        /// CAP data TLV tag for LOAD command.
        /// </summary>
        public const byte CAP_DATA_TLV_TAG = 0xC4;

        /// <summary>
        /// Application identifier (AID) tag.
        /// </summary>
        public const byte APPLICATION_IDENTIFIER = 0x4F;

        /// <summary>
        /// Security domain privileges tag.
        /// </summary>
        public const byte SECURITY_DOMAIN_PRIVILEGES = 0xC5;

        /// <summary>
        /// Life cycle state tag.
        /// </summary>
        public const ushort LIFE_CYCLE_STATE = 0x9F70;
    }
}
