// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants;

/// <summary>
/// TLV (Tag-Length-Value) parsing constants as defined by ISO 8825-1.
/// </summary>
[PublicAPI]
public static class TlvConstants
{
    /// <summary>
    /// Mask to check if tag requires multiple bytes (tag &amp; 0x1F == 0x1F).
    /// </summary>
    public const byte MultiByteTagMask = 0x1F;

    /// <summary>
    /// Mask to check if length is in long form (first byte &amp; 0x80 != 0).
    /// </summary>
    public const byte LongFormLengthMask = 0x80;

    /// <summary>
    /// Mask to get number of length bytes in long form (first byte &amp; 0x7F).
    /// </summary>
    public const byte LengthBytesMask = 0x7F;

    /// <summary>
    /// Mask to check if tag has more bytes following (byte &amp; 0x80 != 0).
    /// </summary>
    public const byte SubsequentTagByteMask = 0x80;

    /// <summary>
    /// Maximum length that can be encoded in short form.
    /// </summary>
    public const int MaxShortFormLength = 127;

    /// <summary>
    /// Maximum number of length bytes in long form.
    /// </summary>
    public const int MaxLongFormLengthBytes = 4;

    /// <summary>
    /// Indefinite length marker (0x80 in length field).
    /// </summary>
    public const byte IndefiniteLengthMarker = 0x80;

    /// <summary>
    /// End-of-contents octets for indefinite length (0x00 0x00).
    /// </summary>
    public static readonly byte[] EndOfContents = { 0x00, 0x00 };
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
    public const ushort FciTemplate = 0x6F;

    /// <summary>
    /// DF (Dedicated File) name tag.
    /// </summary>
    public const byte DfName = 0x84;

    /// <summary>
    /// Application label tag.
    /// </summary>
    public const byte ApplicationLabel = 0x50;

    /// <summary>
    /// Application priority indicator tag.
    /// </summary>
    public const byte ApplicationPriorityIndicator = 0x87;

    /// <summary>
    /// PDOL (Processing Options Data Object List) tag.
    /// </summary>
    public const ushort Pdol = 0x9F38;

    /// <summary>
    /// FCI proprietary template tag.
    /// </summary>
    public const byte FciProprietaryTemplate = 0xA5;

    /// <summary>
    /// FCI issuer discretionary data tag.
    /// </summary>
    public const ushort FciIssuerDiscretionaryData = 0xBF0C;

    /// <summary>
    /// CAP data TLV tag for LOAD command.
    /// </summary>
    public const byte CapDataTlvTag = 0xC4;

    /// <summary>
    /// Application identifier (AID) tag.
    /// </summary>
    public const byte ApplicationIdentifier = 0x4F;

    /// <summary>
    /// Security domain privileges tag.
    /// </summary>
    public const byte SecurityDomainPrivileges = 0xC5;

    /// <summary>
    /// Life cycle state tag.
    /// </summary>
    public const ushort LifeCycleState = 0x9F70;
}