// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants;

/// <summary>
/// APDU format and length constants as defined by ISO 7816-4.
/// </summary>
[PublicAPI]
public static class ApduConstants
{
    /// <summary>
    /// Maximum length for Lc field in short APDU format.
    /// </summary>
    public const int MaxShortLengthLc = 255;

    /// <summary>
    /// Maximum length for Le field in short APDU format.
    /// </summary>
    public const int MaxShortLengthLe = 256;

    /// <summary>
    /// Maximum length for extended APDU format.
    /// </summary>
    public const int MaxExtendedLength = 65536;

    /// <summary>
    /// Default block size for LOAD command operations.
    /// Optimized for most smart card implementations.
    /// </summary>
    public const int DefaultLoadBlockSize = 245;

    /// <summary>
    /// Maximum data length for single APDU in extended format.
    /// </summary>
    public const int MaxApduDataLength = 65535;

    /// <summary>
    /// Standard APDU header length (CLA, INS, P1, P2).
    /// </summary>
    public const int ApduHeaderLength = 4;

    /// <summary>
    /// Length field size for short APDU format.
    /// </summary>
    public const int ShortApduLcLength = 1;

    /// <summary>
    /// Length field size for extended APDU format.
    /// </summary>
    public const int ExtendedApduLcLength = 3;

    /// <summary>
    /// Minimum APDU length (header only).
    /// </summary>
    public const int MinApduLength = ApduHeaderLength;

    /// <summary>
    /// Threshold for switching from short to extended APDU format.
    /// </summary>
    public const int ExtendedLengthThreshold = 256;

    /// <summary>
    /// Maximum number of GET RESPONSE chains to prevent infinite loops.
    /// Protects against malicious cards sending continuous 0x61XX responses.
    /// </summary>
    public const int MaxResponseChainLength = 128;

    /// <summary>
    /// Maximum total accumulated response size across all chains.
    /// Prevents memory exhaustion from excessive response data accumulation.
    /// </summary>
    public const int MaxTotalResponseSize = 1048576; // 1MB
}