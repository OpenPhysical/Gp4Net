// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants
{
    /// <summary>
    /// APDU format and length constants as defined by ISO 7816-4.
    /// </summary>
    [PublicAPI]
    public static class ApduConstants
    {
        /// <summary>
        /// Maximum length for Lc field in short APDU format.
        /// </summary>
        public const int MAX_SHORT_LENGTH_LC = 255;

        /// <summary>
        /// Maximum length for Le field in short APDU format.
        /// </summary>
        public const int MAX_SHORT_LENGTH_LE = 256;

        /// <summary>
        /// Maximum length for extended APDU format.
        /// </summary>
        public const int MAX_EXTENDED_LENGTH = 65536;

        /// <summary>
        /// Default block size for LOAD command operations.
        /// Optimized for most smart card implementations.
        /// </summary>
        public const int DEFAULT_LOAD_BLOCK_SIZE = 245;

        /// <summary>
        /// Maximum data length for single APDU in extended format.
        /// </summary>
        public const int MAX_APDU_DATA_LENGTH = 65535;

        /// <summary>
        /// Standard APDU header length (CLA, INS, P1, P2).
        /// </summary>
        public const int APDU_HEADER_LENGTH = 4;

        /// <summary>
        /// Length field size for short APDU format.
        /// </summary>
        public const int SHORT_APDU_LC_LENGTH = 1;

        /// <summary>
        /// Length field size for extended APDU format.
        /// </summary>
        public const int EXTENDED_APDU_LC_LENGTH = 3;

        /// <summary>
        /// Minimum APDU length (header only).
        /// </summary>
        public const int MIN_APDU_LENGTH = APDU_HEADER_LENGTH;

        /// <summary>
        /// Threshold for switching from short to extended APDU format.
        /// </summary>
        public const int EXTENDED_LENGTH_THRESHOLD = 256;
    }
}
