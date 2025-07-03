// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants
{
    /// <summary>
    /// Security and secure channel constants for GlobalPlatform protocols.
    /// </summary>
    [PublicAPI]
    public static class SecurityConstants
    {
        /// <summary>
        /// Session identifier length in bytes.
        /// </summary>
        public const int SESSION_ID_LENGTH = 8;

        /// <summary>
        /// Host challenge length for secure channel establishment.
        /// </summary>
        public const int HOST_CHALLENGE_LENGTH = 8;

        /// <summary>
        /// Card challenge length for secure channel establishment.
        /// </summary>
        public const int CARD_CHALLENGE_LENGTH = 8;

        /// <summary>
        /// Host cryptogram length for authentication.
        /// </summary>
        public const int HOST_CRYPTOGRAM_LENGTH = 8;

        /// <summary>
        /// Card cryptogram length for authentication.
        /// </summary>
        public const int CARD_CRYPTOGRAM_LENGTH = 8;

        /// <summary>
        /// INITIALIZE UPDATE response length for SCP02/SCP03.
        /// </summary>
        public const int INITIALIZE_UPDATE_RESPONSE_LENGTH = 28;

        /// <summary>
        /// Key diversification data length in INITIALIZE UPDATE response.
        /// </summary>
        public const int KEY_DIVERSIFICATION_DATA_LENGTH = 10;

        /// <summary>
        /// Standard length for cryptographic nonces.
        /// </summary>
        public const int NONCE_LENGTH = 16;

        /// <summary>
        /// Receipt MAC length for response verification.
        /// </summary>
        public const int RECEIPT_MAC_LENGTH = 8;

        /// <summary>
        /// Minimum secure channel key version.
        /// </summary>
        public const byte MIN_KEY_VERSION = 0x01;

        /// <summary>
        /// Maximum secure channel key version.
        /// </summary>
        public const byte MAX_KEY_VERSION = 0xFF;

        /// <summary>
        /// Factory default key version (typically used for test keys).
        /// </summary>
        public const byte FACTORY_KEY_VERSION = 0xFF;
    }
}
