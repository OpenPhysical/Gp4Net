// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants
{
    /// <summary>
    /// Cryptographic constants for GlobalPlatform secure channel protocols.
    /// </summary>
    [PublicAPI]
    public static class CryptographicConstants
    {
        /// <summary>
        /// Triple DES key length for 2-key format (K1||K2||K1).
        /// </summary>
        public const int DES3_KEY_LENGTH_16 = 16;

        /// <summary>
        /// Triple DES key length for 3-key format (K1||K2||K3).
        /// </summary>
        public const int DES3_KEY_LENGTH_24 = 24;

        /// <summary>
        /// AES block size in bytes.
        /// </summary>
        public const int AES_BLOCK_SIZE = 16;

        /// <summary>
        /// DES/3DES block size in bytes.
        /// </summary>
        public const int DES_BLOCK_SIZE = 8;

        /// <summary>
        /// AES key length for 128-bit keys.
        /// </summary>
        public const int AES_KEY_LENGTH_128 = 16;

        /// <summary>
        /// AES key length for 192-bit keys.
        /// </summary>
        public const int AES_KEY_LENGTH_192 = 24;

        /// <summary>
        /// AES key length for 256-bit keys.
        /// </summary>
        public const int AES_KEY_LENGTH_256 = 32;

        /// <summary>
        /// Key check value length as defined by GlobalPlatform.
        /// </summary>
        public const int KEY_CHECK_VALUE_LENGTH = 3;

        /// <summary>
        /// ISO 7816-4 padding marker byte.
        /// </summary>
        public const byte ISO7816_PADDING_MARKER = 0x80;

        /// <summary>
        /// SCP02 sequence counter length for 2-byte format.
        /// </summary>
        public const int SEQUENCE_COUNTER_LENGTH_2 = 2;

        /// <summary>
        /// SCP03 sequence counter length for 3-byte format.
        /// </summary>
        public const int SEQUENCE_COUNTER_LENGTH_3 = 3;

        /// <summary>
        /// CMAC (Cipher-based Message Authentication Code) length.
        /// </summary>
        public const int CMAC_LENGTH = 8;

        /// <summary>
        /// CMAC length for AES-based secure channels.
        /// </summary>
        public const int AES_CMAC_LENGTH = 16;

        /// <summary>
        /// IV (Initialization Vector) length for encryption operations.
        /// </summary>
        public const int ENCRYPTION_IV_LENGTH = 16;

        /// <summary>
        /// Default MAC chaining value for secure channel initialization.
        /// </summary>
        public static readonly byte[] DEFAULT_MAC_CHAINING_VALUE = new byte[DES_BLOCK_SIZE];
    }
}
