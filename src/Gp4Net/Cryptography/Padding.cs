// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using Gp4Net.Constants;

namespace Gp4Net.Cryptography
{
    /// <summary>
    /// Implements ISO/IEC 9797-1 padding method 2 (ISO 7816-4 padding).
    /// </summary>
    public static class Iso7816Padding
    {
        /// <summary>
        /// Adds ISO 7816-4 padding to the input data.
        /// </summary>
        /// <param name="data">The data to pad.</param>
        /// <param name="blockSize">The block size in bytes.</param>
        /// <returns>The padded data.</returns>
        public static byte[] AddPadding(byte[] data, int blockSize)
        {
            ArgumentNullException.ThrowIfNull(data);

            if (blockSize <= 0)
            {
                throw new ArgumentException("Block size must be positive.", nameof(blockSize));
            }

            // Calculate the number of padding bytes needed
            int paddingLength = blockSize - (data.Length % blockSize);

            // Create the padded array
            byte[] padded = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, padded, 0, data.Length);

            // Add the padding: 0x80 followed by zeros
            padded[data.Length] = CryptographicConstants.ISO7816_PADDING_MARKER;
            // Remaining bytes are already zero (default value)

            return padded;
        }

        /// <summary>
        /// Removes ISO 7816-4 padding from the input data.
        /// </summary>
        /// <param name="data">The padded data.</param>
        /// <returns>The unpadded data.</returns>
        public static byte[] RemovePadding(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            if (data.Length == 0)
            {
                throw new ArgumentException("Data cannot be empty.", nameof(data));
            }

            // Find the padding marker (0x80) from the end
            int i = data.Length - 1;
            while (i >= 0 && data[i] == 0x00)
            {
                i--;
            }

            if (i < 0 || data[i] != CryptographicConstants.ISO7816_PADDING_MARKER)
            {
                throw new ArgumentException("Invalid padding.");
            }

            // Create the unpadded array
            byte[] unpadded = new byte[i];
            Array.Copy(data, 0, unpadded, 0, i);

            return unpadded;
        }

        /// <summary>
        /// Calculates the padded length for the given data length.
        /// </summary>
        /// <param name="dataLength">The length of the data.</param>
        /// <param name="blockSize">The block size in bytes.</param>
        /// <returns>The padded length.</returns>
        public static int GetPaddedLength(int dataLength, int blockSize)
        {
            if (dataLength < 0)
            {
                throw new ArgumentException("Data length cannot be negative.", nameof(dataLength));
            }

            if (blockSize <= 0)
            {
                throw new ArgumentException("Block size must be positive.", nameof(blockSize));
            }

            int paddingLength = blockSize - (dataLength % blockSize);
            return dataLength + paddingLength;
        }
    }
}
