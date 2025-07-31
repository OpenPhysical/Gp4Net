// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol
{
    /// <summary>
    /// Shared cryptographic operations for secure channel protocols.
    /// Provides common cryptographic utilities used across SCP02, SCP03, and other protocols.
    /// </summary>
    [PublicAPI]
    public static class CryptographicOperations
    {
        /// <summary>
        /// Applies ISO 7816-4 padding to data to reach the target length.
        /// Appends 0x80 followed by zero bytes to reach the target length.
        /// </summary>
        /// <param name="data">The data to pad.</param>
        /// <param name="targetLength">The target length after padding.</param>
        /// <returns>The padded data.</returns>
        /// <exception cref="ArgumentException">If data is longer than target length.</exception>
        public static byte[] ApplyIso7816Padding(byte[] data, int targetLength)
        {
            ArgumentNullException.ThrowIfNull(data);
            
            if (data.Length >= targetLength)
            {
                throw new ArgumentException($"Data length {data.Length} must be less than target length {targetLength}");
            }

            var padded = new byte[targetLength];
            Array.Copy(data, 0, padded, 0, data.Length);
            
            // ISO 7816-4 padding: 0x80 followed by zero bytes
            padded[data.Length] = 0x80;
            // Remaining bytes are already 0x00 from array initialization
            
            return padded;
        }

        /// <summary>
        /// Compares two byte arrays in constant time to prevent timing attacks.
        /// </summary>
        /// <param name="a">First array.</param>
        /// <param name="b">Second array.</param>
        /// <returns>True if arrays are equal, false otherwise.</returns>
        public static bool CompareBytes(byte[] a, byte[] b)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);
            
            if (a.Length != b.Length)
            {
                return false;
            }

            var result = 0;
            for (var i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            
            return result == 0;
        }

        /// <summary>
        /// Extracts a specified number of bytes from an array starting at the given offset.
        /// </summary>
        /// <param name="source">The source array.</param>
        /// <param name="offset">The starting offset.</param>
        /// <param name="length">The number of bytes to extract.</param>
        /// <returns>The extracted bytes.</returns>
        /// <exception cref="ArgumentException">If the extraction would exceed array bounds.</exception>
        public static byte[] ExtractBytes(byte[] source, int offset, int length)
        {
            ArgumentNullException.ThrowIfNull(source);
            
            if (offset < 0 || length < 0 || offset + length > source.Length)
            {
                throw new ArgumentException($"Cannot extract {length} bytes from offset {offset} in array of length {source.Length}");
            }

            var result = new byte[length];
            Array.Copy(source, offset, result, 0, length);
            return result;
        }

        /// <summary>
        /// Safely concatenates multiple byte arrays.
        /// </summary>
        /// <param name="arrays">The arrays to concatenate.</param>
        /// <returns>The concatenated array.</returns>
        public static byte[] ConcatenateArrays(params byte[][] arrays)
        {
            ArgumentNullException.ThrowIfNull(arrays);
            
            var totalLength = 0;
            foreach (var array in arrays)
            {
                if (array != null)
                {
                    totalLength += array.Length;
                }
            }

            var result = new byte[totalLength];
            var offset = 0;
            
            foreach (var array in arrays)
            {
                if (array != null)
                {
                    Array.Copy(array, 0, result, offset, array.Length);
                    offset += array.Length;
                }
            }

            return result;
        }
    }
}