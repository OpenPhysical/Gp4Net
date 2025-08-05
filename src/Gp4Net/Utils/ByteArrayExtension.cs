// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Text;

namespace Gp4Net.Utils;

/// <summary>
/// Extension methods for byte arrays.
/// </summary>
public static class ByteArrayExtensions
{
    /// <summary>
    /// Converts a byte array to a hexadecimal string.
    /// </summary>
    /// <param name="data">The byte array to convert.</param>
    /// <returns>The hexadecimal string representation.</returns>
    public static string ToHexString(this byte[] data)
    {
        if (data == null)
        {
            return string.Empty;
        }

        return Convert.ToHexString(data);
    }

    /// <summary>
    /// Converts a byte array to a hexadecimal string with spaces.
    /// </summary>
    /// <param name="data">The byte array to convert.</param>
    /// <returns>The hexadecimal string representation with spaces.</returns>
    public static string ToHexStringWithSpaces(this byte[] data)
    {
        if (data == null)
        {
            return string.Empty;
        }

        if (data.Length == 0)
        {
            return string.Empty;
        }

        // Convert to hex string and insert spaces
        var hex = Convert.ToHexString(data);
        var sb = new StringBuilder(hex.Length + data.Length - 1);
        
        for (var i = 0; i < hex.Length; i += 2)
        {
            if (i > 0)
            {
                _ = sb.Append(' ');
            }
            _ = sb.Append(hex, i, 2);
        }
        
        return sb.ToString();
    }

    /// <summary>
    /// Creates a copy of a portion of a byte array.
    /// </summary>
    /// <param name="data">The source array.</param>
    /// <param name="offset">The starting offset.</param>
    /// <param name="length">The number of bytes to copy.</param>
    /// <returns>A new array containing the specified portion.</returns>
    public static byte[] Slice(this byte[] data, int offset, int length)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (offset < 0 || offset > data.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }

        if (length < 0 || offset + length > data.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        var result = new byte[length];
        Array.Copy(data, offset, result, 0, length);
        return result;
    }

    /// <summary>
    /// Concatenates multiple byte arrays.
    /// </summary>
    /// <param name="arrays">The arrays to concatenate.</param>
    /// <returns>A new array containing all the input arrays.</returns>
    public static byte[] Concat(params byte[][] arrays)
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

    /// <summary>
    /// Compares two byte arrays for equality.
    /// </summary>
    /// <param name="a">The first array.</param>
    /// <param name="b">The second array.</param>
    /// <returns>True if the arrays are equal; otherwise, false.</returns>
    public static bool SequenceEqual(this byte[] a, byte[] b)
    {
        if (ReferenceEquals(a, b))
        {
            return true;
        }

        if (a == null || b == null)
        {
            return false;
        }

        if (a.Length != b.Length)
        {
            return false;
        }

        for (var i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// XORs two byte arrays.
    /// </summary>
    /// <param name="a">The first array.</param>
    /// <param name="b">The second array.</param>
    /// <returns>A new array containing the XOR result.</returns>
    public static byte[] Xor(this byte[] a, byte[] b)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);

        if (a.Length != b.Length)
        {
            throw new ArgumentException("Arrays must have the same length.");
        }

        var result = new byte[a.Length];
        for (var i = 0; i < a.Length; i++)
        {
            result[i] = (byte)(a[i] ^ b[i]);
        }

        return result;
    }
}