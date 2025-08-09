using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Security;
using JetBrains.Annotations;
using MoonSharp.Interpreter;
using MoonSharp.Interpreter.Interop;

namespace Gp4Net.Tool.Scripting;

/// <summary>
/// Provides utility functions to Lua scripts.
/// </summary>
[PublicAPI]
[MoonSharpUserData]
public class UtilityScriptModule
{
    /// <summary>
    /// Converts a hex string to bytes.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] Hex(string hexString)
    {
        if (string.IsNullOrEmpty(hexString))
        {
            return [];
        }

        // Remove spaces and ensure even length
        hexString = hexString.Replace(" ", "").Replace("-", "");
        if (hexString.Length % 2 != 0)
        {
            throw new ArgumentException("Hex string must have even length");
        }

        return Convert.FromHexString(hexString);
    }

    /// <summary>
    /// Creates a byte array from various inputs.
    /// </summary>
    [MoonSharpVisible(true)]
    public byte[] Bytes(object input)
    {
        switch (input)
        {
            case byte[] bytes:
                return bytes;

            case string str:
                return Hex(str);

            case int value:
                // Create array of zeros with specified length
                return new byte[value];

            case Table table:
                // Convert Lua table to byte array
                var list = new List<byte>();
                foreach (var pair in table.Pairs)
                {
                    if (pair.Value.Type == DataType.Number)
                    {
                        list.Add((byte)pair.Value.Number);
                    }
                }
                return [.. list];

            default:
                throw new ArgumentException($"Cannot convert {input?.GetType()} to bytes");
        }
    }

    /// <summary>
    /// Concatenates byte arrays.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] Concat(params byte[][] arrays)
    {
        var totalLength = arrays.Sum(a => a?.Length ?? 0);
        var result = new byte[totalLength];
        var offset = 0;

        foreach (var array in arrays)
        {
            if (array is { Length: > 0 })
            {
                Array.Copy(array, 0, result, offset, array.Length);
                offset += array.Length;
            }
        }

        return result;
    }

    /// <summary>
    /// Extracts a sub-array.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] Sub(byte[] data, int start, int length)
    {
        if (start < 1 || start > data.Length)
        {
            throw new ArgumentOutOfRangeException(
                nameof(start),
                "Start index out of range (1-based)"
            );
        }

        // Convert from 1-based Lua indexing to 0-based
        start--;

        if (length < 0)
        {
            // Negative length means "to the end"
            length = data.Length - start;
        }

        if (start + length > data.Length)
        {
            length = data.Length - start;
        }

        var result = new byte[length];
        Array.Copy(data, start, result, 0, length);
        return result;
    }

    /// <summary>
    /// XORs two byte arrays.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] Xor(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
        {
            throw new ArgumentException("Arrays must have the same length for XOR");
        }

        var result = new byte[a.Length];
        for (var i = 0; i < a.Length; i++)
        {
            result[i] = (byte)(a[i] ^ b[i]);
        }

        return result;
    }

    /// <summary>
    /// Applies ISO 7816-4 padding (0x80 followed by zeros).
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] Pad80(byte[] data, int blockSize)
    {
        var paddingLength = blockSize - (data.Length % blockSize);
        if (paddingLength == 0)
        {
            paddingLength = blockSize;
        }

        var padded = new byte[data.Length + paddingLength];
        Array.Copy(data, padded, data.Length);
        padded[data.Length] = 0x80;
        // Rest are already zeros

        return padded;
    }

    /// <summary>
    /// Converts bytes to hex string.
    /// </summary>
    [MoonSharpVisible(true)]
    public static string HexString(byte[] bytes)
    {
        return BitConverter.ToString(bytes).Replace("-", "");
    }

    /// <summary>
    /// Generates random bytes.
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] RandomBytes(int length)
    {
        var bytes = new byte[length];
        var random = new SecureRandom();
        random.NextBytes(bytes);
        return bytes;
    }

    /// <summary>
    /// Converts integer to bytes (big-endian).
    /// </summary>
    [MoonSharpVisible(true)]
    public static byte[] IntToBytes(int value, int length)
    {
        var bytes = new byte[length];
        for (var i = length - 1; i >= 0; i--)
        {
            bytes[i] = (byte)(value & 0xFF);
            value >>= 8;
        }
        return bytes;
    }

    /// <summary>
    /// Converts bytes to integer (big-endian).
    /// </summary>
    [MoonSharpVisible(true)]
    public static int BytesToInt(byte[] bytes)
    {
        if (bytes.Length > 4)
        {
            throw new ArgumentException("Byte array too long for int conversion");
        }

        var result = 0;
        foreach (var b in bytes)
        {
            result = (result << 8) | b;
        }
        return result;
    }
}