// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Text;
using CSharpFunctionalExtensions;
using JetBrains.Annotations;
using System.Linq;

namespace Gp4Net.Core;

/// <summary>
/// Safe encoding utilities that handle malformed input gracefully.
/// Provides security-hardened text decoding operations.
/// </summary>
[PublicAPI]
public static class EncodingUtils
{
    /// <summary>
    /// Maximum reasonable text length to prevent memory exhaustion attacks.
    /// </summary>
    private const int MaxTextLength = 8192; // 8KB reasonable limit for card text fields

    /// <summary>
    /// Safely decodes UTF-8 bytes to string with comprehensive validation.
    /// Protects against malformed UTF-8 sequences, excessive lengths, and embedded nulls.
    /// </summary>
    /// <param name="bytes">The bytes to decode.</param>
    /// <returns>Decoded string or error if validation fails.</returns>
    public static Result<string, SmartCardError> SafeUtf8Decode(byte[] bytes)
    {
        if (bytes == null)
        {
            return Result.Failure<string, SmartCardError>(
                SmartCardError.InvalidArgument("Input bytes cannot be null"));
        }

        // Security check: Prevent memory exhaustion from excessive text lengths
        if (bytes.Length > MaxTextLength)
        {
            return Result.Failure<string, SmartCardError>(
                SmartCardError.InvalidArgument($"Text length ({bytes.Length}) exceeds maximum ({MaxTextLength})"));
        }

        // Handle empty input
        if (bytes.Length == 0)
        {
            return Result.Success<string, SmartCardError>(string.Empty);
        }

        try
        {
            // Use UTF-8 decoder with strict validation
            var decoder = Encoding.UTF8.GetDecoder();
            decoder.Fallback = DecoderFallback.ExceptionFallback; // Throw on invalid sequences

            var chars = new char[Encoding.UTF8.GetMaxCharCount(bytes.Length)];
            var charCount = decoder.GetChars(bytes, 0, bytes.Length, chars, 0, true);

            var result = new string(chars, 0, charCount);

            // Security check: Reject strings with embedded null characters
            if (result.Contains('\0'))
            {
                return Result.Failure<string, SmartCardError>(
                    SmartCardError.InvalidArgument("Text contains embedded null characters"));
            }

            // Security check: Validate reasonable character ranges (optional but recommended)
            foreach (var c in result)
            {
                // Reject control characters except common whitespace
                if (char.IsControl(c) && c != '\t' && c != '\n' && c != '\r')
                {
                    return Result.Failure<string, SmartCardError>(
                        SmartCardError.InvalidArgument($"Text contains invalid control character (U+{(int)c:X4})"));
                }
            }

            return Result.Success<string, SmartCardError>(result);
        }
        catch (DecoderFallbackException ex)
        {
            return Result.Failure<string, SmartCardError>(
                SmartCardError.InvalidArgument($"Invalid UTF-8 sequence: {ex.Message}"));
        }
        catch (ArgumentException ex)
        {
            return Result.Failure<string, SmartCardError>(
                SmartCardError.InvalidArgument($"UTF-8 decoding error: {ex.Message}"));
        }
    }

    /// <summary>
    /// Safely decodes ASCII bytes to string with validation.
    /// More restrictive than UTF-8 for cases where only ASCII is expected.
    /// </summary>
    /// <param name="bytes">The bytes to decode.</param>
    /// <returns>Decoded ASCII string or error if validation fails.</returns>
    public static Result<string, SmartCardError> SafeAsciiDecode(byte[] bytes)
    {
        if (bytes == null)
        {
            return Result.Failure<string, SmartCardError>(
                SmartCardError.InvalidArgument("Input bytes cannot be null"));
        }

        // Security check: Prevent memory exhaustion
        if (bytes.Length > MaxTextLength)
        {
            return Result.Failure<string, SmartCardError>(
                SmartCardError.InvalidArgument($"Text length ({bytes.Length}) exceeds maximum ({MaxTextLength})"));
        }

        // Handle empty input
        if (bytes.Length == 0)
        {
            return Result.Success<string, SmartCardError>(string.Empty);
        }

        // Validate all bytes are valid ASCII (0-127) using functional approach
        var invalidByteIndex = bytes.AsEnumerable().Select((b, index) => new { Byte = b, Index = index })
            .Where(x => x.Byte > 127)
            .Select(x => x.Index)
            .FirstOrDefault(-1);
            
        if (invalidByteIndex >= 0)
        {
            return Result.Failure<string, SmartCardError>(
                SmartCardError.InvalidArgument($"Non-ASCII byte at position {invalidByteIndex}: 0x{bytes[invalidByteIndex]:X2}"));
        }

        try
        {
            var result = Encoding.ASCII.GetString(bytes);

            // Security check: Reject embedded nulls
            if (result.Contains('\0'))
            {
                return Result.Failure<string, SmartCardError>(
                    SmartCardError.InvalidArgument("ASCII text contains embedded null characters"));
            }

            return Result.Success<string, SmartCardError>(result);
        }
        catch (Exception ex)
        {
            return Result.Failure<string, SmartCardError>(
                SmartCardError.InvalidArgument($"ASCII decoding error: {ex.Message}"));
        }
    }

    /// <summary>
    /// Safely decodes hex string with validation.
    /// Useful for debugging and logging binary data safely.
    /// </summary>
    /// <param name="bytes">The bytes to convert to hex.</param>
    /// <returns>Hex string representation.</returns>
    public static string SafeToHexString(byte[] bytes)
    {
        if (bytes == null || bytes.Length == 0)
        {
            return string.Empty;
        }

        // Prevent excessive memory usage for very large byte arrays
        if (bytes.Length > MaxTextLength / 2) // Each byte becomes 2 hex chars
        {
            return $"[{bytes.Length} bytes - too large to display]";
        }

        return Convert.ToHexString(bytes);
    }
}