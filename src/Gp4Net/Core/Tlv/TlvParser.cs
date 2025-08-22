using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Core.Tlv;

/// <summary>
/// Provides functionality for parsing TLV (Tag-Length-Value) encoded data.
/// </summary>
[PublicAPI]
public static class TlvParser
{
    /// <summary>
    /// Parses a single TLV object from the given data.
    /// </summary>
    /// <param name="data">The data to parse.</param>
    /// <returns>The parsed TLV object or None if the data is not valid TLV.</returns>
    public static Maybe<TlvObject> ParseSingle(byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return Maybe<TlvObject>.None;
        }

        return ParseSingle(data, 0, out _);
    }

    /// <summary>
    /// Parses a single TLV object from the given data starting at the specified offset.
    /// </summary>
    /// <param name="data">The data to parse.</param>
    /// <param name="startOffset">The offset to start parsing from.</param>
    /// <param name="bytesConsumed">The number of bytes consumed by parsing.</param>
    /// <returns>The parsed TLV object or None if the data is not valid TLV.</returns>
    public static Maybe<TlvObject> ParseSingle(byte[] data, int startOffset, out int bytesConsumed)
    {
        bytesConsumed = 0;

        if (data == null || startOffset >= data.Length)
        {
            return Maybe<TlvObject>.None;
        }

        try
        {
            var offset = startOffset;

            // Parse tag
            var tagMaybe = ParseTag(data, ref offset);
            if (!tagMaybe.HasValue || offset >= data.Length)
            {
                return Maybe<TlvObject>.None;
            }

            // Parse length
            var lengthMaybe = ParseLength(data, ref offset);
            if (!lengthMaybe.HasValue || offset + lengthMaybe.Value > data.Length)
            {
                return Maybe<TlvObject>.None;
            }

            // Extract value - additional safety check before array allocation
            var length = lengthMaybe.Value;
            if (length < 0 || length > TlvConstants.MaxTlvValueSize)
            {
                return Maybe<TlvObject>.None;
            }

            var value = new byte[length];
            if (length > 0)
            {
                Array.Copy(data, offset, value, 0, length);
            }

            bytesConsumed = (offset - startOffset) + lengthMaybe.Value;
            return Maybe<TlvObject>.From(new TlvObject(tagMaybe.Value, value));
        }
        catch
        {
            return Maybe<TlvObject>.None;
        }
    }

    /// <summary>
    /// Parses all TLV objects from the given data.
    /// </summary>
    /// <param name="data">The data to parse.</param>
    /// <returns>A collection of parsed TLV objects.</returns>
    public static IReadOnlyList<TlvObject> ParseAll(byte[] data)
    {
        var result = new List<TlvObject>();

        if (data == null || data.Length == 0)
        {
            return result;
        }

        var offset = 0;
        while (offset < data.Length)
        {
            var tlvMaybe = ParseSingle(data, offset, out var consumed);
            if (!tlvMaybe.HasValue || consumed == 0)
            {
                break;
            }

            result.Add(tlvMaybe.Value);
            offset += consumed;
        }

        return result;
    }

    /// <summary>
    /// Finds a TLV object with the specified tag.
    /// </summary>
    /// <param name="data">The data to search in.</param>
    /// <param name="tag">The tag to find.</param>
    /// <returns>The first TLV object with the specified tag, or None if not found.</returns>
    public static Maybe<TlvObject> FindByTag(byte[] data, byte[] tag)
    {
        if (data == null || tag == null || tag.Length == 0)
        {
            return Maybe<TlvObject>.None;
        }

        var allTlv = ParseAll(data);
        var found = allTlv.FirstOrDefault(tlv => tlv.Tag.SequenceEqual(tag));
        return found != null ? Maybe<TlvObject>.From(found) : Maybe<TlvObject>.None;
    }

    /// <summary>
    /// Finds a TLV object with the specified tag (single byte).
    /// </summary>
    /// <param name="data">The data to search in.</param>
    /// <param name="tag">The tag to find.</param>
    /// <returns>The first TLV object with the specified tag, or None if not found.</returns>
    public static Maybe<TlvObject> FindByTag(byte[] data, byte tag)
    {
        return FindByTag(data, [tag]);
    }

    /// <summary>
    /// Finds a TLV object with the specified tag (two bytes).
    /// </summary>
    /// <param name="data">The data to search in.</param>
    /// <param name="tag">The tag to find.</param>
    /// <returns>The first TLV object with the specified tag, or None if not found.</returns>
    public static Maybe<TlvObject> FindByTag(byte[] data, ushort tag)
    {
        return FindByTag(data, [(byte)(tag >> 8), (byte)(tag & 0xFF)]);
    }

    /// <summary>
    /// Parses a tag from the data.
    /// </summary>
    private static Maybe<byte[]> ParseTag(byte[] data, ref int offset)
    {
        if (offset >= data.Length)
        {
            return Maybe<byte[]>.None;
        }

        var tagBytes = new List<byte> { data[offset++] };

        // Check if this is a multi-byte tag
        if (
            (tagBytes[0] & TlvConstants.MultiByteTagMask) == TlvConstants.MultiByteTagMask
        )
        {
            // Continue reading until we find a byte without the continuation bit
            while (offset < data.Length)
            {
                tagBytes.Add(data[offset++]);
                if ((tagBytes[tagBytes.Count - 1] & TlvConstants.SubsequentTagByteMask) == 0)
                {
                    break;
                }
            }
        }

        return Maybe<byte[]>.From([.. tagBytes]);
    }

    /// <summary>
    /// Parses a length from the data.
    /// </summary>
    private static Maybe<int> ParseLength(byte[] data, ref int offset)
    {
        if (offset >= data.Length)
        {
            return Maybe<int>.None;
        }

        var firstByte = data[offset++];

        // GP Card Specification v2.3.1: GP-specific extension where 0x80 alone means length 128
        // References: Install Token, Make Selectable Token, Extradition Token, Registry Update Token sections
        // "The length field for [tokens] is as defined for ASN.1 BER-TLV (see [ISO 8825-1]) 
        // except that the length 128 may also be coded on one byte as '80'."
        if (firstByte == 0x80)
        {
            return Maybe<int>.From(128);
        }

        // Short form
        if ((firstByte & TlvConstants.LongFormLengthMask) == 0)
        {
            return Maybe<int>.From(firstByte);
        }

        // Long form
        var lengthBytes = firstByte & TlvConstants.LengthBytesMask;
        if (lengthBytes == 0 || offset + lengthBytes > data.Length)
        {
            return Maybe<int>.None;
        }

        // Security check: Prevent integer overflow attacks with excessive length bytes
        if (lengthBytes > TlvConstants.MaxReasonableLengthBytes)
        {
            return Maybe<int>.None;
        }

        var length = 0;
        for (var i = 0; i < lengthBytes; i++)
        {
            // Security check: Detect integer overflow before it happens
            if (length > (int.MaxValue >> 8))
            {
                return Maybe<int>.None;
            }
            length = (length << 8) | data[offset++];
        }

        // Security check: Validate length against maximum allowed TLV value size
        if (length > TlvConstants.MaxTlvValueSize)
        {
            return Maybe<int>.None;
        }

        return Maybe<int>.From(length);
    }

    /// <summary>
    /// Converts a tag array to a numeric value for common 1-3 byte tags.
    /// </summary>
    /// <param name="tag">The tag bytes.</param>
    /// <returns>The numeric tag value.</returns>
    public static uint TagToNumber(byte[] tag)
    {
        if (tag == null || tag.Length == 0 || tag.Length > 4)
        {
            throw new ArgumentException("Tag must be 1-4 bytes.", nameof(tag));
        }

        uint result = 0;
        foreach (var b in tag)
        {
            result = (result << 8) | b;
        }
        return result;
    }

    /// <summary>
    /// Converts a numeric tag value to a byte array.
    /// </summary>
    /// <param name="tagValue">The numeric tag value.</param>
    /// <returns>The tag as a byte array.</returns>
    public static byte[] NumberToTag(uint tagValue)
    {
        switch (tagValue)
        {
            case <= 0xFF:
                return [(byte)tagValue];
            case <= 0xFFFF:
                return [(byte)(tagValue >> 8), (byte)(tagValue & 0xFF)];
            case <= 0xFFFFFF:
                return
                [
                    (byte)(tagValue >> 16),
                    (byte)(tagValue >> 8),
                    (byte)(tagValue & 0xFF)
                ];
            default:
                return
                [
                    (byte)(tagValue >> 24),
                    (byte)(tagValue >> 16),
                    (byte)(tagValue >> 8),
                    (byte)(tagValue & 0xFF)
                ];
        }

    }
}

/// <summary>
/// Represents a TLV (Tag-Length-Value) object.
/// </summary>
[PublicAPI]
public class TlvObject
{
    /// <summary>
    /// Gets the tag bytes.
    /// </summary>
    public byte[] Tag { get; }

    /// <summary>
    /// Gets the value bytes.
    /// </summary>
    public byte[] Value { get; }

    /// <summary>
    /// Gets the length of the value.
    /// </summary>
    public int Length
    {
        get
        {
            return Value.Length;
        }
    }

    /// <summary>
    /// Gets the tag as a numeric value (for common 1-3 byte tags).
    /// </summary>
    public uint TagNumber
    {
        get
        {
            return TlvParser.TagToNumber(Tag);
        }
    }

    /// <summary>
    /// Initializes a new instance of the TlvObject class.
    /// </summary>
    /// <param name="tag">The tag bytes.</param>
    /// <param name="value">The value bytes.</param>
    public TlvObject(byte[] tag, byte[] value)
    {
        Tag = tag;
        Value = value;
    }

    /// <summary>
    /// Creates a new TlvObject with functional error handling.
    /// </summary>
    /// <param name="tag">The tag bytes.</param>
    /// <param name="value">The value bytes.</param>
    /// <returns>A Result containing the TlvObject or an error if parameters are invalid.</returns>
    public static Result<TlvObject, SmartCardError> Create(byte[] tag, byte[] value)
    {
        if (tag is null)
            return Result.Failure<TlvObject, SmartCardError>(
                new NullParameterError("tag"));
        
        if (value is null)
            return Result.Failure<TlvObject, SmartCardError>(
                new NullParameterError("value"));
        
        return Result.Success<TlvObject, SmartCardError>(new TlvObject(tag, value));
    }

    /// <summary>
    /// Gets the value as a hex string.
    /// </summary>
    /// <returns>The value formatted as a hex string.</returns>
    public string GetValueAsHexString()
    {
        return Convert.ToHexString(Value);
    }

    /// <summary>
    /// Gets the tag as a hex string.
    /// </summary>
    /// <returns>The tag formatted as a hex string.</returns>
    public string GetTagAsHexString()
    {
        return Convert.ToHexString(Tag);
    }

    /// <summary>
    /// Gets the value as an unsigned integer (for numeric values).
    /// </summary>
    /// <returns>The numeric value or None if not applicable.</returns>
    public Maybe<uint> GetValueAsNumber()
    {
        if (Value.Length is 0 or > 4)
        {
            return Maybe<uint>.None;
        }

        uint result = 0;
        foreach (var b in Value)
        {
            result = (result << 8) | b;
        }
        return Maybe<uint>.From(result);
    }

    /// <summary>
    /// Parses nested TLV objects from the value.
    /// </summary>
    /// <returns>A collection of nested TLV objects.</returns>
    public IReadOnlyList<TlvObject> ParseNestedTlv()
    {
        return TlvParser.ParseAll(Value);
    }

    /// <summary>
    /// Returns a string representation of this TLV object.
    /// </summary>
    /// <returns>A string representation.</returns>
    public override string ToString()
    {
        return $"Tag: {GetTagAsHexString()}, Length: {Length}, Value: {GetValueAsHexString()}";
    }
}