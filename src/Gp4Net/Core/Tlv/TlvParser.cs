using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.Constants;
using JetBrains.Annotations;

namespace Gp4Net.Core.Tlv
{
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
        /// <returns>The parsed TLV object or null if the data is not valid TLV.</returns>
        public static TlvObject? ParseSingle(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            return ParseSingle(data, 0, out _);
        }

        /// <summary>
        /// Parses a single TLV object from the given data starting at the specified offset.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <param name="startOffset">The offset to start parsing from.</param>
        /// <param name="bytesConsumed">The number of bytes consumed by parsing.</param>
        /// <returns>The parsed TLV object or null if the data is not valid TLV.</returns>
        public static TlvObject? ParseSingle(byte[] data, int startOffset, out int bytesConsumed)
        {
            bytesConsumed = 0;

            if (data == null || startOffset >= data.Length)
            {
                return null;
            }

            try
            {
                int offset = startOffset;

                // Parse tag
                var tag = ParseTag(data, ref offset);
                if (tag == null || offset >= data.Length)
                {
                    return null;
                }

                // Parse length
                var length = ParseLength(data, ref offset);
                if (!length.HasValue || offset + length.Value > data.Length)
                {
                    return null;
                }

                // Extract value
                var value = new byte[length.Value];
                if (length.Value > 0)
                {
                    Array.Copy(data, offset, value, 0, length.Value);
                }

                bytesConsumed = (offset - startOffset) + length.Value;
                return new TlvObject(tag, value);
            }
            catch
            {
                return null;
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

            int offset = 0;
            while (offset < data.Length)
            {
                var tlv = ParseSingle(data, offset, out int consumed);
                if (tlv == null || consumed == 0)
                {
                    break;
                }

                result.Add(tlv);
                offset += consumed;
            }

            return result;
        }

        /// <summary>
        /// Finds a TLV object with the specified tag.
        /// </summary>
        /// <param name="data">The data to search in.</param>
        /// <param name="tag">The tag to find.</param>
        /// <returns>The first TLV object with the specified tag, or null if not found.</returns>
        public static TlvObject? FindByTag(byte[] data, byte[] tag)
        {
            if (data == null || tag == null || tag.Length == 0)
            {
                return null;
            }

            var allTlv = ParseAll(data);
            return allTlv.FirstOrDefault(tlv => tlv.Tag.SequenceEqual(tag));
        }

        /// <summary>
        /// Finds a TLV object with the specified tag (single byte).
        /// </summary>
        /// <param name="data">The data to search in.</param>
        /// <param name="tag">The tag to find.</param>
        /// <returns>The first TLV object with the specified tag, or null if not found.</returns>
        public static TlvObject? FindByTag(byte[] data, byte tag)
        {
            return FindByTag(data, new[] { tag });
        }

        /// <summary>
        /// Finds a TLV object with the specified tag (two bytes).
        /// </summary>
        /// <param name="data">The data to search in.</param>
        /// <param name="tag">The tag to find.</param>
        /// <returns>The first TLV object with the specified tag, or null if not found.</returns>
        public static TlvObject? FindByTag(byte[] data, ushort tag)
        {
            return FindByTag(data, new[] { (byte)(tag >> 8), (byte)(tag & 0xFF) });
        }

        /// <summary>
        /// Parses a tag from the data.
        /// </summary>
        private static byte[]? ParseTag(byte[] data, ref int offset)
        {
            if (offset >= data.Length)
            {
                return null;
            }

            var tagBytes = new List<byte> { data[offset++] };

            // Check if this is a multi-byte tag
            if (
                (tagBytes[0] & TlvConstants.MULTI_BYTE_TAG_MASK) == TlvConstants.MULTI_BYTE_TAG_MASK
            )
            {
                // Continue reading until we find a byte without the continuation bit
                while (offset < data.Length)
                {
                    tagBytes.Add(data[offset++]);
                    if ((tagBytes[tagBytes.Count - 1] & TlvConstants.SUBSEQUENT_TAG_BYTE_MASK) == 0)
                    {
                        break;
                    }
                }
            }

            return [.. tagBytes];
        }

        /// <summary>
        /// Parses a length from the data.
        /// </summary>
        private static int? ParseLength(byte[] data, ref int offset)
        {
            if (offset >= data.Length)
            {
                return null;
            }

            byte firstByte = data[offset++];

            // Short form
            if ((firstByte & TlvConstants.LONG_FORM_LENGTH_MASK) == 0)
            {
                return firstByte;
            }

            // Long form
            int lengthBytes = firstByte & TlvConstants.LENGTH_BYTES_MASK;
            if (lengthBytes == 0 || offset + lengthBytes > data.Length)
            {
                return null;
            }

            int length = 0;
            for (int i = 0; i < lengthBytes; i++)
            {
                length = (length << 8) | data[offset++];
            }

            return length;
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
            if (tagValue <= 0xFF)
            {
                return new[] { (byte)tagValue };
            }

            if (tagValue <= 0xFFFF)
            {
                return new[] { (byte)(tagValue >> 8), (byte)(tagValue & 0xFF) };
            }

            if (tagValue <= 0xFFFFFF)
            {
                return new[]
                {
                    (byte)(tagValue >> 16),
                    (byte)(tagValue >> 8),
                    (byte)(tagValue & 0xFF),
                };
            }

            return new[]
            {
                (byte)(tagValue >> 24),
                (byte)(tagValue >> 16),
                (byte)(tagValue >> 8),
                (byte)(tagValue & 0xFF),
            };
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
        public int Length => Value.Length;

        /// <summary>
        /// Gets the tag as a numeric value (for common 1-3 byte tags).
        /// </summary>
        public uint TagNumber => TlvParser.TagToNumber(Tag);

        /// <summary>
        /// Initializes a new instance of the TlvObject class.
        /// </summary>
        /// <param name="tag">The tag bytes.</param>
        /// <param name="value">The value bytes.</param>
        public TlvObject(byte[] tag, byte[] value)
        {
            ArgumentNullException.ThrowIfNull(tag);
            ArgumentNullException.ThrowIfNull(value);
            Tag = tag;
            Value = value;
        }

        /// <summary>
        /// Gets the value as a hex string.
        /// </summary>
        /// <returns>The value formatted as a hex string.</returns>
        public string GetValueAsHexString()
        {
            return BitConverter.ToString(Value).Replace("-", "");
        }

        /// <summary>
        /// Gets the tag as a hex string.
        /// </summary>
        /// <returns>The tag formatted as a hex string.</returns>
        public string GetTagAsHexString()
        {
            return BitConverter.ToString(Tag).Replace("-", "");
        }

        /// <summary>
        /// Gets the value as an unsigned integer (for numeric values).
        /// </summary>
        /// <returns>The numeric value or null if not applicable.</returns>
        public uint? GetValueAsNumber()
        {
            if (Value.Length == 0 || Value.Length > 4)
            {
                return null;
            }

            uint result = 0;
            foreach (var b in Value)
            {
                result = (result << 8) | b;
            }
            return result;
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
}
