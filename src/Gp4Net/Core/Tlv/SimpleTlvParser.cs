using System;
using System.Collections.Generic;

namespace Gp4Net.Core.Tlv;

/// <summary>
/// Simple TLV (Tag-Length-Value) parser for card data structures.
/// This parser handles the TLV format used in GlobalPlatform card data,
/// which is similar to but not identical to ASN.1 DER encoding.
/// </summary>
public static class SimpleTlvParser
{
    /// <summary>
    /// Enumerates all TLV elements in the provided data.
    /// </summary>
    /// <param name="data">The TLV-encoded data to parse.</param>
    /// <returns>An enumerable of parsed TLV elements.</returns>
    public static IEnumerable<ParsedTlvElement> Enumerate(byte[] data)
    {
        int offset = 0;

        while (offset + 2 <= data.Length)
        {
            int start = offset;
            byte tag = data[offset++];
            byte lenByte = data[offset++];

            int contentLength;

            if ((lenByte & 0x80) == 0)
            {
                // Short form
                contentLength = lenByte;
            }
            else
            {
                // Long form
                int lenLength = lenByte & 0x7F;

                if (lenLength == 0 || lenLength > 4 || offset + lenLength > data.Length)
                {
                    yield break; // invalid or unsupported
                }

                contentLength = 0;
                for (int i = 0; i < lenLength; i++)
                {
                    contentLength = (contentLength << 8) | data[offset++];
                }

                if (contentLength < 0)
                {
                    yield break; // invalid
                }
            }

            int totalLen = offset - start + contentLength;
            if (offset + contentLength > data.Length)
            {
                yield break; // truncated
            }

            byte[] content = new byte[contentLength];
            Buffer.BlockCopy(data, offset, content, 0, contentLength);
            yield return new ParsedTlvElement(tag, content, start, totalLen);

            offset += contentLength;
        }
    }
}

/// <summary>
/// Represents a parsed TLV element.
/// </summary>
public readonly struct ParsedTlvElement
{
    /// <summary>
    /// The tag byte of the TLV element.
    /// </summary>
    public byte Tag { get; }

    /// <summary>
    /// The content bytes of the TLV element.
    /// </summary>
    public byte[] Content { get; }

    /// <summary>
    /// The offset in the original data where this element starts.
    /// </summary>
    public int Offset { get; }

    /// <summary>
    /// The total length of this element including tag and length bytes.
    /// </summary>
    public int TotalLength { get; }

    public ParsedTlvElement(byte tag, byte[] content, int offset, int totalLength)
    {
        Tag = tag;
        Content = content;
        Offset = offset;
        TotalLength = totalLength;
    }
}
