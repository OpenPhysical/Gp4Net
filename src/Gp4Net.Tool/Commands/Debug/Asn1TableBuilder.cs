using System;
using System.Collections.Generic;
using System.Text.Json;
using Org.BouncyCastle.Asn1;
using CSharpFunctionalExtensions;

namespace Gp4Net.Tool.Commands.Debug;

/// <summary>
/// Pure functional table builder for ASN.1 parsing display.
/// Uses semantic row types and functional composition per CLAUDE.md patterns.
/// Handles hierarchical ASN.1 structure display.
/// </summary>
public static class Asn1TableBuilder
{
    #region Semantic Row Types

    /// <summary>
    /// Base type for all ASN.1 display rows, enabling type-safe UI composition.
    /// </summary>
    public abstract record Asn1Row;

    /// <summary>
    /// Row displaying ASN.1 object information.
    /// </summary>
    public record Asn1DataRow(
        int Depth,
        string Offset,
        string TypeInfo,
        Maybe<string> Value = default,
        Maybe<string> RawBytes = default
    ) : Asn1Row;

    /// <summary>
    /// Row indicating the start of a container (sequence, set, etc).
    /// </summary>
    public record ContainerHeaderRow(
        int Depth,
        string ContainerType,
        int ElementCount
    ) : Asn1Row;

    /// <summary>
    /// Row indicating an element within a container.
    /// </summary>
    public record ElementHeaderRow(
        int Depth,
        int ElementIndex,
        string Description
    ) : Asn1Row;

    /// <summary>
    /// Row for nested ASN.1 detection.
    /// </summary>
    public record NestedAsn1HeaderRow(
        int Depth,
        string Message = "Nested ASN.1 detected:"
    ) : Asn1Row;

    /// <summary>
    /// Summary information row.
    /// </summary>
    public record SummaryRow(string Message) : Asn1Row;

    /// <summary>
    /// Warning or informational message row.
    /// </summary>
    public record InfoRow(string Message, string Severity = "info") : Asn1Row;

    #endregion

    /// <summary>
    /// Main entry point to build ASN.1 parsing rows using functional composition.
    /// Returns semantic row types that can be rendered by any UI framework.
    /// </summary>
    /// <param name="data">Raw ASN.1 data bytes</param>
    /// <param name="showBytes">Whether to include raw byte values</param>
    /// <param name="showOffsets">Whether to include byte offsets</param>
    /// <returns>Sequence of semantic ASN.1 rows</returns>
    public static IEnumerable<Asn1Row> BuildAsn1Rows(
        byte[] data,
        bool showBytes = false,
        bool showOffsets = true)
    {
        if (data == null || data.Length == 0)
        {
            yield return new InfoRow("No data to parse", "warning");
            yield break;
        }

        yield return new SummaryRow($"Parsing {data.Length} bytes of ASN.1 data:");
        yield return new InfoRow($"Raw hex: {Convert.ToHexString(data)}", "info");

        var parseResult = TryParseAsn1(data);
        if (parseResult.asn1Object == null)
        {
            yield return new InfoRow($"Error parsing ASN.1 data: {parseResult.error}", "error");
            yield break;
        }

        foreach (var row in BuildAsn1ObjectRows(parseResult.asn1Object, 0, 0, showBytes, showOffsets))
        {
            yield return row;
        }
    }

    /// <summary>
    /// Recursively builds rows for an ASN.1 object and its children.
    /// </summary>
    private static IEnumerable<Asn1Row> BuildAsn1ObjectRows(
        Asn1Object obj,
        int depth,
        int offset,
        bool showBytes,
        bool showOffsets)
    {
        var typeInfo = GetAsn1TypeInfo(obj);
        var offsetStr = showOffsets ? $"@{offset:X4}" : "";
        
        var rawBytes = Maybe<string>.None;
        if (showBytes && obj.GetEncoded() != null)
        {
            var encoded = obj.GetEncoded();
            rawBytes = Maybe<string>.From($"Bytes: {Convert.ToHexString(encoded)}");
        }

        yield return new Asn1DataRow(
            Depth: depth,
            Offset: offsetStr,
            TypeInfo: typeInfo,
            Value: GetAsn1Value(obj),
            RawBytes: rawBytes
        );

        // Handle different ASN.1 types
        foreach (var childRow in GetAsn1ChildRows(obj, depth, offset, showBytes, showOffsets))
        {
            yield return childRow;
        }
    }

    /// <summary>
    /// Gets child rows for container ASN.1 types.
    /// </summary>
    private static IEnumerable<Asn1Row> GetAsn1ChildRows(
        Asn1Object obj,
        int depth,
        int offset,
        bool showBytes,
        bool showOffsets)
    {
        switch (obj)
        {
            case Asn1Sequence sequence:
                yield return new ContainerHeaderRow(depth, "Sequence", sequence.Count);
                var seqOffset = offset + GetHeaderLength(obj);
                for (var i = 0; i < sequence.Count; i++)
                {
                    yield return new ElementHeaderRow(depth + 1, i, $"Element {i}:");
                    foreach (var row in BuildAsn1ObjectRows(sequence[i].ToAsn1Object(), depth + 2, seqOffset, showBytes, showOffsets))
                    {
                        yield return row;
                    }
                    seqOffset += sequence[i].GetEncoded().Length;
                }
                break;

            case Asn1Set set:
                yield return new ContainerHeaderRow(depth, "Set", set.Count);
                var setOffset = offset + GetHeaderLength(obj);
                for (var i = 0; i < set.Count; i++)
                {
                    yield return new ElementHeaderRow(depth + 1, i, $"Element {i}:");
                    foreach (var row in BuildAsn1ObjectRows(set[i].ToAsn1Object(), depth + 2, setOffset, showBytes, showOffsets))
                    {
                        yield return row;
                    }
                    setOffset += set[i].GetEncoded().Length;
                }
                break;

            case DerOctetString octetString:
                var octets = octetString.GetOctets();
                
                // Try to parse nested ASN.1 if it looks like it
                if (octets.Length > 2 && IsLikelyAsn1(octets))
                {
                    var nestedResult = TryParseAsn1(octets);
                    if (nestedResult.asn1Object != null)
                    {
                        yield return new NestedAsn1HeaderRow(depth + 1);
                        foreach (var row in BuildAsn1ObjectRows(nestedResult.asn1Object, depth + 2, 0, showBytes, showOffsets))
                        {
                            yield return row;
                        }
                    }
                }
                break;
        }
    }

    /// <summary>
    /// Gets the display value for an ASN.1 object.
    /// </summary>
    private static Maybe<string> GetAsn1Value(Asn1Object obj)
    {
        return obj switch
        {
            DerOctetString octetString => Maybe<string>.From($"Value: {Convert.ToHexString(octetString.GetOctets())} ({octetString.GetOctets().Length} bytes)"),
            DerInteger integer => Maybe<string>.From($"Value: {integer.Value}"),
            DerObjectIdentifier oid => Maybe<string>.From($"OID: {oid.Id}"),
            DerUtf8String utf8 => Maybe<string>.From($"Value: \"{utf8.GetString()}\""),
            DerPrintableString printable => Maybe<string>.From($"Value: \"{printable.GetString()}\""),
            DerBitString bitString => Maybe<string>.From($"Bits: {Convert.ToHexString(bitString.GetBytes())} (unused bits: {bitString.PadBits})"),
            _ when obj.GetEncoded()?.Length > 0 => Maybe<string>.From($"Raw data: {Convert.ToHexString(obj.GetEncoded())}"),
            _ => Maybe<string>.None
        };
    }

    /// <summary>
    /// Exports ASN.1 structure to JSON format using pure functions.
    /// </summary>
    public static string ToJson(IEnumerable<Asn1Row> rows)
    {
        var data = new List<object>();
        
        foreach (var row in rows)
        {
            object item = row switch
            {
                Asn1TableBuilder.Asn1DataRow(var depth, var offset, var typeInfo, var value, var rawBytes) => new
                {
                    type = "data",
                    depth,
                    offset,
                    typeInfo,
                    value = value.GetValueOrDefault(""),
                    rawBytes = rawBytes.GetValueOrDefault("")
                },
                Asn1TableBuilder.ContainerHeaderRow(var depth, var containerType, var elementCount) => new
                {
                    type = "container",
                    depth,
                    containerType,
                    elementCount
                },
                Asn1TableBuilder.ElementHeaderRow(var depth, var elementIndex, var description) => new
                {
                    type = "element",
                    depth,
                    elementIndex,
                    description
                },
                Asn1TableBuilder.NestedAsn1HeaderRow(var depth, var message) => new
                {
                    type = "nested",
                    depth,
                    message
                },
                Asn1TableBuilder.SummaryRow(var message) => new { type = "summary", message },
                Asn1TableBuilder.InfoRow(var message, var severity) => new { type = "info", message, severity },
                _ => new { type = "unknown", data = row.ToString() }
            };
            
            data.Add(item);
        }

        return JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>
    /// Safely tries to parse ASN.1 data without throwing exceptions.
    /// </summary>
    private static (Asn1Object asn1Object, string error) TryParseAsn1(byte[] data)
    {
        try
        {
            var asn1Object = Asn1Object.FromByteArray(data);
            return (asn1Object, null);
        }
        catch (Exception ex)
        {
            return (null, ex.Message);
        }
    }

    #region Pure Helper Functions

    /// <summary>
    /// Gets type information for an ASN.1 object.
    /// </summary>
    private static string GetAsn1TypeInfo(Asn1Object obj)
    {
        var encoded = obj.GetEncoded();
        if (encoded == null || encoded.Length == 0)
        {
            return "Invalid ASN.1 object";
        }

        var tag = encoded[0];
        var tagClass = (tag & 0xC0) >> 6;
        var constructed = (tag & 0x20) != 0;
        var tagNumber = tag & 0x1F;

        var classStr = tagClass switch
        {
            0 => "Universal",
            1 => "Application", 
            2 => "Context",
            3 => "Private",
            _ => "Unknown"
        };

        var typeStr = obj.GetType().Name;
        var lengthInfo = GetLengthInfo(encoded);

        return $"{classStr} {typeStr} (tag={tag:X2}, constructed={constructed}, length={lengthInfo})";
    }

    /// <summary>
    /// Gets length information from encoded ASN.1 data.
    /// </summary>
    private static string GetLengthInfo(byte[] encoded)
    {
        if (encoded.Length < 2)
        {
            return "?";
        }

        var lengthByte = encoded[1];
        if ((lengthByte & 0x80) == 0)
        {
            return lengthByte.ToString();
        }
        else
        {
            var lengthBytes = lengthByte & 0x7F;
            if (lengthBytes == 0)
            {
                return "indefinite";
            }

            var length = 0;
            for (var i = 0; i < lengthBytes && i + 2 < encoded.Length; i++)
            {
                length = (length << 8) | encoded[i + 2];
            }
            return $"{length} (long form, {lengthBytes} bytes)";
        }
    }

    /// <summary>
    /// Gets the header length of an ASN.1 object.
    /// </summary>
    private static int GetHeaderLength(Asn1Object obj)
    {
        var encoded = obj.GetEncoded();
        if (encoded.Length < 2)
        {
            return 2;
        }

        var lengthByte = encoded[1];
        if ((lengthByte & 0x80) == 0)
        {
            return 2; // Tag + short length
        }
        else
        {
            return 2 + (lengthByte & 0x7F); // Tag + long length indicator + length bytes
        }
    }

    /// <summary>
    /// Checks if data looks like ASN.1.
    /// </summary>
    private static bool IsLikelyAsn1(byte[] data)
    {
        if (data.Length < 2)
        {
            return false;
        }

        var tag = data[0];
        var length = data[1];
            
        // Check if tag looks reasonable (common ASN.1 tags)
        if ((tag & 0x1F) > 30)
        {
            return false;
        }

        // Check length encoding
        if ((length & 0x80) == 0)
        {
            // Short form - check if data length matches
            return data.Length >= length + 2;
        }
        else
        {
            // Long form
            var lengthBytes = length & 0x7F;
            return lengthBytes is > 0 and <= 4 && data.Length >= lengthBytes + 2;
        }
    }

    #endregion
}