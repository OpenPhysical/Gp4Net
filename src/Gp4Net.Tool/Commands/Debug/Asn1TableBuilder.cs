using System;
using System.Collections.Generic;
using System.Text.Json;
using CSharpFunctionalExtensions;
using Org.BouncyCastle.Asn1;

namespace Gp4Net.Tool.Commands.Debug;

/// <summary>
/// Pure functional table builder for ASN.1 parsing display.
/// Uses semantic row types and functional composition per CLAUDE.md patterns.
/// Handles hierarchical ASN.1 structure display.
/// </summary>
public static class Asn1TableBuilder
{
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
    public record ContainerHeaderRow(int Depth, string ContainerType, int ElementCount) : Asn1Row;

    /// <summary>
    /// Row indicating an element within a container.
    /// </summary>
    public record ElementHeaderRow(int Depth, int ElementIndex, string Description) : Asn1Row;

    /// <summary>
    /// Row for nested ASN.1 detection.
    /// </summary>
    public record NestedAsn1HeaderRow(int Depth, string Message = "Nested ASN.1 detected:")
        : Asn1Row;

    /// <summary>
    /// Summary information row.
    /// </summary>
    public record SummaryRow(string Message) : Asn1Row;

    /// <summary>
    /// Warning or informational message row.
    /// </summary>
    public record InfoRow(string Message, string Severity = "info") : Asn1Row;

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
        bool showOffsets = true
    )
    {
        if (data == null || data.Length == 0)
        {
            yield return new InfoRow("No data to parse", "warning");
            yield break;
        }

        yield return new SummaryRow($"Parsing {data.Length} bytes of ASN.1 data:");
        yield return new InfoRow($"Raw hex: {Convert.ToHexString(data)}");

        (Asn1Object asn1Object, string error) parseResult = TryParseAsn1(data);
        if (parseResult.asn1Object == null)
        {
            yield return new InfoRow($"Error parsing ASN.1 data: {parseResult.error}", "error");
            yield break;
        }

        foreach (
            Asn1Row row in BuildAsn1ObjectRows(parseResult.asn1Object, 0, 0, showBytes, showOffsets)
        )
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
        bool showOffsets
    )
    {
        string typeInfo = GetAsn1TypeInfo(obj);
        string offsetStr = showOffsets ? $"@{offset:X4}" : "";

        Maybe<string> rawBytes = Maybe<string>.None;
        if (showBytes && obj.GetEncoded() != null)
        {
            byte[] encoded = obj.GetEncoded();
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
        foreach (Asn1Row childRow in GetAsn1ChildRows(obj, depth, offset, showBytes, showOffsets))
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
        bool showOffsets
    )
    {
        switch (obj)
        {
            case Asn1Sequence sequence:
                yield return new ContainerHeaderRow(depth, "Sequence", sequence.Count);
                int seqOffset = offset + GetHeaderLength(obj);
                for (int i = 0; i < sequence.Count; i++)
                {
                    yield return new ElementHeaderRow(depth + 1, i, $"Element {i}:");
                    foreach (
                        Asn1Row row in BuildAsn1ObjectRows(
                            sequence[i].ToAsn1Object(),
                            depth + 2,
                            seqOffset,
                            showBytes,
                            showOffsets
                        )
                    )
                    {
                        yield return row;
                    }
                    seqOffset += sequence[i].GetEncoded().Length;
                }
                break;

            case Asn1Set set:
                yield return new ContainerHeaderRow(depth, "Set", set.Count);
                int setOffset = offset + GetHeaderLength(obj);
                for (int i = 0; i < set.Count; i++)
                {
                    yield return new ElementHeaderRow(depth + 1, i, $"Element {i}:");
                    foreach (
                        Asn1Row row in BuildAsn1ObjectRows(
                            set[i].ToAsn1Object(),
                            depth + 2,
                            setOffset,
                            showBytes,
                            showOffsets
                        )
                    )
                    {
                        yield return row;
                    }
                    setOffset += set[i].GetEncoded().Length;
                }
                break;

            case DerOctetString octetString:
                byte[] octets = octetString.GetOctets();

                // Try to parse nested ASN.1 if it looks like it
                if (octets.Length > 2 && IsLikelyAsn1(octets))
                {
                    (Asn1Object asn1Object, string error) nestedResult = TryParseAsn1(octets);
                    if (nestedResult.asn1Object != null)
                    {
                        yield return new NestedAsn1HeaderRow(depth + 1);
                        foreach (
                            Asn1Row row in BuildAsn1ObjectRows(
                                nestedResult.asn1Object,
                                depth + 2,
                                0,
                                showBytes,
                                showOffsets
                            )
                        )
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
            DerOctetString octetString => Maybe<string>.From(
                $"Value: {Convert.ToHexString(octetString.GetOctets())} ({octetString.GetOctets().Length} bytes)"
            ),
            DerInteger integer => Maybe<string>.From($"Value: {integer.Value}"),
            DerObjectIdentifier oid => Maybe<string>.From($"OID: {oid.Id}"),
            DerUtf8String utf8 => Maybe<string>.From($"Value: \"{utf8.GetString()}\""),
            DerPrintableString printable => Maybe<string>.From(
                $"Value: \"{printable.GetString()}\""
            ),
            DerBitString bitString => Maybe<string>.From(
                $"Bits: {Convert.ToHexString(bitString.GetBytes())} (unused bits: {bitString.PadBits})"
            ),
            _ when obj.GetEncoded()?.Length > 0 => Maybe<string>.From(
                $"Raw data: {Convert.ToHexString(obj.GetEncoded())}"
            ),
            _ => Maybe<string>.None,
        };
    }

    /// <summary>
    /// Exports ASN.1 structure to JSON format using pure functions.
    /// </summary>
    public static string ToJson(IEnumerable<Asn1Row> rows)
    {
        List<object> data = [];

        foreach (Asn1Row row in rows)
        {
            object item = row switch
            {
                Asn1DataRow(var depth, var offset, var typeInfo, var value, var rawBytes) => new
                {
                    type = "data",
                    depth,
                    offset,
                    typeInfo,
                    value = value.GetValueOrDefault(""),
                    rawBytes = rawBytes.GetValueOrDefault(""),
                },
                ContainerHeaderRow(var depth, var containerType, var elementCount) => new
                {
                    type = "container",
                    depth,
                    containerType,
                    elementCount,
                },
                ElementHeaderRow(var depth, var elementIndex, var description) => new
                {
                    type = "element",
                    depth,
                    elementIndex,
                    description,
                },
                NestedAsn1HeaderRow(var depth, var message) => new
                {
                    type = "nested",
                    depth,
                    message,
                },
                SummaryRow(var message) => new { type = "summary", message },
                InfoRow(var message, var severity) => new
                {
                    type = "info",
                    message,
                    severity,
                },
                _ => new { type = "unknown", data = row.ToString() },
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
            Asn1Object asn1Object = Asn1Object.FromByteArray(data);
            return (asn1Object, null);
        }
        catch (Exception ex)
        {
            return (null, ex.Message);
        }
    }

    /// <summary>
    /// Gets type information for an ASN.1 object.
    /// </summary>
    private static string GetAsn1TypeInfo(Asn1Object obj)
    {
        byte[] encoded = obj.GetEncoded();
        if (encoded == null || encoded.Length == 0)
        {
            return "Invalid ASN.1 object";
        }

        byte tag = encoded[0];
        int tagClass = (tag & 0xC0) >> 6;
        bool constructed = (tag & 0x20) != 0;
        int tagNumber = tag & 0x1F;

        string classStr = tagClass switch
        {
            0 => "Universal",
            1 => "Application",
            2 => "Context",
            3 => "Private",
            _ => "Unknown",
        };

        string typeStr = obj.GetType().Name;
        string lengthInfo = GetLengthInfo(encoded);

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

        byte lengthByte = encoded[1];
        if ((lengthByte & 0x80) == 0)
        {
            return lengthByte.ToString();
        }
        int lengthBytes = lengthByte & 0x7F;
        if (lengthBytes == 0)
        {
            return "indefinite";
        }

        int length = 0;
        for (int i = 0; i < lengthBytes && i + 2 < encoded.Length; i++)
        {
            length = length << 8 | encoded[i + 2];
        }
        return $"{length} (long form, {lengthBytes} bytes)";
    }

    /// <summary>
    /// Gets the header length of an ASN.1 object.
    /// </summary>
    private static int GetHeaderLength(Asn1Object obj)
    {
        byte[] encoded = obj.GetEncoded();
        if (encoded.Length < 2)
        {
            return 2;
        }

        byte lengthByte = encoded[1];
        if ((lengthByte & 0x80) == 0)
        {
            return 2; // Tag + short length
        }
        return 2 + (lengthByte & 0x7F); // Tag + long length indicator + length bytes
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

        byte tag = data[0];
        byte length = data[1];

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

        // Long form
        int lengthBytes = length & 0x7F;
        return lengthBytes is > 0 and <= 4 && data.Length >= lengthBytes + 2;
    }
}
