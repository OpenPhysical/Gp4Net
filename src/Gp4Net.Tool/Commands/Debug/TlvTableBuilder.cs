using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Services;
using static Gp4Net.Services.TlvService;
using Gp4Net.Tool.Common;
using Gp4Net.Constants;

namespace Gp4Net.Tool.Commands.Debug;

/// <summary>
/// Pure functional table builder for TLV parsing display.
/// Uses semantic row types and functional composition per CLAUDE.md patterns.
/// Handles hierarchical TLV structure display.
/// </summary>
public static class TlvTableBuilder
{
    /// <summary>
    /// Base type for all TLV display rows, inheriting from semantic row system.
    /// </summary>
    public abstract record TlvRow : SemanticTableBuilder.SemanticRow;

    /// <summary>
    /// Row displaying TLV element information.
    /// </summary>
    public record TlvDataRow(
        int ElementIndex,
        int Depth,
        string TagInfo,
        string LengthInfo,
        Maybe<string> Content = default,
        Maybe<string> AsciiContent = default,
        Maybe<string> RawBytes = default
    ) : TlvRow;

    /// <summary>
    /// Row for nested TLV detection.
    /// </summary>
    public record NestedTlvHeaderRow(int Depth, string Message = "Nested TLV detected:") : TlvRow;

    /// <summary>
    /// Row for known tag interpretations.
    /// </summary>
    public record TagInterpretationRow(int Depth, string Interpretation) : TlvRow;

    /// <summary>
    /// Summary information row.
    /// </summary>
    public record SummaryRow(string Message) : TlvRow;

    /// <summary>
    /// Warning or informational message row.
    /// </summary>
    public record InfoRow(string Message, string Severity = "info") : TlvRow;

    /// <summary>
    /// Main entry point to build TLV parsing rows using functional composition.
    /// Returns semantic row types that can be rendered by any UI framework.
    /// </summary>
    /// <param name="data">Raw TLV data bytes</param>
    /// <param name="showBytes">Whether to include raw byte values</param>
    /// <param name="showOffsets">Whether to include byte offsets</param>
    /// <param name="recursive">Whether to parse nested TLV structures</param>
    /// <returns>Sequence of semantic TLV rows</returns>
    public static IEnumerable<TlvRow> BuildTlvRows(
        byte[] data,
        bool showBytes = false,
        bool showOffsets = true,
        bool recursive = true
    )
    {
        if (data == null || data.Length == 0)
        {
            yield return new InfoRow("No data to parse", "warning");
            yield break;
        }

        yield return new SummaryRow($"Parsing {data.Length} bytes of TLV data:");
        yield return new InfoRow($"Raw hex: {Convert.ToHexString(data)}");

        (IEnumerable<TlvObject> elements, string error) parseResult = TryParseTlv(data);
        if (parseResult.elements == null || !parseResult.elements.Any())
        {
            if (!string.IsNullOrEmpty(parseResult.error))
            {
                yield return new InfoRow($"Error parsing TLV data: {parseResult.error}", "error");
            }
            else
            {
                yield return new InfoRow("No valid TLV elements found", "warning");
            }
            yield break;
        }

        int elementIndex = 0;
        foreach (TlvObject element in parseResult.elements)
        {
            foreach (
                TlvRow row in BuildTlvElementRows(element, elementIndex++, 0, showBytes, recursive)
            )
            {
                yield return row;
            }
        }
    }

    /// <summary>
    /// Recursively builds rows for a TLV element and its children.
    /// </summary>
    private static IEnumerable<TlvRow> BuildTlvElementRows(
        TlvObject element,
        int elementIndex,
        int depth,
        bool showBytes,
        bool recursive
    )
    {
        string tagInfo = GetTagInfo(element);
        string lengthInfo = GetLengthInfo(element);
        Maybe<string> content = GetTlvContent(element);
        Maybe<string> asciiContent = GetAsciiContent(element);

        Maybe<string> rawBytes = Maybe<string>.None;
        if (showBytes)
        {
            byte[] fullBytes = GetFullElementBytes(element);
            rawBytes = Maybe<string>.From($"Full TLV: {Convert.ToHexString(fullBytes)}");
        }

        yield return new TlvDataRow(
            ElementIndex: elementIndex,
            Depth: depth,
            TagInfo: tagInfo,
            LengthInfo: lengthInfo,
            Content: content,
            AsciiContent: asciiContent,
            RawBytes: rawBytes
        );

        // Add known tag interpretation if available
        Maybe<string> interpretation = GetKnownTagInterpretation(element);
        if (interpretation.HasValue)
        {
            yield return new TagInterpretationRow(depth + 1, interpretation.Value);
        }

        // Recursive parsing if enabled and content looks like TLV
        if (recursive && element.TlvData.Bytes.Length > 2 && IsLikelyTlv(element.TlvData.Bytes.ToArray()))
        {
            (IEnumerable<TlvObject> elements, string error) nestedResult = TryParseTlv(
                element.TlvData.Bytes.ToArray()
            );
            if (nestedResult.elements != null && nestedResult.elements.Any())
            {
                yield return new NestedTlvHeaderRow(depth + 1);
                int nestedIndex = 0;
                foreach (TlvObject nested in nestedResult.elements)
                {
                    foreach (
                        TlvRow row in BuildTlvElementRows(
                            nested,
                            nestedIndex++,
                            depth + 2,
                            showBytes,
                            recursive
                        )
                    )
                    {
                        yield return row;
                    }
                }
            }
        }
    }

    /// <summary>
    /// Exports TLV structure to JSON format using pure functions.
    /// </summary>
    public static string ToJson(IEnumerable<TlvRow> rows)
    {
        List<object> data = [];

        foreach (TlvRow row in rows)
        {
            object item = row switch
            {
                TlvDataRow(
                    var elementIndex,
                    var depth,
                    var tagInfo,
                    var lengthInfo,
                    var content,
                    var asciiContent,
                    var rawBytes
                ) => new
                {
                    type = "data",
                    elementIndex,
                    depth,
                    tagInfo,
                    lengthInfo,
                    content = content.GetValueOrDefault(""),
                    asciiContent = asciiContent.GetValueOrDefault(""),
                    rawBytes = rawBytes.GetValueOrDefault(""),
                },
                NestedTlvHeaderRow(var depth, var message) => new
                {
                    type = "nested",
                    depth,
                    message,
                },
                TagInterpretationRow(var depth, var interpretation) => new
                {
                    type = "interpretation",
                    depth,
                    interpretation,
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
    /// Safely tries to parse TLV data without throwing exceptions.
    /// </summary>
    private static (IEnumerable<TlvObject> elements, string error) TryParseTlv(byte[] data)
    {
        try
        {
            var parseResult = TlvService.TlvParser.ParseMultiple(data.ToImmutableArray());
            if (parseResult.IsFailure)
                return (Enumerable.Empty<TlvObject>(), parseResult.Error.Message);
            IReadOnlyList<TlvObject> elements = parseResult.Value.Objects;
            return (elements, null);
        }
        catch (Exception ex)
        {
            return (null, ex.Message);
        }
    }

    /// <summary>
    /// Gets tag information for a TLV element.
    /// </summary>
    private static string GetTagInfo(TlvObject element)
    {
        string tagHex = Convert.ToHexString(element.Tag.Bytes.ToArray());
        byte firstTagByte = element.Tag.Bytes[0];
        Result<uint, SmartCardError> tagNumberResult = element.Tag.ToNumber();
        string tagName = tagNumberResult.IsSuccess
            ? GetKnownTagName(tagNumberResult.Value)
            : "UNKNOWN";
        string tagClass = GetTagClass(firstTagByte);
        string constructed = (firstTagByte & 0x20) != 0 ? "constructed" : "primitive";

        return $"Tag {tagHex} ({tagName}) - {tagClass}, {constructed}";
    }

    /// <summary>
    /// Gets known tag name for common GlobalPlatform/GP tags.
    /// </summary>
    private static string GetKnownTagName(uint tag)
    {
        return tag switch
        {
            0x4F => "AID (Application Identifier)",
            0x61 => "Application Template",
            0x62 => "FCP Template",
            0x6F => "FCI Template",
            0x73 => "Security Support Template",
            0x80 => "Response Message Template",
            0x81 => "Card Capabilities/Secure Messaging Support",
            0x82 => "Secure Channel Protocol Data",
            0x83 => "Additional Security Capabilities",
            0x84 => "DF Name",
            0x85 => "FCI Proprietary Template",
            0x86 => "Supported Key Lengths",
            0x87 => "Security Attributes",
            0x88 => "SCP Capabilities",
            0x8A => "Life Cycle State",
            0x8E => "SCP Domain Management",
            0x70 => "Card Data Object (0x9F70)",
            0xC4 => "Key Information Template",
            0xC5 => "Key Information Data",
            0xCF => "Diversification Data",
            0xE0 => "Key Information",
            _ => "Unknown",
        };
    }

    /// <summary>
    /// Gets tag class description.
    /// </summary>
    private static string GetTagClass(byte tag)
    {
        return (tag & 0xC0) switch
        {
            0x00 => "Universal",
            0x40 => "Application",
            0x80 => "Context",
            0xC0 => "Private",
            _ => "Unknown",
        };
    }

    /// <summary>
    /// Gets length information string.
    /// </summary>
    private static string GetLengthInfo(TlvObject element)
    {
        return $"{element.TlvData.Bytes.Length} bytes";
    }

    /// <summary>
    /// Gets content display for TLV element.
    /// </summary>
    private static Maybe<string> GetTlvContent(TlvObject element)
    {
        switch (element.TlvData.Bytes.Length)
        {
            case 0:
                return Maybe<string>.From("(empty)");
            case <= 32:
            {
                // Short content - show as hex
                string hexContent = Convert.ToHexString(element.TlvData.Bytes.ToArray());
                return Maybe<string>.From($"Content: {hexContent}");
            }
            default:
            {
                // Long content - show truncated hex
                byte[] valueBytes = element.TlvData.Bytes.ToArray();
                byte[] truncated = valueBytes[..16];
                string hexContent = Convert.ToHexString(truncated);
                return Maybe<string>.From(
                    $"Content: {hexContent}... ({valueBytes.Length} bytes total)"
                );
            }
        }
    }

    /// <summary>
    /// Gets ASCII content if printable.
    /// </summary>
    private static Maybe<string> GetAsciiContent(TlvObject element)
    {
        byte[] valueBytes = element.TlvData.Bytes.ToArray();
        if (valueBytes.Length is > 0 and <= 32 && IsPrintableAscii(valueBytes))
        {
            string ascii = Encoding.ASCII.GetString(valueBytes);
            return Maybe<string>.From($"ASCII: \"{ascii}\"");
        }
        return Maybe<string>.None;
    }

    /// <summary>
    /// Gets known tag interpretation.
    /// </summary>
    private static Maybe<string> GetKnownTagInterpretation(TlvObject element)
    {
        return element
            .Tag.ToNumber()
            .Match(
                tagNumber => InterpretByTagNumber(tagNumber, element),
                error => Maybe<string>.None
            );
    }

    private static Maybe<string> InterpretByTagNumber(uint tagNumber, TlvObject element)
    {
        byte[] elementValue = GetTlvValueUsingReflection(element);
        if (elementValue == null)
            return Maybe<string>.None;

        return tagNumber switch
        {
            0x4F when elementValue.Length >= 5 => Maybe<string>.From(
                $"AID: {Convert.ToHexString(elementValue)}"
            ),
            0x8A when elementValue.Length == 1 => Maybe<string>.From(
                $"Life Cycle: {GetLifeCycleStateName(elementValue[0])}"
            ),
            0x81 or 0x82 or 0x83 => Maybe<string>.From(
                "Security-related data - may indicate SCP support"
            ),
            _ => Maybe<string>.None,
        };
    }

    private static byte[] GetTlvValueUsingReflection(TlvObject element)
    {
        PropertyInfo valueProperty = typeof(TlvObject).GetProperty("Value");
        return valueProperty?.GetValue(element) as byte[] ?? [];
    }

    /// <summary>
    /// Gets life cycle state name.
    /// </summary>
    private static string GetLifeCycleStateName(byte state)
    {
        return state switch
        {
            0x01 => "OP_READY",
            0x03 => "INITIALIZED",
            0x07 => "SECURED",
            0x0F => "CARD_LOCKED",
            0x7F => "TERMINATED",
            _ => $"Unknown (0x{state:X2})",
        };
    }

    /// <summary>
    /// Reconstructs the full TLV element bytes.
    /// </summary>
    private static byte[] GetFullElementBytes(TlvObject element)
    {
        // Calculate total length
        int tagLength = element.Tag.Bytes.Length;
        int valueLength = element.TlvData.Bytes.Length;
        int lengthFieldSize;

        switch (valueLength)
        {
            case < 128:
                lengthFieldSize = 1;
                break;
            case <= 255:
                lengthFieldSize = 2;
                break;
            default:
                // For now, assume max 2-byte length encoding
                lengthFieldSize = 3;
                break;
        }

        byte[] result = new byte[tagLength + lengthFieldSize + valueLength];

        // Copy tag
        Array.Copy(element.Tag.Bytes.ToArray(), 0, result, 0, tagLength);

        // Encode length
        int offset = tagLength;
        if (valueLength < 0x80)
        {
            // Short form
            result[offset] = (byte)valueLength;
            offset++;
        }
        else
        {
            // Long form - one byte length
            result[offset] = 0x81;
            result[offset + 1] = (byte)valueLength;
            offset += 2;
        }

        // Copy value
        Array.Copy(element.TlvData.Bytes.ToArray(), 0, result, offset, valueLength);

        return result;
    }

    /// <summary>
    /// Checks if data looks like TLV.
    /// </summary>
    private static bool IsLikelyTlv(byte[] data)
    {
        if (data.Length < 2)
        {
            return false;
        }

        (IEnumerable<TlvObject> elements, string error) parseResult = TryParseTlv(data);
        return parseResult.elements?.Any() == true;
    }

    /// <summary>
    /// Checks if data contains printable ASCII characters.
    /// </summary>
    private static bool IsPrintableAscii(byte[] data)
    {
        foreach (byte b in data)
        {
            if (b is < 32 or > 126)
            {
                return false;
            }
        }
        return true;
    }
}
