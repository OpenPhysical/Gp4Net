using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using CSharpFunctionalExtensions;
using Gp4Net.Core.Tlv;

namespace Gp4Net.Tool.Commands.Debug;

/// <summary>
/// Pure functional table builder for TLV parsing display.
/// Uses semantic row types and functional composition per CLAUDE.md patterns.
/// Handles hierarchical TLV structure display.
/// </summary>
public static class TlvTableBuilder
{
    #region Semantic Row Types

    /// <summary>
    /// Base type for all TLV display rows, enabling type-safe UI composition.
    /// </summary>
    public abstract record TlvRow;

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
    public record NestedTlvHeaderRow(
        int Depth,
        string Message = "Nested TLV detected:"
    ) : TlvRow;

    /// <summary>
    /// Row for known tag interpretations.
    /// </summary>
    public record TagInterpretationRow(
        int Depth,
        string Interpretation
    ) : TlvRow;

    /// <summary>
    /// Summary information row.
    /// </summary>
    public record SummaryRow(string Message) : TlvRow;

    /// <summary>
    /// Warning or informational message row.
    /// </summary>
    public record InfoRow(string Message, string Severity = "info") : TlvRow;

    #endregion

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
        bool recursive = true)
    {
        if (data == null || data.Length == 0)
        {
            yield return new InfoRow("No data to parse", "warning");
            yield break;
        }

        yield return new SummaryRow($"Parsing {data.Length} bytes of TLV data:");
        yield return new InfoRow($"Raw hex: {Convert.ToHexString(data)}", "info");

        var parseResult = TryParseTlv(data);
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

        var elementIndex = 0;
        foreach (var element in parseResult.elements)
        {
            foreach (var row in BuildTlvElementRows(element, elementIndex++, 0, showBytes, recursive))
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
        bool recursive)
    {
        var tagInfo = GetTagInfo(element);
        var lengthInfo = GetLengthInfo(element);
        var content = GetTlvContent(element);
        var asciiContent = GetAsciiContent(element);

        var rawBytes = Maybe<string>.None;
        if (showBytes)
        {
            var fullBytes = GetFullElementBytes(element);
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
        var interpretation = GetKnownTagInterpretation(element);
        if (interpretation.HasValue)
        {
            yield return new TagInterpretationRow(depth + 1, interpretation.Value);
        }

        // Recursive parsing if enabled and content looks like TLV
        if (recursive && element.Value.Length > 2 && IsLikelyTlv(element.Value))
        {
            var nestedResult = TryParseTlv(element.Value);
            if (nestedResult.elements != null && nestedResult.elements.Any())
            {
                yield return new NestedTlvHeaderRow(depth + 1);
                var nestedIndex = 0;
                foreach (var nested in nestedResult.elements)
                {
                    foreach (var row in BuildTlvElementRows(nested, nestedIndex++, depth + 2, showBytes, recursive))
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
        var data = new List<object>();
        
        foreach (var row in rows)
        {
            object item = row switch
            {
                TlvTableBuilder.TlvDataRow(var elementIndex, var depth, var tagInfo, var lengthInfo, var content, var asciiContent, var rawBytes) => new
                {
                    type = "data",
                    elementIndex,
                    depth,
                    tagInfo,
                    lengthInfo,
                    content = content.GetValueOrDefault(""),
                    asciiContent = asciiContent.GetValueOrDefault(""),
                    rawBytes = rawBytes.GetValueOrDefault("")
                },
                TlvTableBuilder.NestedTlvHeaderRow(var depth, var message) => new
                {
                    type = "nested",
                    depth,
                    message
                },
                TlvTableBuilder.TagInterpretationRow(var depth, var interpretation) => new
                {
                    type = "interpretation",
                    depth,
                    interpretation
                },
                TlvTableBuilder.SummaryRow(var message) => new { type = "summary", message },
                TlvTableBuilder.InfoRow(var message, var severity) => new { type = "info", message, severity },
                _ => new { type = "unknown", data = row.ToString() }
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
            var elements = TlvParser.ParseAll(data);
            return (elements, null);
        }
        catch (Exception ex)
        {
            return (null, ex.Message);
        }
    }

    #region Pure Helper Functions

    /// <summary>
    /// Gets tag information for a TLV element.
    /// </summary>
    private static string GetTagInfo(TlvObject element)
    {
        var tagHex = element.GetTagAsHexString();
        byte firstTagByte = element.Tag[0];
        var tagNumberResult = element.GetTagNumber();
        var tagName = tagNumberResult.IsSuccess ? GetKnownTagName(tagNumberResult.Value) : "UNKNOWN";
        var tagClass = GetTagClass(firstTagByte);
        var constructed = (firstTagByte & 0x20) != 0 ? "constructed" : "primitive";
            
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
            _ => "Unknown"
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
            _ => "Unknown"
        };
    }

    /// <summary>
    /// Gets length information string.
    /// </summary>
    private static string GetLengthInfo(TlvObject element)
    {
        return $"{element.Value.Length} bytes";
    }

    /// <summary>
    /// Gets content display for TLV element.
    /// </summary>
    private static Maybe<string> GetTlvContent(TlvObject element)
    {
        switch (element.Value.Length)
        {
            case 0:
                return Maybe<string>.From("(empty)");
            case <= 32:
            {
                // Short content - show as hex
                var hexContent = Convert.ToHexString(element.Value);
                return Maybe<string>.From($"Content: {hexContent}");
            }
            default:
            {
                // Long content - show truncated hex
                var truncated = element.Value[..16];
                var hexContent = Convert.ToHexString(truncated);
                return Maybe<string>.From($"Content: {hexContent}... ({element.Value.Length} bytes total)");
            }
        }
    }

    /// <summary>
    /// Gets ASCII content if printable.
    /// </summary>
    private static Maybe<string> GetAsciiContent(TlvObject element)
    {
        if (element.Value.Length > 0 && element.Value.Length <= 32 && IsPrintableAscii(element.Value))
        {
            var ascii = System.Text.Encoding.ASCII.GetString(element.Value);
            return Maybe<string>.From($"ASCII: \"{ascii}\"");
        }
        return Maybe<string>.None;
    }

    /// <summary>
    /// Gets known tag interpretation.
    /// </summary>
    private static Maybe<string> GetKnownTagInterpretation(TlvObject element)
    {
        return element.GetTagNumber().Match(
            tagNumber => InterpretByTagNumber(tagNumber, element),
            error => Maybe<string>.None
        );
    }
    
    private static Maybe<string> InterpretByTagNumber(uint tagNumber, TlvObject element)
    {
        var elementValue = GetTlvValueUsingReflection(element);
        if (elementValue == null) return Maybe<string>.None;
        
        return tagNumber switch
        {
            0x4F when elementValue.Length >= 5 => Maybe<string>.From($"AID: {Convert.ToHexString(elementValue)}"),
            0x8A when elementValue.Length == 1 => Maybe<string>.From($"Life Cycle: {GetLifeCycleStateName(elementValue[0])}"),
            0x81 or 0x82 or 0x83 => Maybe<string>.From("Security-related data - may indicate SCP support"),
            _ => Maybe<string>.None
        };
    }
    
    private static byte[] GetTlvValueUsingReflection(TlvObject element)
    {
        var valueProperty = typeof(TlvObject).GetProperty("Value");
        return valueProperty?.GetValue(element) as byte[] ?? Array.Empty<byte>();
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
            _ => $"Unknown (0x{state:X2})"
        };
    }

    /// <summary>
    /// Reconstructs the full TLV element bytes.
    /// </summary>
    private static byte[] GetFullElementBytes(TlvObject element)
    {
        // Calculate total length
        var tagLength = element.Tag.Length;
        var valueLength = element.Value.Length;
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
        
        var result = new byte[tagLength + lengthFieldSize + valueLength];
        
        // Copy tag
        Array.Copy(element.Tag, 0, result, 0, tagLength);
        
        // Encode length
        var offset = tagLength;
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
        Array.Copy(element.Value, 0, result, offset, valueLength);
            
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

        var parseResult = TryParseTlv(data);
        return parseResult.elements?.Any() == true;
    }

    /// <summary>
    /// Checks if data contains printable ASCII characters.
    /// </summary>
    private static bool IsPrintableAscii(byte[] data)
    {
        foreach (var b in data)
        {
            if (b is < 32 or > 126)
            {
                return false;
            }
        }
        return true;
    }

    #endregion
}