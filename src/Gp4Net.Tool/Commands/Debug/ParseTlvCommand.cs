using System;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Gp4Net.Core.Tlv;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Debug;

/// <summary>
/// CLI command to parse and display TLV data in a human-readable format.
/// Helps with debugging and validation of GlobalPlatform TLV structures.
/// </summary>
[PublicAPI]
[CommandHandler(Description = "Parse and display TLV (Tag-Length-Value) data structure")]
public class ParseTlvCommand : IPipelineCommand<ParseTlvCommand.Settings>
{
    public class Settings : CommandSettings
    {
        [CommandArgument(0, "<hex-data>")]
        [Description("Hex string of TLV data to parse")]
        public string HexData { get; set; } = string.Empty;

        [CommandOption("--show-bytes")]
        [Description("Show raw byte values for each element")]
        public bool ShowBytes { get; set; }

        [CommandOption("--show-offsets")]
        [Description("Show byte offsets (default: true)")]
        public bool ShowOffsets { get; set; } = true;

        [CommandOption("--recursive")]
        [Description("Recursively parse nested TLV structures (default: true)")]
        public bool Recursive { get; set; } = true;
    }

    public Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(settings.HexData))
            {
                context.Display.Error("hex-data argument is required");
                return Task.FromResult(1);
            }

            // Clean up hex string
            var cleanHex = settings.HexData.Replace(" ", "").Replace("-", "").Replace(":", "");
                
            if (cleanHex.Length % 2 != 0)
            {
                context.Display.Error("Hex string must have even number of characters");
                return Task.FromResult(1);
            }

            var data = Convert.FromHexString(cleanHex);
            context.Display.Success($"Parsing {data.Length} bytes of TLV data:");
            AnsiConsole.MarkupLine($"[dim]Raw hex: {Convert.ToHexString(data)}[/]");
            AnsiConsole.WriteLine();

            var elements = TlvParser.ParseAll(data);
            var elementIndex = 0;
                
            foreach (var element in elements)
            {
                DisplayTlvElement(context, element, elementIndex++, 0, settings);
                AnsiConsole.WriteLine();
            }

            if (elementIndex == 0)
            {
                AnsiConsole.MarkupLine("[yellow]No valid TLV elements found[/]");
            }

            return Task.FromResult(0);
        }
        catch (Exception ex)
        {
            context.Display.Error($"Error parsing TLV data: {ex.Message}");
            return Task.FromResult(1);
        }
    }

    private void DisplayTlvElement(ICliExecutionContext context, TlvObject element, int index, int depth, Settings settings)
    {
        var indent = new string(' ', depth * 2);
        var tagInfo = GetTagInfo(element);
        var lengthInfo = GetLengthInfo(element);
            
        // Main element info
        AnsiConsole.MarkupLine($"{indent}[cyan]Element {index}[/]: {tagInfo}");
            
        AnsiConsole.MarkupLine($"{indent}  Length: {lengthInfo}");
            
        // Content display
        if (element.Value.Length == 0)
        {
            AnsiConsole.MarkupLine($"{indent}  [dim]Content: (empty)[/]");
        }
        else if (element.Value.Length <= 32)
        {
            // Short content - show as hex
            var hexContent = Convert.ToHexString(element.Value);
            AnsiConsole.MarkupLine($"{indent}  [yellow]Content: {hexContent}[/]");
                
            // Try to show as ASCII if printable
            if (IsPrintableAscii(element.Value))
            {
                var ascii = System.Text.Encoding.ASCII.GetString(element.Value);
                AnsiConsole.MarkupLine($"{indent}  [dim]ASCII: \"{ascii}\"[/]");
            }
        }
        else
        {
            // Long content - show truncated hex
            var truncated = element.Value[..16];
            var hexContent = Convert.ToHexString(truncated);
            AnsiConsole.MarkupLine($"{indent}  [yellow]Content: {hexContent}... ({element.Value.Length} bytes total)[/]");
        }

        // Show raw bytes if requested
        if (settings.ShowBytes)
        {
            var fullBytes = GetFullElementBytes(element);
            AnsiConsole.MarkupLine($"{indent}  [dim]Full TLV: {Convert.ToHexString(fullBytes)}[/]");
        }

        // Recursive parsing if enabled and content looks like TLV
        if (settings.Recursive && element.Value.Length > 2 && IsLikelyTlv(element.Value))
        {
            try
            {
                AnsiConsole.MarkupLine($"{indent}  [magenta]Nested TLV detected:[/]");
                var nestedElements = TlvParser.ParseAll(element.Value);
                var nestedIndex = 0;
                    
                foreach (var nested in nestedElements)
                {
                    DisplayTlvElement(context, nested, nestedIndex++, depth + 2, settings);
                }
                    
                if (nestedIndex == 0)
                {
                    AnsiConsole.MarkupLine($"{indent}    [dim](No valid nested TLV found)[/]");
                }
            }
            catch
            {
                // Not valid TLV, ignore
            }
        }

        // Known tag interpretations
        DisplayKnownTagInterpretation(context, element, indent, settings);
    }

    private string GetTagInfo(TlvObject element)
    {
        var tagHex = element.GetTagAsHexString();
        byte firstTagByte = element.Tag[0];
        var tagName = GetKnownTagName(element.TagNumber);
        var tagClass = GetTagClass(firstTagByte);
        var constructed = (firstTagByte & 0x20) != 0 ? "constructed" : "primitive";
            
        return $"[white]Tag {tagHex}[/] ({tagName}) - {tagClass}, {constructed}";
    }

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

    private static string GetLengthInfo(TlvObject element)
    {
        var contentLength = element.Value.Length;
            
        return $"{contentLength} bytes";
    }

    private static byte[] GetFullElementBytes(TlvObject element)
    {
        // Reconstruct the full TLV element
        // Calculate total length
        var tagLength = element.Tag.Length;
        var valueLength = element.Value.Length;
        int lengthFieldSize;
        
        if (valueLength < 128)
        {
            lengthFieldSize = 1;
        }
        else if (valueLength <= 255)
        {
            lengthFieldSize = 2;
        }
        else
        {
            // For now, assume max 2-byte length encoding
            lengthFieldSize = 3;
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

    private static bool IsLikelyTlv(byte[] data)
    {
        if (data.Length < 2)
        {
            return false;
        }

        try
        {
            var elements = TlvParser.ParseAll(data);
            return elements.Any();
        }
        catch
        {
            return false;
        }
    }

    private static bool IsPrintableAscii(byte[] data)
    {
        foreach (var b in data)
        {
            if (b < 32 || b > 126)
            {
                return false;
            }
        }
        return true;
    }

    private static void DisplayKnownTagInterpretation(ICliExecutionContext context, TlvObject element, string indent, Settings settings)
    {
        switch (element.TagNumber)
        {
            case 0x4F: // AID
                if (element.Value.Length >= 5)
                {
                    var aid = Convert.ToHexString(element.Value);
                    AnsiConsole.MarkupLine($"{indent}  [green]AID: {aid}[/]");
                }
                break;
                    
            case 0x8A: // Life Cycle State
                if (element.Value.Length == 1)
                {
                    var state = element.Value[0];
                    var stateName = state switch
                    {
                        0x01 => "OP_READY",
                        0x03 => "INITIALIZED", 
                        0x07 => "SECURED",
                        0x0F => "CARD_LOCKED",
                        0x7F => "TERMINATED",
                        _ => $"Unknown (0x{state:X2})"
                    };
                    AnsiConsole.MarkupLine($"{indent}  [green]Life Cycle: {stateName}[/]");
                }
                break;
                    
            case 0x81: // Secure Messaging Support
            case 0x82: // SCP Protocol Data
            case 0x83: // Additional Security Capabilities
                AnsiConsole.MarkupLine($"{indent}  [green]Security-related data - may indicate SCP support[/]");
                break;
        }
    }
}