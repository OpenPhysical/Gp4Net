using System;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Gp4Net.Core.Tlv;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Debug
{
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

                var elements = SimpleTlvParser.Enumerate(data);
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

        private void DisplayTlvElement(ICliExecutionContext context, ParsedTlvElement element, int index, int depth, Settings settings)
        {
            var indent = new string(' ', depth * 2);
            var tagInfo = GetTagInfo(element.Tag);
            var lengthInfo = GetLengthInfo(element);
            
            // Main element info
            if (settings.ShowOffsets)
            {
                AnsiConsole.MarkupLine($"{indent}[cyan]Element {index} @{element.Offset:X4}[/]: {tagInfo}");
            }
            else
            {
                AnsiConsole.MarkupLine($"{indent}[cyan]Element {index}[/]: {tagInfo}");
            }
            
            AnsiConsole.MarkupLine($"{indent}  Length: {lengthInfo}");
            
            // Content display
            if (element.Content.Length == 0)
            {
                AnsiConsole.MarkupLine($"{indent}  [dim]Content: (empty)[/]");
            }
            else if (element.Content.Length <= 32)
            {
                // Short content - show as hex
                var hexContent = Convert.ToHexString(element.Content);
                AnsiConsole.MarkupLine($"{indent}  [yellow]Content: {hexContent}[/]");
                
                // Try to show as ASCII if printable
                if (IsPrintableAscii(element.Content))
                {
                    var ascii = System.Text.Encoding.ASCII.GetString(element.Content);
                    AnsiConsole.MarkupLine($"{indent}  [dim]ASCII: \"{ascii}\"[/]");
                }
            }
            else
            {
                // Long content - show truncated hex
                var truncated = element.Content[..16];
                var hexContent = Convert.ToHexString(truncated);
                AnsiConsole.MarkupLine($"{indent}  [yellow]Content: {hexContent}... ({element.Content.Length} bytes total)[/]");
            }

            // Show raw bytes if requested
            if (settings.ShowBytes)
            {
                var fullBytes = GetFullElementBytes(element);
                AnsiConsole.MarkupLine($"{indent}  [dim]Full TLV: {Convert.ToHexString(fullBytes)}[/]");
            }

            // Recursive parsing if enabled and content looks like TLV
            if (settings.Recursive && element.Content.Length > 2 && IsLikelyTlv(element.Content))
            {
                try
                {
                    AnsiConsole.MarkupLine($"{indent}  [magenta]Nested TLV detected:[/]");
                    var nestedElements = SimpleTlvParser.Enumerate(element.Content);
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

        private string GetTagInfo(byte tag)
        {
            var tagName = GetKnownTagName(tag);
            var tagClass = GetTagClass(tag);
            var constructed = (tag & 0x20) != 0 ? "constructed" : "primitive";
            
            return $"[white]Tag {tag:X2}[/] ({tagName}) - {tagClass}, {constructed}";
        }

        private string GetKnownTagName(byte tag)
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

        private string GetTagClass(byte tag)
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

        private string GetLengthInfo(ParsedTlvElement element)
        {
            var contentLength = element.Content.Length;
            var totalLength = element.TotalLength;
            var headerLength = totalLength - contentLength;
            
            return $"{contentLength} bytes content, {headerLength} bytes header, {totalLength} bytes total";
        }

        private byte[] GetFullElementBytes(ParsedTlvElement element)
        {
            // Reconstruct the full TLV element
            var result = new byte[element.TotalLength];
            result[0] = element.Tag;
            
            // Encode length
            if (element.Content.Length < 0x80)
            {
                // Short form
                result[1] = (byte)element.Content.Length;
                Array.Copy(element.Content, 0, result, 2, element.Content.Length);
            }
            else
            {
                // Long form - simplified reconstruction
                result[1] = 0x81; // Assume 1 byte length for simplicity
                result[2] = (byte)element.Content.Length;
                Array.Copy(element.Content, 0, result, 3, element.Content.Length);
            }
            
            return result;
        }

        private bool IsLikelyTlv(byte[] data)
        {
            if (data.Length < 2) return false;
            
            try
            {
                var elements = SimpleTlvParser.Enumerate(data);
                return elements.Any();
            }
            catch
            {
                return false;
            }
        }

        private bool IsPrintableAscii(byte[] data)
        {
            foreach (var b in data)
            {
                if (b < 32 || b > 126) return false;
            }
            return true;
        }

        private void DisplayKnownTagInterpretation(ICliExecutionContext context, ParsedTlvElement element, string indent, Settings settings)
        {
            switch (element.Tag)
            {
                case 0x4F: // AID
                    if (element.Content.Length >= 5)
                    {
                        var aid = Convert.ToHexString(element.Content);
                        AnsiConsole.MarkupLine($"{indent}  [green]AID: {aid}[/]");
                    }
                    break;
                    
                case 0x8A: // Life Cycle State
                    if (element.Content.Length == 1)
                    {
                        var state = element.Content[0];
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
}