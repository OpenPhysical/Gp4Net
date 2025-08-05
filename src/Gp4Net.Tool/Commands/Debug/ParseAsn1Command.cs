using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Debug;

/// <summary>
/// CLI command to parse and display ASN.1 data in a human-readable format.
/// Helps with debugging and validation of ASN.1 structures.
/// </summary>
[PublicAPI]
[CommandHandler(Description = "Parse and display ASN.1 data structure")]
public class ParseAsn1Command : IPipelineCommand<ParseAsn1Command.Settings>
{
    public class Settings : CommandSettings
    {
        [CommandArgument(0, "<hex-data>")]
        [Description("Hex string of ASN.1 data to parse")]
        public string HexData { get; set; } = string.Empty;

        [CommandOption("--show-bytes")]
        [Description("Show raw byte values for each element")]
        public bool ShowBytes { get; set; }

        [CommandOption("--show-offsets")]
        [Description("Show byte offsets (default: true)")]
        public bool ShowOffsets { get; set; } = true;
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
            context.Display.Success($"Parsing {data.Length} bytes of ASN.1 data:");
            AnsiConsole.MarkupLine($"[dim]Raw hex: {Convert.ToHexString(data)}[/]");
            AnsiConsole.WriteLine();

            var asn1Object = Asn1Object.FromByteArray(data);
            DisplayAsn1Object(context, asn1Object, 0, 0, settings);

            return Task.FromResult(0);
        }
        catch (Exception ex)
        {
            context.Display.Error($"Error parsing ASN.1 data: {ex.Message}");
            return Task.FromResult(1);
        }
    }

    private void DisplayAsn1Object(ICliExecutionContext context, Asn1Object obj, int depth, int offset, Settings settings)
    {
        var indent = new string(' ', depth * 2);
        var typeInfo = GetAsn1TypeInfo(obj);
            
        if (settings.ShowOffsets)
        {
            AnsiConsole.MarkupLine($"{indent}[cyan]@{offset:X4}[/] {typeInfo}");
        }
        else
        {
            AnsiConsole.MarkupLine($"{indent}{typeInfo}");
        }

        // Show raw bytes if requested
        if (settings.ShowBytes && obj.GetEncoded() != null)
        {
            var encoded = obj.GetEncoded();
            var bytesStr = Convert.ToHexString(encoded);
            AnsiConsole.MarkupLine($"{indent}  [dim]Bytes: {bytesStr}[/]");
        }

        // Handle different ASN.1 types
        switch (obj)
        {
            case Asn1Sequence sequence:
                AnsiConsole.MarkupLine($"{indent}  [blue]Sequence with {sequence.Count} elements:[/]");
                var seqOffset = offset + GetHeaderLength(obj);
                for (var i = 0; i < sequence.Count; i++)
                {
                    AnsiConsole.MarkupLine($"{indent}  [dim]Element {i}:[/]");
                    DisplayAsn1Object(context, sequence[i].ToAsn1Object(), depth + 2, seqOffset, settings);
                    seqOffset += sequence[i].GetEncoded().Length;
                }
                break;

            case Asn1Set set:
                AnsiConsole.MarkupLine($"{indent}  [blue]Set with {set.Count} elements:[/]");
                var setOffset = offset + GetHeaderLength(obj);
                for (var i = 0; i < set.Count; i++)
                {
                    AnsiConsole.MarkupLine($"{indent}  [dim]Element {i}:[/]");
                    DisplayAsn1Object(context, set[i].ToAsn1Object(), depth + 2, setOffset, settings);
                    setOffset += set[i].GetEncoded().Length;
                }
                break;

            case DerOctetString octetString:
                var octets = octetString.GetOctets();
                AnsiConsole.MarkupLine($"{indent}  [yellow]Value: {Convert.ToHexString(octets)} ({octets.Length} bytes)[/]");
                    
                // Try to parse nested ASN.1 if it looks like it
                if (octets.Length > 2 && IsLikelyAsn1(octets))
                {
                    try
                    {
                        var nested = Asn1Object.FromByteArray(octets);
                        AnsiConsole.MarkupLine($"{indent}  [magenta]Nested ASN.1 detected:[/]");
                        DisplayAsn1Object(context, nested, depth + 2, 0, settings);
                    }
                    catch
                    {
                        // Not ASN.1, ignore
                    }
                }
                break;

            case DerInteger integer:
                AnsiConsole.MarkupLine($"{indent}  [yellow]Value: {integer.Value}[/]");
                break;

            case DerObjectIdentifier oid:
                AnsiConsole.MarkupLine($"{indent}  [yellow]OID: {oid.Id}[/]");
                break;

            case DerUtf8String utf8:
                AnsiConsole.MarkupLine($"{indent}  [yellow]Value: \"{utf8.GetString()}\"[/]");
                break;

            case DerPrintableString printable:
                AnsiConsole.MarkupLine($"{indent}  [yellow]Value: \"{printable.GetString()}\"[/]");
                break;

            case DerBitString bitString:
                var bits = bitString.GetBytes();
                AnsiConsole.MarkupLine($"{indent}  [yellow]Bits: {Convert.ToHexString(bits)} (unused bits: {bitString.PadBits})[/]");
                break;

            default:
                var encoded = obj.GetEncoded();
                if (encoded is { Length: > 0 })
                {
                    AnsiConsole.MarkupLine($"{indent}  [yellow]Raw data: {Convert.ToHexString(encoded)}[/]");
                }
                break;
        }
    }

    private string GetAsn1TypeInfo(Asn1Object obj)
    {
        var encoded = obj.GetEncoded();
        if (encoded == null || encoded.Length == 0)
        {
            return "[red]Invalid ASN.1 object[/]";
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

        return $"[white]{classStr}[/] [green]{typeStr}[/] (tag={tag:X2}, constructed={constructed}, length={lengthInfo})";
    }

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
}