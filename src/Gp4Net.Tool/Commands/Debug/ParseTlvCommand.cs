using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Threading.Tasks;
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

        [CommandOption("--format")]
        [Description("Output format (console, table, json)")]
        public string Format { get; set; } = "console";
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
            string cleanHex = settings.HexData.Replace(" ", "").Replace("-", "").Replace(":", "");

            if (cleanHex.Length % 2 != 0)
            {
                context.Display.Error("Hex string must have even number of characters");
                return Task.FromResult(1);
            }

            byte[] data = Convert.FromHexString(cleanHex);

            // Build semantic rows using pure functional composition
            List<TlvTableBuilder.TlvRow> semanticRows = [.. TlvTableBuilder
                .BuildTlvRows(
                    data,
                    showBytes: settings.ShowBytes,
                    showOffsets: settings.ShowOffsets,
                    recursive: settings.Recursive
                )];

            // Display based on format using pure functions
            switch (settings.Format.ToLowerInvariant())
            {
                case "json":
                    string json = TlvTableBuilder.ToJson(semanticRows);
                    AnsiConsole.WriteLine(json);
                    break;

                case "table":
                    TlvTableRenderer.RenderToTable(semanticRows);
                    break;

                case "console":
                default:
                    TlvTableRenderer.RenderToConsole(semanticRows);
                    break;
            }

            return Task.FromResult(0);
        }
        catch (Exception ex)
        {
            context.Display.Error($"Error parsing TLV data: {ex.Message}");
            return Task.FromResult(1);
        }
    }
}
