using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.OpenPhysical;
using Gp4Net.Tool.Commands;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card
{
    /// <summary>
    /// Command to write data to ISD using PUT DATA operations.
    /// </summary>
    [PublicAPI]
    [CommandHandler(Description = "Write data objects to the card")]
    public class PutIsdDataCommand : IPipelineCommand<PutIsdDataCommand.Settings>
    {
        /// <summary>
        /// Executes the put-data command to write data objects to the card.
        /// </summary>
        public async Task<int> ExecuteAsync(ICommandContext context, Settings settings)
        {
            var ctx = await context.WithVerbose(settings.Verbose).RequireCardConnection(settings);

            ctx = await ctx.RequireSecureChannel(settings);

            return PutDataObjects(ctx, settings);
        }

        private static int PutDataObjects(ICommandContext context, Settings settings)
        {
            try
            {
                // Parse data to write
                var dataToWrite = new Dictionary<string, string>();

                // Handle different input methods
                if (!string.IsNullOrEmpty(settings.ConfigFile))
                {
                    if (!LoadDataFromFile(settings.ConfigFile, dataToWrite, context))
                    {
                        return 1;
                    }
                }
                else if (settings.Interactive)
                {
                    if (!LoadDataInteractively(dataToWrite, context))
                    {
                        return 1;
                    }
                }
                else if (settings.KeyValuePairs != null && settings.KeyValuePairs.Length > 0)
                {
                    if (!ParseKeyValuePairs(settings.KeyValuePairs, dataToWrite, context))
                    {
                        return 1;
                    }
                }
                else
                {
                    context.Display.Error(
                        "No data specified. Use key=value pairs, --file, or --interactive"
                    );
                    return 1;
                }

                // Validate for conflicts
                if (!ValidateNoConflicts(dataToWrite, context))
                {
                    return 1;
                }

                // Expand OPID if present
                if (dataToWrite.ContainsKey("opid"))
                {
                    if (!ExpandOpid(dataToWrite, context))
                    {
                        return 1;
                    }
                }

                // Show what will be written
                if (settings.DryRun || !settings.Force)
                {
                    ShowPreview(dataToWrite, context);

                    if (settings.DryRun)
                    {
                        context.Display.Info("Dry run completed - no data was written");
                        return 0;
                    }

                    if (!settings.Force)
                    {
                        if (!AnsiConsole.Confirm("Proceed with writing data to card?"))
                        {
                            context.Display.Info("Operation cancelled");
                            return 0;
                        }
                    }
                }

                // Write data to card
                return WriteDataToCard(dataToWrite, context, settings);
            }
            catch (Exception ex)
            {
                context.Display.Error($"Failed to write data: {ex.Message}");
                return 1;
            }
        }

        private static bool LoadDataFromFile(
            string filePath,
            Dictionary<string, string> dataToWrite,
            ICommandContext context
        )
        {
            try
            {
                string content;
                if (filePath == "-")
                {
                    // Read from stdin
                    content = Console.In.ReadToEnd();
                }
                else
                {
                    if (!File.Exists(filePath))
                    {
                        context.Display.Error($"File not found: {filePath}");
                        return false;
                    }
                    content = File.ReadAllText(filePath);
                }

                // Try to parse as JSON
                try
                {
                    var jsonData = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                        content
                    );
                    if (jsonData != null)
                    {
                        foreach (var kvp in jsonData)
                        {
                            dataToWrite[kvp.Key.ToLowerInvariant()] = kvp.Value.ToString();
                        }
                        return true;
                    }
                }
                catch
                {
                    // Not JSON, try key=value format
                    var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines)
                    {
                        var trimmed = line.Trim();
                        if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#"))
                        {
                            continue;
                        }

                        var parts = trimmed.Split('=', 2);
                        if (parts.Length == 2)
                        {
                            dataToWrite[parts[0].Trim().ToLowerInvariant()] = parts[1].Trim();
                        }
                    }
                    return true;
                }

                context.Display.Error("Could not parse file content as JSON or key=value format");
                return false;
            }
            catch (Exception ex)
            {
                context.Display.Error($"Error reading file: {ex.Message}");
                return false;
            }
        }

        private static bool LoadDataInteractively(
            Dictionary<string, string> dataToWrite,
            ICommandContext context
        )
        {
            context.Display.Info("Interactive data entry mode. Press Enter to skip a field.");

            var prompts = new[]
            {
                ("IIN", "Issuer Identification Number (4 digits)"),
                ("CIN", "Card Image Number (digits only)"),
                ("Manager URL", "Security Domain Manager URL"),
                ("OPID", "OpenPhysical ID (format: IIII-... where I=digits)")
            };

            foreach (var (key, description) in prompts)
            {
                var value = AnsiConsole.Ask<string>(
                    $"[yellow]{description}[/] ({key}):",
                    string.Empty
                );
                if (!string.IsNullOrWhiteSpace(value))
                {
                    dataToWrite[key.ToLowerInvariant()] = value.Trim();
                }
            }

            return dataToWrite.Count > 0;
        }

        private static bool ParseKeyValuePairs(
            string[] keyValuePairs,
            Dictionary<string, string> dataToWrite,
            ICommandContext context
        )
        {
            foreach (var pair in keyValuePairs)
            {
                var parts = pair.Split('=', 2);
                if (parts.Length != 2)
                {
                    context.Display.Error($"Invalid key=value format: {pair}");
                    return false;
                }

                var key = parts[0].Trim().ToLowerInvariant();
                var value = parts[1].Trim();

                if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(value))
                {
                    context.Display.Error($"Empty key or value in: {pair}");
                    return false;
                }

                dataToWrite[key] = value;
            }

            return true;
        }

        private static bool ValidateNoConflicts(
            Dictionary<string, string> dataToWrite,
            ICommandContext context
        )
        {
            var hasOpid = dataToWrite.ContainsKey("opid");
            var hasIndividualFields =
                dataToWrite.ContainsKey("iin")
                || dataToWrite.ContainsKey("cin")
                || dataToWrite.ContainsKey("manager-url");

            if (hasOpid && hasIndividualFields)
            {
                context.Display.Error(
                    "Cannot specify both 'opid' and individual fields (iin, cin, manager-url)"
                );
                context.Display.Info("OPID automatically sets all three fields");
                return false;
            }

            return true;
        }

        private static bool ExpandOpid(
            Dictionary<string, string> dataToWrite,
            ICommandContext context
        )
        {
            var opidString = dataToWrite["opid"];

            if (!OpenPhysicalId.TryParse(opidString, out var opid) || opid == null)
            {
                var validation = OpidValidator.ValidateOpid(opidString);
                context.Display.Error($"Invalid OPID: {validation.ErrorMessage}");
                return false;
            }

            // Remove OPID and add individual components
            _ = dataToWrite.Remove("opid");
            dataToWrite["iin"] = opid.Iin;
            dataToWrite["cin"] = opid.Cin;
            dataToWrite["manager-url"] = opid.ManagerUrl;

            context.Display.Info($"OPID '{opidString}' expanded to:");
            context.Display.Info($"  IIN: {opid.Iin}");
            context.Display.Info($"  CIN: {opid.Cin}");
            context.Display.Info($"  Manager URL: {opid.ManagerUrl}");

            return true;
        }

        private static void ShowPreview(
            Dictionary<string, string> dataToWrite,
            ICommandContext context
        )
        {
            var table = new Table()
                .AddColumn("Data Object")
                .AddColumn("Value")
                .AddColumn("Encoding");

            foreach (var kvp in dataToWrite)
            {
                var encoding = kvp.Key switch
                {
                    "iin" or "cin" => "ASCII",
                    "manager-url" => "UTF-8",
                    _ when kvp.Key.StartsWith("0x") => "Binary",
                    _ => "Auto"
                };

                _ = table.AddRow(kvp.Key.ToUpperInvariant(), kvp.Value, encoding);
            }

            AnsiConsole.Write(new Panel(table).Header("[bold]Data to be written[/]"));
        }

        private static int WriteDataToCard(
            Dictionary<string, string> dataToWrite,
            ICommandContext context,
            Settings settings
        )
        {
            int errors = 0;
            int written = 0;

            foreach (var kvp in dataToWrite)
            {
                try
                {
                    var success = WriteDataObject(kvp.Key, kvp.Value, context);
                    if (success)
                    {
                        written++;
                        context.Display.Success(
                            $"✓ {kvp.Key.ToUpperInvariant()} written successfully"
                        );
                    }
                    else
                    {
                        errors++;
                        context.Display.Error($"✗ Failed to write {kvp.Key.ToUpperInvariant()}");

                        if (!settings.ContinueOnError)
                        {
                            context.Display.Error(
                                "Stopping due to error (use --continue-on-error to continue)"
                            );
                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    errors++;
                    context.Display.Error(
                        $"✗ Error writing {kvp.Key.ToUpperInvariant()}: {ex.Message}"
                    );

                    if (!settings.ContinueOnError)
                    {
                        context.Display.Error(
                            "Stopping due to error (use --continue-on-error to continue)"
                        );
                        break;
                    }
                }
            }

            // Summary
            if (written > 0 || errors > 0)
            {
                AnsiConsole.WriteLine();
                context.Display.Info($"Summary: {written} objects written, {errors} errors");
            }

            return errors > 0 ? 1 : 0;
        }

        private static bool WriteDataObject(string key, string value, ICommandContext context)
        {
            try
            {
                var (tag, data) = key switch
                {
                    "iin"
                        => (
                            Domain.Commands.GetDataCommand.DataObjects.IssuerIdentificationNumber,
                            System.Text.Encoding.ASCII.GetBytes(value)
                        ),
                    "cin"
                        => (
                            Domain.Commands.GetDataCommand.DataObjects.CardImageNumber,
                            System.Text.Encoding.ASCII.GetBytes(value)
                        ),
                    "manager-url"
                        => (
                            Domain.Commands.GetDataCommand.DataObjects.SecurityDomainManagerUrl,
                            System.Text.Encoding.UTF8.GetBytes(value)
                        ),
                    _ when key.StartsWith("0x") => ParseRawDataObject(key, value),
                    _ => throw new ArgumentException($"Unknown data object: {key}")
                };

                // Create BER-TLV formatted data
                var tlvData = CreateTlvData(tag, data);

                // Create STORE DATA command
                var storeResult = StoreDataCommand.CreateWithFormat(
                    StoreDataCommand.DataStructureFormat.BerTlv,
                    StoreDataCommand.BlockFormat.FirstOrOnly,
                    tlvData
                );
                if (storeResult.IsFailure)
                {
                    throw new InvalidOperationException($"Failed to create STORE DATA command: {storeResult.Error.Message}");
                }
                var storeCommand = storeResult.Value;

                // Send command
                var response = context.CardService.SendCommand(storeCommand);
                return response.IsSuccessful;
            }
            catch (Exception ex)
            {
                context.Display.Error($"Error creating command for {key}: {ex.Message}");
                return false;
            }
        }

        private static (ushort tag, byte[] data) ParseRawDataObject(string key, string value)
        {
            if (key.StartsWith("0x") && key.Length > 2)
            {
                // Handle hex tag format: 0x9F70
                if (!ushort.TryParse(
                    key.AsSpan(2),
                    System.Globalization.NumberStyles.HexNumber,
                    null,
                    out var tag
                ))
                {
                    throw new ArgumentException($"Invalid hex tag format: {key}");
                }

                byte[] data;
                try
                {
                    data = Convert.FromHexString(value);
                }
                catch
                {
                    // Try as UTF-8 string
                    data = System.Text.Encoding.UTF8.GetBytes(value);
                }

                return (tag, data);
            }
            else
            {
                // Try parsing as tag:data or tag=data format
                var fullString = $"{key}:{value}";
                var result = DataObjectParser.ParseRawDataObject(fullString);
                if (result.IsSuccess)
                {
                    return result.Value;
                }

                // Try with = separator
                fullString = $"{key}={value}";
                result = DataObjectParser.ParseRawDataObject(fullString);
                if (result.IsSuccess)
                {
                    return result.Value;
                }

                throw new ArgumentException($"Invalid data object format: {key}. Expected formats: 0x9F70, 9F70:040102, or 9F70=040102");
            }
        }

        private static byte[] CreateTlvData(ushort tag, byte[] data)
        {
            var result = new List<byte>();

            // Add tag
            if (tag > 0xFF)
            {
                result.Add((byte)(tag >> 8));
                result.Add((byte)(tag & 0xFF));
            }
            else
            {
                result.Add((byte)tag);
            }

            // Add length
            if (data.Length < 0x80)
            {
                result.Add((byte)data.Length);
            }
            else if (data.Length < 0x100)
            {
                result.Add(0x81);
                result.Add((byte)data.Length);
            }
            else
            {
                result.Add(0x82);
                result.Add((byte)(data.Length >> 8));
                result.Add((byte)(data.Length & 0xFF));
            }

            // Add data
            result.AddRange(data);

            return [.. result];
        }

        /// <summary>
        /// Settings for the put-data command.
        /// </summary>
        public class Settings : SecureCommandSettings
        {
            /// <summary>
            /// Gets or sets the key-value pairs to write.
            /// </summary>
            [CommandArgument(0, "[key=value...]")]
            [Description("Key-value pairs to write (e.g., iin=1234 cin=567890)")]
            public string[]? KeyValuePairs { get; set; }

            /// <summary>
            /// Gets or sets the configuration file path.
            /// </summary>
            [CommandOption("--file <FILE>")]
            [Description("Configuration file (JSON or key=value format). Use '-' for stdin")]
            public string? ConfigFile { get; set; }

            /// <summary>
            /// Gets or sets whether to use interactive mode.
            /// </summary>
            [CommandOption("--interactive")]
            [Description("Interactive mode with prompts for each field")]
            public bool Interactive { get; set; }

            /// <summary>
            /// Gets or sets whether to perform a dry run.
            /// </summary>
            [CommandOption("--dry-run")]
            [Description("Show what would be written without actually writing")]
            public bool DryRun { get; set; }

            /// <summary>
            /// Gets or sets whether to continue on errors.
            /// </summary>
            [CommandOption("--continue-on-error")]
            [Description("Continue writing other objects if one fails")]
            public bool ContinueOnError { get; set; }

            /// <summary>
            /// Gets or sets whether to skip confirmation prompts.
            /// </summary>
            [CommandOption("--force")]
            [Description("Skip confirmation prompts")]
            public bool Force { get; set; }

            /// <summary>
            /// Validates the command settings.
            /// </summary>
            /// <returns>Success if valid, or an error message if validation fails.</returns>
            public override ValidationResult Validate()
            {
                var hasKeyValuePairs = KeyValuePairs != null && KeyValuePairs.Length > 0;
                var hasFile = !string.IsNullOrEmpty(ConfigFile);
                var hasInteractive = Interactive;

                var inputMethods = new[] { hasKeyValuePairs, hasFile, hasInteractive }.Count(x =>
                    x
                );
                if (inputMethods == 0)
                {
                    return ValidationResult.Error(
                        "Must specify data using key=value pairs, --file, or --interactive"
                    );
                }
                if (inputMethods > 1)
                {
                    return ValidationResult.Error(
                        "Cannot combine key=value pairs, --file, and --interactive options"
                    );
                }

                return ValidationResult.Success();
            }
        }
    }
}
