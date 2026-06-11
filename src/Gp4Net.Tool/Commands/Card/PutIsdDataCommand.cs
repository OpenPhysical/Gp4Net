using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.OpenPhysical;
using Gp4Net.Tool.Extensions;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Command to write data to ISD using PUT DATA operations.
/// </summary>
[PublicAPI]
[CliCommand("put-data", "Write data objects to the card (IIN, CIN, OPID, etc.)", "card")]
[CommandHandler(Description = "Write data objects to the card")]
public class PutIsdDataCommand : IPipelineCommand<PutIsdDataCommand.Settings>
{
    /// <summary>
    /// Executes the put-data command to write data objects to the card.
    /// </summary>
    public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
    {
        var connectionResult = await context
            .WithVerbose(settings.Verbose)
            .RequireCardConnection(settings.GetReaderName());

        return await connectionResult.Match(
            async connectedCtx =>
            {
                var secureChannelResult = await connectedCtx.RequireSecureChannel(
                    settings.ToSecureChannelRequest()
                );
                return await secureChannelResult.Match(
                    async secureCtx => await PutDataObjects(secureCtx, settings),
                    async secureChannelError =>
                    {
                        AnsiConsole.MarkupLine(
                            $"[red]Secure channel error: {secureChannelError.Message}[/]"
                        );
                        return await Task.FromResult(1);
                    }
                );
            },
            async connectionError =>
            {
                AnsiConsole.MarkupLine($"[red]Connection error: {connectionError.Message}[/]");
                return await Task.FromResult(1);
            }
        );
    }

    private static async Task<int> PutDataObjects(ICliExecutionContext context, Settings settings)
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
            else if (settings.KeyValuePairs is { Length: > 0 })
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
            return await WriteDataToCard(dataToWrite, context, settings);
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
        ICliExecutionContext context
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
                var jsonData = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(content);
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
                string[] lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (string line in lines)
                {
                    string trimmed = line.Trim();
                    if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#"))
                    {
                        continue;
                    }

                    string[] parts = trimmed.Split('=', 2);
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
        ICliExecutionContext context
    )
    {
        context.Display.Info("Interactive data entry mode. Press Enter to skip a field.");

        (string, string)[] prompts =
        [
            ("IIN", "Issuer Identification Number (4 digits)"),
            ("CIN", "Card Image Number (digits only)"),
            ("Manager URL", "Security Domain Manager URL"),
            ("OPID", "OpenPhysical ID (format: IIII-... where I=digits)"),
        ];

        foreach ((string key, string description) in prompts)
        {
            string value = AnsiConsole.Ask($"[yellow]{description}[/] ({key}):", string.Empty);
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
        ICliExecutionContext context
    )
    {
        foreach (string pair in keyValuePairs)
        {
            string[] parts = pair.Split('=', 2);
            if (parts.Length != 2)
            {
                context.Display.Error($"Invalid key=value format: {pair}");
                return false;
            }

            string key = parts[0].Trim().ToLowerInvariant();
            string value = parts[1].Trim();

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
        ICliExecutionContext context
    )
    {
        bool hasOpid = dataToWrite.ContainsKey("opid");
        bool hasIndividualFields =
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
        ICliExecutionContext context
    )
    {
        string opidString = dataToWrite["opid"];

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
        dataToWrite["manager-url"] = OpenPhysicalId.ManagerUrl;

        context.Display.Info($"OPID '{opidString}' expanded to:");
        context.Display.Info($"  IIN: {opid.Iin}");
        context.Display.Info($"  CIN: {opid.Cin}");
        context.Display.Info($"  Manager URL: {OpenPhysicalId.ManagerUrl}");

        return true;
    }

    private static void ShowPreview(
        Dictionary<string, string> dataToWrite,
        ICliExecutionContext context
    )
    {
        var table = new Table().AddColumn("Data Object").AddColumn("Value").AddColumn("Encoding");

        foreach (var kvp in dataToWrite)
        {
            string encoding = kvp.Key switch
            {
                "iin" or "cin" => "ASCII",
                "manager-url" => "UTF-8",
                _ when kvp.Key.StartsWith("0x") => "Binary",
                _ => "Auto",
            };

            _ = table.AddRow(kvp.Key.ToUpperInvariant(), kvp.Value, encoding);
        }

        AnsiConsole.Write(new Panel(table).Header("[bold]Data to be written[/]"));
    }

    private static async Task<int> WriteDataToCard(
        Dictionary<string, string> dataToWrite,
        ICliExecutionContext context,
        Settings settings
    )
    {
        var dataItems = dataToWrite.ToImmutableDictionary();

        return await WriteDataObjectsSequentially(
            dataItems,
            context,
            settings,
            0,
            ImmutableArray<(string key, Result<bool, SmartCardError> result)>.Empty
        );
    }

    private static async Task<int> WriteDataObjectsSequentially(
        IReadOnlyDictionary<string, string> dataToWrite,
        ICliExecutionContext context,
        Settings settings,
        int currentIndex,
        ImmutableArray<(string key, Result<bool, SmartCardError> result)> processedResults
    )
    {
        KeyValuePair<string, string>[] dataItems = [.. dataToWrite];

        if (currentIndex >= dataItems.Length)
        {
            return ProcessWriteResults(processedResults, context);
        }

        (string key, string value) = dataItems[currentIndex];
        var writeResult = await WriteDataObject(key, value, context);

        DisplayWriteResult(key, writeResult, context);

        var updatedResults = processedResults.Add((key, writeResult));

        if (writeResult.IsFailure && !settings.ContinueOnError)
        {
            context.Display.Error("Stopping due to error (use --continue-on-error to continue)");
            return ProcessWriteResults(updatedResults, context);
        }

        return await WriteDataObjectsSequentially(
            dataToWrite,
            context,
            settings,
            currentIndex + 1,
            updatedResults
        );
    }

    private static void DisplayWriteResult(
        string key,
        Result<bool, SmartCardError> result,
        ICliExecutionContext context
    )
    {
        _ = result.Match(
            success =>
            {
                if (success)
                {
                    context.Display.Success($"✓ {key.ToUpperInvariant()} written successfully");
                }
                else
                {
                    context.Display.Error($"✗ Failed to write {key.ToUpperInvariant()}");
                }
                return true;
            },
            error =>
            {
                context.Display.Error($"✗ Error writing {key.ToUpperInvariant()}: {error.Message}");
                return false;
            }
        );
    }

    private static int ProcessWriteResults(
        ImmutableArray<(string key, Result<bool, SmartCardError> result)> results,
        ICliExecutionContext context
    )
    {
        int written = results.Count(r => r.result.Match(success => success, _ => false));
        int errors = results.Count(r =>
            r.result.IsFailure || r.result.Match(success => !success, _ => true)
        );

        if (written > 0 || errors > 0)
        {
            AnsiConsole.WriteLine();
            context.Display.Info($"Summary: {written} objects written, {errors} errors");
        }

        return errors > 0 ? 1 : 0;
    }

    private static async Task<Result<bool, SmartCardError>> WriteDataObject(
        string key,
        string value,
        ICliExecutionContext context
    )
    {
        return await ParseDataObjectAsync(key, value)
            .Bind(async tagData => await CreateAndSendCommand(tagData, context));
    }

    private static Task<Result<(ushort tag, byte[] data), SmartCardError>> ParseDataObjectAsync(
        string key,
        string value
    )
    {
        var result = key switch
        {
            "iin"
                => Result.Success<(ushort tag, byte[] data), SmartCardError>(
                    (
                        GetDataCommand.DataObjects.IssuerIdentificationNumber,
                        Encoding.ASCII.GetBytes(value)
                    )
                ),
            "cin"
                => Result.Success<(ushort tag, byte[] data), SmartCardError>(
                    (GetDataCommand.DataObjects.CardImageNumber, Encoding.ASCII.GetBytes(value))
                ),
            "manager-url"
                => Result.Success<(ushort tag, byte[] data), SmartCardError>(
                    (
                        GetDataCommand.DataObjects.SecurityDomainManagerUrl,
                        Encoding.UTF8.GetBytes(value)
                    )
                ),
            _ when key.StartsWith("0x")
                => Result.Try(
                    () => ParseRawDataObject(key, value),
                    ex =>
                        SmartCardError.InvalidData($"Invalid raw data object format: {ex.Message}")
                ),
            _
                => Result.Failure<(ushort tag, byte[] data), SmartCardError>(
                    SmartCardError.InvalidData($"Unknown data object: {key}")
                ),
        };

        return Task.FromResult(result);
    }

    private static async Task<Result<bool, SmartCardError>> CreateAndSendCommand(
        (ushort tag, byte[] data) tagData,
        ICliExecutionContext context
    )
    {
        (ushort tag, byte[] data) = tagData;
        byte[] tlvData = CreateTlvData(tag, data);

        var storeResult = StoreDataCommand.CreateWithFormat(
            StoreDataCommand.DataStructureFormat.BerTlv,
            StoreDataCommand.BlockFormat.FirstOrOnly,
            tlvData
        );

        return await storeResult.Match(
            async storeCommand =>
            {
                // Construct APDU byte array from command properties
                return await ConstructApduBytes(storeCommand)
                    .Bind(async apduBytes =>
                    {
                        var responseResult = await context.CardService.SendCommandAsync(apduBytes);
                        return responseResult.Match(
                            response =>
                                Result.Success<bool, SmartCardError>(response.StatusWord == 0x9000),
                            error => Result.Failure<bool, SmartCardError>(error)
                        );
                    });
            },
            error => Task.FromResult(Result.Failure<bool, SmartCardError>(error))
        );
    }

    /// <summary>
    /// Constructs an APDU byte array from the command properties following ISO 7816-4 format.
    /// Format: CLA INS P1 P2 [Lc] [Data] where Lc is the data length.
    /// </summary>
    private static Result<byte[], SmartCardError> ConstructApduBytes(StoreDataCommand command)
    {
        // Use centralized ApduBuilder to avoid DRY violation
        return ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(command));
    }

    private static (ushort tag, byte[] data) ParseRawDataObject(string key, string value)
    {
        if (key.StartsWith("0x") && key.Length > 2)
        {
            // Handle hex tag format: 0x9F70
            if (!ushort.TryParse(key.AsSpan(2), NumberStyles.HexNumber, null, out ushort tag))
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
                data = Encoding.UTF8.GetBytes(value);
            }

            return (tag, data);
        }

        // Try parsing as tag:data or tag=data format
        string fullString = $"{key}:{value}";
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

        throw new ArgumentException(
            $"Invalid data object format: {key}. Expected formats: 0x9F70, 9F70:040102, or 9F70=040102"
        );
    }

    private static byte[] CreateTlvData(ushort tag, byte[] data)
    {
        List<byte> result = [];

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

        switch (data.Length)
        {
            // Add length
            case < 0x80:
                result.Add((byte)data.Length);
                break;
            case < 0x100:
                result.Add(0x81);
                result.Add((byte)data.Length);
                break;
            default:
                result.Add(0x82);
                result.Add((byte)(data.Length >> 8));
                result.Add((byte)(data.Length & 0xFF));
                break;
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
        public string[] KeyValuePairs { get; set; }

        /// <summary>
        /// Gets or sets the configuration file path.
        /// </summary>
        [CommandOption("--file <FILE>")]
        [Description("Configuration file (JSON or key=value format). Use '-' for stdin")]
        public string ConfigFile { get; set; }

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
            bool hasKeyValuePairs = KeyValuePairs is { Length: > 0 };
            bool hasFile = !string.IsNullOrEmpty(ConfigFile);
            bool hasInteractive = Interactive;

            int inputMethods = new[] { hasKeyValuePairs, hasFile, hasInteractive }.Count(x => x);
            switch (inputMethods)
            {
                case 0:
                    return ValidationResult.Error(
                        "Must specify data using key=value pairs, --file, or --interactive"
                    );
                case > 1:
                    return ValidationResult.Error(
                        "Cannot combine key=value pairs, --file, and --interactive options"
                    );
                default:
                    return ValidationResult.Success();
            }
        }
    }
}
