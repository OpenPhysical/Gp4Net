using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.OpenPhysical;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Services.GlobalPlatform;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Command to retrieve data from ISD using GET DATA operations.
/// </summary>
[PublicAPI]
[CommandHandler(Description = "Retrieve data objects from the card")]
public class GetIsdDataCommand : IPipelineCommand<GetIsdDataCommand.Settings>
{
    /// <summary>
    /// Executes the get-data command to retrieve data objects from the card.
    /// </summary>
    public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
    {
        Result<ICliExecutionContext, SmartCardError> connectionResult = await context
            .WithVerbose(settings.Verbose)
            .RequireCardConnection(settings.GetReaderName());

        return await connectionResult.Match(
            async connectedCtx => await GetDataObjectsAsync(connectedCtx, settings),
            async connectionError =>
            {
                AnsiConsole.MarkupLine($"[red]Connection error: {connectionError.Message}[/]");
                return await Task.FromResult(1);
            }
        );
    }

    private static async Task<int> GetDataObjectsAsync(
        ICliExecutionContext context,
        Settings settings
    )
    {
        try
        {
            string dataObject = settings.DataObject.ToLowerInvariant();

            return dataObject switch
            {
                "iin" => await GetSingleDataObjectAsync(
                    context,
                    settings,
                    "IIN",
                    GetDataCommand.DataObjects.IssuerIdentificationNumber
                ),
                "cin" => await GetSingleDataObjectAsync(
                    context,
                    settings,
                    "CIN",
                    GetDataCommand.DataObjects.CardImageNumber
                ),
                "manager-url" => await GetSingleDataObjectAsync(
                    context,
                    settings,
                    "Manager URL",
                    GetDataCommand.DataObjects.SecurityDomainManagerUrl
                ),
                "opid" => await GetOpidDataAsync(context, settings),
                "all" => await GetAllDataAsync(context, settings),
                _ when dataObject.StartsWith("0x") => await GetRawDataObjectAsync(
                    context,
                    settings,
                    dataObject
                ),
                _ => HandleInvalidDataObject(context, dataObject),
            };
        }
        catch (Exception ex)
        {
            context.Display.Error($"Failed to retrieve data: {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> GetSingleDataObjectAsync(
        ICliExecutionContext context,
        Settings settings,
        string name,
        ushort tag
    )
    {
        try
        {
            Result<byte[], SmartCardError> dataResult = await Gp4Net.Services.GlobalPlatform.Commands.CreateGetDataCommand(tag)
                .Bind(command => command.ToCommandApdu())
                .Bind(async apdu =>
                {
                    Result<CommandResponse, SmartCardError> response = await context.CardService.ExecuteCommandAsync(apdu, CancellationToken.None);
                    return response.Bind(resp => Responses.ParseGetDataResponse(resp));
                });
            if (dataResult.IsSuccess)
            {
                DisplaySingleDataObject(
                    context,
                    settings,
                    name,
                    new GetDataResponse(tag, dataResult.Value)
                );
                return 0;
            }
            context.Display.Warning($"Could not retrieve {name}: {dataResult.Error.Message}");
            return 1;
        }
        catch (Exception ex)
        {
            context.Display.Warning($"Could not retrieve {name}: {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> GetRawDataObjectAsync(
        ICliExecutionContext context,
        Settings settings,
        string hexTag
    )
    {
        try
        {
            if (
                !hexTag.StartsWith("0x")
                || !ushort.TryParse(hexTag.AsSpan(2), NumberStyles.HexNumber, null, out ushort tag)
            )
            {
                context.Display.Error(
                    $"Invalid hex tag format: {hexTag}. Use format like '0x5F50'"
                );
                return 1;
            }

            Result<byte[], SmartCardError> dataResult = await Gp4Net.Services.GlobalPlatform.Commands.CreateGetDataCommand(tag)
                .Bind(command => command.ToCommandApdu())
                .Bind(async apdu =>
                {
                    Result<CommandResponse, SmartCardError> response = await context.CardService.ExecuteCommandAsync(apdu, CancellationToken.None);
                    return response.Bind(resp => Responses.ParseGetDataResponse(resp));
                });
            if (dataResult.IsSuccess)
            {
                DisplaySingleDataObject(
                    context,
                    settings,
                    $"Tag {hexTag.ToUpperInvariant()}",
                    new GetDataResponse(tag, dataResult.Value)
                );
                return 0;
            }
            context.Display.Warning(
                $"Tag {hexTag} is not supported by this card: {dataResult.Error.Message}"
            );
            return 1;
        }
        catch (Exception ex)
        {
            context.Display.Warning($"Could not retrieve tag {hexTag}: {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> GetOpidDataAsync(ICliExecutionContext context, Settings settings)
    {
        try
        {
            // Get all three required components
            Result<byte[], SmartCardError> iinResult = await Gp4Net.Services.GlobalPlatform.Commands.CreateGetDataCommand(GetDataCommand.DataObjects.IssuerIdentificationNumber)
                .Bind(command => command.ToCommandApdu())
                .Bind(async apdu =>
                {
                    Result<CommandResponse, SmartCardError> response = await context.CardService.ExecuteCommandAsync(apdu, CancellationToken.None);
                    return response.Bind(Responses.ParseGetDataResponse);
                });
            Result<byte[], SmartCardError> cinResult = await Gp4Net.Services.GlobalPlatform.Commands.CreateGetDataCommand(GetDataCommand.DataObjects.CardImageNumber)
                .Bind(command => command.ToCommandApdu())
                .Bind(async apdu =>
                {
                    Result<CommandResponse, SmartCardError> response = await context.CardService.ExecuteCommandAsync(apdu, CancellationToken.None);
                    return response.Bind(Responses.ParseGetDataResponse);
                });
            Result<byte[], SmartCardError> urlResult = await Gp4Net.Services.GlobalPlatform.Commands.CreateGetDataCommand(GetDataCommand.DataObjects.SecurityDomainManagerUrl)
                .Bind(command => command.ToCommandApdu())
                .Bind(async apdu =>
                {
                    Result<CommandResponse, SmartCardError> response = await context.CardService.ExecuteCommandAsync(apdu, CancellationToken.None);
                    return response.Bind(Responses.ParseGetDataResponse);
                });

            if (iinResult.IsFailure || cinResult.IsFailure || urlResult.IsFailure)
            {
                context.Display.Error(
                    "One or more required OPID components are not available on this card"
                );
                return 1;
            }

            // All OPID components should be ASCII per specification
            Result<string, SmartCardError> iinDecodeResult = iinResult.Bind(bytes =>
                Result.Success<string, SmartCardError>(Encoding.ASCII.GetString(bytes))
            );
            Result<string, SmartCardError> cinDecodeResult = cinResult.Bind(bytes =>
                Result.Success<string, SmartCardError>(Encoding.ASCII.GetString(bytes))
            );
            Result<string, SmartCardError> urlDecodeResult = urlResult.Bind(bytes =>
                Result.Success<string, SmartCardError>(Encoding.ASCII.GetString(bytes))
            );

            if (iinDecodeResult.IsFailure)
            {
                context.Display.Error($"Invalid IIN encoding: {iinDecodeResult.Error.Message}");
                return 1;
            }
            if (cinDecodeResult.IsFailure)
            {
                context.Display.Error($"Invalid CIN encoding: {cinDecodeResult.Error.Message}");
                return 1;
            }
            if (urlDecodeResult.IsFailure)
            {
                context.Display.Error(
                    $"Invalid Manager URL encoding: {urlDecodeResult.Error.Message}"
                );
                return 1;
            }

            string iin = iinDecodeResult.Value;
            string cin = cinDecodeResult.Value;
            string managerUrl = urlDecodeResult.Value;

            // Try to reconstruct OPID
            if (
                OpenPhysicalId.TryFromCardData(iin, cin, managerUrl, out OpenPhysicalId opid)
                && opid != null
            )
            {
                DisplayOpidData(context, settings, opid, iin, cin, managerUrl);
                return 0;
            }
            OpidValidationResult validation = OpidValidator.ValidateCardData(iin, cin, managerUrl);
            context.Display.Error(
                $"Card data does not represent a valid OPID: {validation.ErrorMessage}"
            );

            // Show the individual components for debugging
            Table table = new Table().AddColumn("Component").AddColumn("Value").AddColumn("Status");
            _ = table.AddRow(
                "IIN",
                iin,
                iin.Length == 4 && iin.All(char.IsDigit) ? "[green]✓[/]" : "[red]✗[/]"
            );
            _ = table.AddRow("CIN", cin, cin.All(char.IsDigit) ? "[green]✓[/]" : "[red]✗[/]");
            _ = table.AddRow(
                "Manager URL",
                managerUrl,
                managerUrl == OpenPhysicalId.OpenPhysicalManagerUrl ? "[green]✓[/]" : "[red]✗[/]"
            );

            AnsiConsole.Write(table);
            return 1;
        }
        catch (Exception ex)
        {
            context.Display.Error($"Could not retrieve OPID data: {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> GetAllDataAsync(ICliExecutionContext context, Settings settings)
    {
        Dictionary<string, string> results = new Dictionary<string, string>();
        List<string> errors = [];

        // Try to get all standard data objects
        (string, ushort)[] dataObjects =
        [
            ("IIN", GetDataCommand.DataObjects.IssuerIdentificationNumber),
            ("CIN", GetDataCommand.DataObjects.CardImageNumber),
            ("Manager URL", GetDataCommand.DataObjects.SecurityDomainManagerUrl),
            ("Card Data", GetDataCommand.DataObjects.CardData),
            ("Card Capabilities", GetDataCommand.DataObjects.CardCapabilities),
            ("Key Info Template", GetDataCommand.DataObjects.KeyInformationTemplate),
            ("Diversification Data", GetDataCommand.DataObjects.DiversificationData),
        ];

        foreach ((string name, ushort tag) in dataObjects)
        {
            try
            {
                Result<byte[], SmartCardError> dataResult = await Gp4Net.Services.GlobalPlatform.Commands.CreateGetDataCommand(tag)
                    .Bind(command => command.ToCommandApdu())
                    .Bind(async apdu =>
                    {
                        Result<CommandResponse, SmartCardError> response = await context.CardService.ExecuteCommandAsync(apdu, CancellationToken.None);
                        return response.Bind(resp => Responses.ParseGetDataResponse(resp));
                    });
                if (dataResult.IsSuccess)
                {
                    results[name] = FormatDataForDisplay(
                        new GetDataResponse(tag, dataResult.Value),
                        settings.Format
                    );
                }
                else
                {
                    errors.Add($"{name}: {dataResult.Error.Message}");
                    results[name] = "[red]Not available[/]";
                }
            }
            catch (Exception ex)
            {
                errors.Add($"{name}: {ex.Message}");
                results[name] = "[red]Not available[/]";
            }
        }

        // Try to reconstruct OPID if possible
        if (
            results.ContainsKey("IIN")
            && results.ContainsKey("CIN")
            && results.ContainsKey("Manager URL")
        )
        {
            // Functional OPID reconstruction with proper error handling
            Result<OpenPhysicalId, SmartCardError> opidResult = Result.Success<byte[], SmartCardError>(Convert.FromHexString(results["IIN"]))
                .Map(bytes => Encoding.ASCII.GetString(bytes))
                .Bind(iin =>
                    Result.Success<byte[], SmartCardError>(Convert.FromHexString(results["CIN"]))
                        .Map(bytes => Encoding.ASCII.GetString(bytes))
                        .Bind(cin =>
                            Result.Success<byte[], SmartCardError>(Convert.FromHexString(results["Manager URL"]))
                                .Map(bytes => Encoding.ASCII.GetString(bytes))
                                .Bind(url =>
                                {
                                    if (OpenPhysicalId.TryFromCardData(iin, cin, url, out OpenPhysicalId opid))
                                    {
                                        return Result.Success<OpenPhysicalId, SmartCardError>(opid);
                                    }
                                    return Result.Failure<OpenPhysicalId, SmartCardError>(
                                        SmartCardError.InvalidArgument("Failed to construct OPID from card data")
                                    );
                                })));

            opidResult.Match(
                opid => results["OPID"] = opid.ToDisplayFormat(),
                error => { /* OPID reconstruction failed, that's okay */ }
            );
        }

        DisplayAllData(context, settings, results, errors);
        return errors.Count > 0 ? 1 : 0;
    }

    private static int HandleInvalidDataObject(ICliExecutionContext context, string dataObject)
    {
        context.Display.Error($"Unknown data object: {dataObject}");
        context.Display.Info(
            "Supported objects: iin, cin, manager-url, opid, all, or hex tags like 0x5F50"
        );
        return 1;
    }

    private static void DisplaySingleDataObject(
        ICliExecutionContext context,
        Settings settings,
        string name,
        GetDataResponse response
    )
    {
        switch (settings.Format.ToLowerInvariant())
        {
            case "hex":
                AnsiConsole.WriteLine(Convert.ToHexString(response.Data));
                break;
            case "raw":
                Console.Out.Write(Encoding.UTF8.GetString(response.Data));
                break;
            case "json":
                var jsonData = new
                {
                    name,
                    value = Convert.ToHexString(response.Data),
                    length = response.Data.Length,
                };
                AnsiConsole.WriteLine(
                    JsonSerializer.Serialize(
                        jsonData,
                        new JsonSerializerOptions { WriteIndented = true }
                    )
                );
                break;
            default: // table
                Table table = new Table().AddColumn("Property").AddColumn("Value");
                _ = table.AddRow("Name", name);
                _ = table.AddRow("Value (Hex)", $"[dim]{Convert.ToHexString(response.Data)}[/]");
                _ = table.AddRow("Value (Text)", TryDecodeAsText(response.Data));
                _ = table.AddRow("Length", $"{response.Data.Length} bytes");
                AnsiConsole.Write(table);
                break;
        }
    }

    private static void DisplayOpidData(
        ICliExecutionContext context,
        Settings settings,
        OpenPhysicalId opid,
        string iin,
        string cin,
        string managerUrl
    )
    {
        switch (settings.Format.ToLowerInvariant())
        {
            case "hex":
                AnsiConsole.WriteLine(
                    Convert.ToHexString(Encoding.ASCII.GetBytes(opid.ToDisplayFormat()))
                );
                break;
            case "raw":
                Console.Out.Write(opid.ToDisplayFormat());
                break;
            case "json":
                var jsonData = new
                {
                    opid = opid.ToDisplayFormat(),
                    iin,
                    cin,
                    managerUrl,
                    format = opid.Format.ToString(),
                };
                AnsiConsole.WriteLine(
                    JsonSerializer.Serialize(
                        jsonData,
                        new JsonSerializerOptions { WriteIndented = true }
                    )
                );
                break;
            default: // table
                Table table = new Table().AddColumn("Property").AddColumn("Value");
                _ = table.AddRow("OPID", $"[green]{opid.ToDisplayFormat()}[/]");
                _ = table.AddRow("Format", $"{opid.Format} ({opid.Format.GetDescription()})");
                _ = table.AddRow("IIN", iin);
                _ = table.AddRow("CIN", cin);
                _ = table.AddRow("Manager URL", managerUrl);
                AnsiConsole.Write(table);
                break;
        }
    }

    private static void DisplayAllData(
        ICliExecutionContext context,
        Settings settings,
        Dictionary<string, string> results,
        List<string> errors
    )
    {
        switch (settings.Format.ToLowerInvariant())
        {
            case "json":
                var jsonData = new { data = results, errors };
                AnsiConsole.WriteLine(
                    JsonSerializer.Serialize(
                        jsonData,
                        new JsonSerializerOptions { WriteIndented = true }
                    )
                );
                break;
            default: // table
                Table table = new Table().AddColumn("Data Object").AddColumn("Value");
                foreach (KeyValuePair<string, string> kvp in results)
                {
                    _ = table.AddRow(kvp.Key, kvp.Value);
                }
                AnsiConsole.Write(table);

                if (errors.Count > 0)
                {
                    AnsiConsole.WriteLine();
                    context.Display.Warning("Some data objects could not be retrieved:");
                    foreach (string error in errors)
                    {
                        context.Display.Warning($"  {error}");
                    }
                }
                break;
        }
    }

    private static string FormatDataForDisplay(GetDataResponse response, string format)
    {
        return format.ToLowerInvariant() switch
        {
            "hex" => Convert.ToHexString(response.Data),
            "raw" => Encoding.UTF8.GetString(response.Data),
            _ => $"[dim]{Convert.ToHexString(response.Data)}[/]",
        };
    }

    private static string TryDecodeAsText(byte[] data)
    {
        try
        {
            string text = Encoding.UTF8.GetString(data);
            return text.All(c => !char.IsControl(c) || char.IsWhiteSpace(c))
                ? text
                : "[binary data]";
        }
        catch
        {
            return "[binary data]";
        }
    }

    /// <summary>
    /// Settings for the get-data command.
    /// </summary>
    public class Settings : CardCommandSettings
    {
        /// <summary>
        /// Gets or sets the data object to retrieve.
        /// </summary>
        [CommandArgument(0, "<object>")]
        [Description(
            "Data object to retrieve (iin, cin, manager-url, opid, all, or hex tag like 0x5F50)"
        )]
        public string DataObject { get; set; } = "";

        /// <summary>
        /// Gets or sets the output format.
        /// </summary>
        [CommandOption("--format <FORMAT>")]
        [Description("Output format: table (default), hex, raw, json")]
        [DefaultValue("table")]
        public string Format { get; set; } = "table";

        /// <summary>
        /// Validates the command settings.
        /// </summary>
        /// <returns>Success if valid, or an error message if validation fails.</returns>
        public override ValidationResult Validate()
        {
            if (string.IsNullOrWhiteSpace(DataObject))
            {
                return ValidationResult.Error("Data object must be specified");
            }

            string[] validFormats = ["table", "hex", "raw", "json"];
            if (!validFormats.Contains(Format.ToLowerInvariant()))
            {
                return ValidationResult.Error(
                    $"Invalid format '{Format}'. Valid formats: {string.Join(", ", validFormats)}"
                );
            }

            return ValidationResult.Success();
        }
    }
}
