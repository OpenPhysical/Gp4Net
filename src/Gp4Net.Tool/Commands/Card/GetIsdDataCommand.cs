using System;
using System.Collections.Generic;
using System.ComponentModel;
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
    /// Command to retrieve data from ISD using GET DATA operations.
    /// </summary>
    [PublicAPI]
    [CommandHandler(Description = "Retrieve data objects from the card")]
    public class GetIsdDataCommand : IPipelineCommand<GetIsdDataCommand.Settings>
    {
        /// <summary>
        /// Executes the get-data command to retrieve data objects from the card.
        /// </summary>
        public async Task<int> ExecuteAsync(ICommandContext context, Settings settings)
        {
            var ctx = await context.WithVerbose(settings.Verbose).RequireCardConnection(settings);

            return GetDataObjects(ctx, settings);
        }

        private static int GetDataObjects(ICommandContext context, Settings settings)
        {
            try
            {
                var dataObject = settings.DataObject.ToLowerInvariant();

                return dataObject switch
                {
                    "iin"
                        => GetSingleDataObject(
                            context,
                            settings,
                            "IIN",
                            Domain.Commands.GetDataCommand.DataObjects.IssuerIdentificationNumber
                        ),
                    "cin"
                        => GetSingleDataObject(
                            context,
                            settings,
                            "CIN",
                            Domain.Commands.GetDataCommand.DataObjects.CardImageNumber
                        ),
                    "manager-url"
                        => GetSingleDataObject(
                            context,
                            settings,
                            "Manager URL",
                            Domain.Commands.GetDataCommand.DataObjects.SecurityDomainManagerUrl
                        ),
                    "opid" => GetOpidData(context, settings),
                    "all" => GetAllData(context, settings),
                    _ when dataObject.StartsWith("0x")
                        => GetRawDataObject(context, settings, dataObject),
                    _ => HandleInvalidDataObject(context, dataObject)
                };
            }
            catch (Exception ex)
            {
                context.Display.Error($"Failed to retrieve data: {ex.Message}");
                return 1;
            }
        }

        private static int GetSingleDataObject(
            ICommandContext context,
            Settings settings,
            string name,
            ushort tag
        )
        {
            try
            {
                var response = context.GlobalPlatformService.GetData(tag);
                if (response != null)
                {
                    DisplaySingleDataObject(context, settings, name, response);
                }
                else
                {
                    context.Display.Warning($"{name} is not supported by this card");
                }
                return 0;
            }
            catch (Exception ex)
            {
                context.Display.Warning($"Could not retrieve {name}: {ex.Message}");
                return 1;
            }
        }

        private static int GetRawDataObject(
            ICommandContext context,
            Settings settings,
            string hexTag
        )
        {
            try
            {
                if (
                    !hexTag.StartsWith("0x")
                    || !ushort.TryParse(
                        hexTag.AsSpan(2),
                        System.Globalization.NumberStyles.HexNumber,
                        null,
                        out var tag
                    )
                )
                {
                    context.Display.Error(
                        $"Invalid hex tag format: {hexTag}. Use format like '0x5F50'"
                    );
                    return 1;
                }

                var response = context.GlobalPlatformService.GetData(tag);
                if (response != null)
                {
                    DisplaySingleDataObject(
                        context,
                        settings,
                        $"Tag {hexTag.ToUpperInvariant()}",
                        response
                    );
                }
                else
                {
                    context.Display.Warning($"Tag {hexTag} is not supported by this card");
                }
                return 0;
            }
            catch (Exception ex)
            {
                context.Display.Warning($"Could not retrieve tag {hexTag}: {ex.Message}");
                return 1;
            }
        }

        private static int GetOpidData(ICommandContext context, Settings settings)
        {
            try
            {
                // Get all three required components
                var iinResponse = context.GlobalPlatformService.GetData(
                    Domain.Commands.GetDataCommand.DataObjects.IssuerIdentificationNumber
                );
                var cinResponse = context.GlobalPlatformService.GetData(
                    Domain.Commands.GetDataCommand.DataObjects.CardImageNumber
                );
                var urlResponse = context.GlobalPlatformService.GetData(
                    Domain.Commands.GetDataCommand.DataObjects.SecurityDomainManagerUrl
                );

                if (iinResponse == null || cinResponse == null || urlResponse == null)
                {
                    context.Display.Error("One or more required OPID components are not available on this card");
                    return 1;
                }

                var iin = System.Text.Encoding.ASCII.GetString(iinResponse.Data);
                var cin = System.Text.Encoding.ASCII.GetString(cinResponse.Data);
                var managerUrl = System.Text.Encoding.UTF8.GetString(urlResponse.Data);

                // Try to reconstruct OPID
                if (
                    OpenPhysicalId.TryFromCardData(iin, cin, managerUrl, out var opid)
                    && opid != null
                )
                {
                    DisplayOpidData(context, settings, opid, iin, cin, managerUrl);
                    return 0;
                }
                else
                {
                    var validation = OpidValidator.ValidateCardData(iin, cin, managerUrl);
                    context.Display.Error(
                        $"Card data does not represent a valid OPID: {validation.ErrorMessage}"
                    );

                    // Show the individual components for debugging
                    var table = new Table()
                        .AddColumn("Component")
                        .AddColumn("Value")
                        .AddColumn("Status");
                    _ = table.AddRow(
                        "IIN",
                        iin,
                        iin.Length == 4 && iin.All(char.IsDigit) ? "[green]✓[/]" : "[red]✗[/]"
                    );
                    _ = table.AddRow(
                        "CIN",
                        cin,
                        cin.All(char.IsDigit) ? "[green]✓[/]" : "[red]✗[/]"
                    );
                    _ = table.AddRow(
                        "Manager URL",
                        managerUrl,
                        managerUrl == OpenPhysicalId.OpenPhysicalManagerUrl
                            ? "[green]✓[/]"
                            : "[red]✗[/]"
                    );

                    AnsiConsole.Write(table);
                    return 1;
                }
            }
            catch (Exception ex)
            {
                context.Display.Error($"Could not retrieve OPID data: {ex.Message}");
                return 1;
            }
        }

        private static int GetAllData(ICommandContext context, Settings settings)
        {
            var results = new Dictionary<string, string>();
            var errors = new List<string>();

            // Try to get all standard data objects
            var dataObjects = new[]
            {
                ("IIN", Domain.Commands.GetDataCommand.DataObjects.IssuerIdentificationNumber),
                ("CIN", Domain.Commands.GetDataCommand.DataObjects.CardImageNumber),
                (
                    "Manager URL",
                    Domain.Commands.GetDataCommand.DataObjects.SecurityDomainManagerUrl
                ),
                ("Card Data", Domain.Commands.GetDataCommand.DataObjects.CardData),
                ("Card Capabilities", Domain.Commands.GetDataCommand.DataObjects.CardCapabilities),
                (
                    "Key Info Template",
                    Domain.Commands.GetDataCommand.DataObjects.KeyInformationTemplate
                ),
                (
                    "Diversification Data",
                    Domain.Commands.GetDataCommand.DataObjects.DiversificationData
                )
            };

            foreach (var (name, tag) in dataObjects)
            {
                try
                {
                    var response = context.GlobalPlatformService.GetData(tag);
                    if (response != null)
                    {
                        results[name] = FormatDataForDisplay(response, settings.Format);
                    }
                    else
                    {
                        errors.Add($"{name} is not supported by this card");
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
                try
                {
                    var iin = System.Text.Encoding.ASCII.GetString(
                        Convert.FromHexString(results["IIN"])
                    );
                    var cin = System.Text.Encoding.ASCII.GetString(
                        Convert.FromHexString(results["CIN"])
                    );
                    var url = System.Text.Encoding.UTF8.GetString(
                        Convert.FromHexString(results["Manager URL"])
                    );

                    if (OpenPhysicalId.TryFromCardData(iin, cin, url, out var opid) && opid != null)
                    {
                        results["OPID"] = opid.ToDisplayFormat();
                    }
                }
                catch
                {
                    // OPID reconstruction failed, that's okay
                }
            }

            DisplayAllData(context, settings, results, errors);
            return errors.Count > 0 ? 1 : 0;
        }

        private static int HandleInvalidDataObject(ICommandContext context, string dataObject)
        {
            context.Display.Error($"Unknown data object: {dataObject}");
            context.Display.Info(
                "Supported objects: iin, cin, manager-url, opid, all, or hex tags like 0x5F50"
            );
            return 1;
        }

        private static void DisplaySingleDataObject(
            ICommandContext context,
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
                    Console.Out.Write(System.Text.Encoding.UTF8.GetString(response.Data));
                    break;
                case "json":
                    var jsonData = new
                    {
                        name,
                        value = Convert.ToHexString(response.Data),
                        length = response.Data.Length
                    };
                    AnsiConsole.WriteLine(
                        JsonSerializer.Serialize(
                            jsonData,
                            new JsonSerializerOptions { WriteIndented = true }
                        )
                    );
                    break;
                default: // table
                    var table = new Table().AddColumn("Property").AddColumn("Value");
                    _ = table.AddRow("Name", name);
                    _ = table.AddRow(
                        "Value (Hex)",
                        $"[dim]{Convert.ToHexString(response.Data)}[/]"
                    );
                    _ = table.AddRow("Value (Text)", TryDecodeAsText(response.Data));
                    _ = table.AddRow("Length", $"{response.Data.Length} bytes");
                    AnsiConsole.Write(table);
                    break;
            }
        }

        private static void DisplayOpidData(
            ICommandContext context,
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
                        Convert.ToHexString(
                            System.Text.Encoding.ASCII.GetBytes(opid.ToDisplayFormat())
                        )
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
                        format = opid.Format.ToString()
                    };
                    AnsiConsole.WriteLine(
                        JsonSerializer.Serialize(
                            jsonData,
                            new JsonSerializerOptions { WriteIndented = true }
                        )
                    );
                    break;
                default: // table
                    var table = new Table().AddColumn("Property").AddColumn("Value");
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
            ICommandContext context,
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
                    var table = new Table().AddColumn("Data Object").AddColumn("Value");
                    foreach (var kvp in results)
                    {
                        _ = table.AddRow(kvp.Key, kvp.Value);
                    }
                    AnsiConsole.Write(table);

                    if (errors.Count > 0)
                    {
                        AnsiConsole.WriteLine();
                        context.Display.Warning("Some data objects could not be retrieved:");
                        foreach (var error in errors)
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
                "raw" => System.Text.Encoding.UTF8.GetString(response.Data),
                _ => $"[dim]{Convert.ToHexString(response.Data)}[/]"
            };
        }

        private static string TryDecodeAsText(byte[] data)
        {
            try
            {
                var text = System.Text.Encoding.UTF8.GetString(data);
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

                var validFormats = new[] { "table", "hex", "raw", "json" };
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
}
