using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Services;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using log4net;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card
{
    /// <summary>
    /// Command to display detailed card information.
    /// </summary>
    [PublicAPI]
    [CommandHandler(Description = "Display detailed card information")]
    public class InfoCommand : IPipelineCommand<InfoCommand.Settings>
    {
        private static readonly ILog Logger = LogManager.GetLogger(typeof(InfoCommand));

        /// <summary>
        /// Executes the info command to display detailed card information.
        /// </summary>
        public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
        {
            try
            {
                // Build custom pipeline for info command - never establish secure channel, always show card info
                var ctx = context.WithVerbose(settings.Verbose);
                ctx = await ctx.RequireCardConnection(settings);

                return await ctx.ExecuteAsync(async ctx =>
                {
                    Logger.Debug("InfoCommand: Starting execution");

                    var table = new Table().AddColumn("Property").AddColumn("Value");

                    // Basic card information (always available)
                    Logger.Debug("InfoCommand: About to call GetAtr()");

                    var atr = ctx.CardService.GetAtr();
                    Logger.Debug("InfoCommand: GetAtr() returned");

                if (atr != null)
                {
                    _ = table.AddRow("ATR", $"[dim]{Convert.ToHexString(atr)}[/]");
                }

                // Connection information
                _ = table.AddRow("Connection Status", "[green]✓ Connected[/]");
                _ = table.AddRow(
                    "Secure Channel",
                    ctx.CardService.IsSecureChannelEstablished
                        ? "[green]✓ Active[/]"
                        : "[yellow]✗ Not established[/]"
                );

                // Try to get ISD information (doesn't require secure channel)
                try
                {
                    var selectResult = await ctx.GetGlobalPlatformService().SelectIsdAsync();
                    if (selectResult.IsSuccess)
                    {
                        var selectResponse = selectResult.Value;
                        _ = table.AddRow("ISD Status", "[green]✓ Available[/]");

                        if (selectResponse.RawData != null && selectResponse.RawData.Length > 0)
                        {
                            AddIsdDataToTable(table, selectResponse);
                        }
                    }
                    else
                    {
                        Logger.Debug($"Could not select ISD: {selectResult.Error.Message}");
                        _ = table.AddRow("ISD Status", "[red]Not available[/]");
                    }

                    // Add CPLC data to table (doesn't require secure channel)
                    try
                    {
                        var cplcResult = await ctx.GetGlobalPlatformService().GetCplcAsync();
                        if (cplcResult.IsSuccess)
                        {
                            AddCplcToTable(table, cplcResult.Value);
                        }
                        else
                        {
                            Logger.Debug($"Could not get CPLC data: {cplcResult.Error.Message}");
                            _ = table.AddRow("CPLC Data", "[red]Not available[/]");
                        }
                    }
                    catch (Exception cplcEx)
                    {
                        Logger.Debug($"Could not get CPLC data: {cplcEx.Message}");
                        _ = table.AddRow("ISD Status", $"[red]✗ Error: {cplcEx.Message}[/]");
                    }

                    // Add other GET DATA commands to table (these don't require secure channel)
                    await AddGetDataToTable(ctx, table, "Card Data", GetDataCommand.DataObjects.CardData);
                    await AddGetDataToTable(
                        ctx,
                        table,
                        "Card Capabilities",
                        GetDataCommand.DataObjects.CardCapabilities
                    );
                    await AddGetDataToTable(
                        ctx,
                        table,
                        "Key Info Template",
                        GetDataCommand.DataObjects.KeyInformationTemplate
                    );
                    await AddGetDataToTable(
                        ctx,
                        table,
                        "Diversification Data",
                        GetDataCommand.DataObjects.DiversificationData
                    );

                    // Only get applications if we have a secure channel (requires GET STATUS commands)
                    if (ctx.CardService.IsSecureChannelEstablished)
                    {
                        try
                        {
                            var statusResult = await ctx.GetGlobalPlatformService().GetStatusAsync(StatusSubset.Applications);
                            if (statusResult.IsSuccess)
                            {
                                var applications = statusResult.Value;
                                var appCounts = applications
                                    .GroupBy(a => a.Type)
                                    .ToDictionary(g => g.Key, g => g.Count());

                                _ = table.AddRow("Total Applications", applications.Count.ToString());

                                foreach (var kvp in appCounts)
                                {
                                    _ = table.AddRow($"  - {kvp.Key}", kvp.Value.ToString());
                                }
                            }
                            else
                            {
                                Logger.Debug($"Could not get applications: {statusResult.Error.Message}");
                                _ = table.AddRow("Applications", "[red]Error retrieving[/]");
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Debug($"Application status error: {ex.Message}");
                            _ = table.AddRow("Applications", $"[red]Error: {ex.Message}[/]");
                        }
                    }
                    else
                    {
                        _ = table.AddRow("Applications", "[yellow]Requires secure channel[/]");
                    }

                }
                catch (Exception ex)
                {
                    Logger.Debug($"ISD error: {ex.Message}");
                    _ = table.AddRow("ISD Status", $"[red]✗ Error: {ex.Message}[/]");
                }

                AnsiConsole.Write(
                    new Panel(table).Header("[bold]Card Information[/]").BorderColor(Color.Green)
                );

                // Show helpful message if not in secure channel
                if (!ctx.CardService.IsSecureChannelEstablished)
                {
                    AnsiConsole.WriteLine();
                    AnsiConsole.MarkupLine(
                        "[yellow]💡 Tip: More information is available with a secure channel.[/]"
                    );
                    AnsiConsole.MarkupLine("[dim]Try: gp4net card info --keyset <KEYSET_NAME>[/]");
                }

                return 0;
                });
            }
            catch (Exception ex)
            {
                Logger.Error("Error executing info command", ex);
                AnsiConsole.MarkupLine($"[red]Error: {ex.Message}[/]");
                return 1;
            }
        }

        private void AddIsdDataToTable(Table table, SelectResponse selectResponse)
        {
            try
            {
                var fci = selectResponse.Fci;
                if (fci != null)
                {
                    if (fci.ApplicationAid != null)
                    {
                        _ = table.AddRow("ISD AID", Convert.ToHexString(fci.ApplicationAid));
                    }

                    if (!string.IsNullOrEmpty(fci.ApplicationLabel))
                    {
                        _ = table.AddRow("ISD Label", fci.ApplicationLabel);
                    }

                    if (fci.IssuerIdentificationNumber != null)
                    {
                        _ = table.AddRow(
                            "Issuer ID Number",
                            Convert.ToHexString(fci.IssuerIdentificationNumber)
                        );
                    }

                    if (fci.CardImageNumber != null)
                    {
                        _ = table.AddRow(
                            "Card Image Number",
                            Convert.ToHexString(fci.CardImageNumber)
                        );
                    }

                    if (fci.DiscretionaryData != null)
                    {
                        var decoded = SecurityDomainDataParser.Decode(fci.DiscretionaryData);
                        if (!string.IsNullOrEmpty(decoded))
                        {
                            _ = table.AddRow("Discretionary Data", decoded);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"Could not parse ISD data: {ex.Message}");
                _ = table.AddRow(
                    "ISD Data",
                    $"[dim]{Convert.ToHexString(selectResponse.RawData)}[/]"
                );
            }
        }


        private void AddCplcToTable(Table table, CplcData cplc)
        {
            _ = table.AddRow("IC Fabricator", $"{cplc.IcFabricator:X4}");
            _ = table.AddRow("IC Type", $"{cplc.IcType:X4}");
            _ = table.AddRow("Operating System ID", $"{cplc.OperatingSystemId:X4}");
            _ = table.AddRow(
                "IC Fabrication Date",
                $"{cplc.IcFabricationDate:X4} ({CplcDateParser.FormatDate(cplc.IcFabricationDate)})"
            );
            _ = table.AddRow("IC Serial Number", $"{cplc.IcSerialNumber:X8}");
            _ = table.AddRow("IC Batch Identifier", $"{cplc.IcBatchIdentifier:X4}");
        }

        /// <summary>
        /// Retrieves data using GET DATA command and adds it to the display table.
        /// Provides special handling for different data object types.
        /// </summary>
        /// <param name="context">The command context for GP operations.</param>
        /// <param name="table">The table to add the data to.</param>
        /// <param name="name">The display name for this data.</param>
        /// <param name="tag">The data object identifier tag.</param>
        private static async Task AddGetDataToTable(
            ICliExecutionContext context,
            Table table,
            string name,
            ushort tag
        )
        {
            try
            {
                var dataResult = await context.GetGlobalPlatformService().GetDataAsync(tag);
                if (dataResult.IsSuccess)
                {
                    var response = dataResult.Value;
                    if (response != null && response.Length > 0)
                    {
                        // Special handling for specific data types
                        if (tag == GetDataCommand.DataObjects.CardData)
                        {
                            var cardData = response.ParseAsCardData();
                            if (cardData != null)
                            {
                                // Prefer OID-based version (matches GP Pro behavior)
                                var gpVersion = cardData.GlobalPlatformVersionFromOid ?? cardData.GlobalPlatformVersion?.ToString();
                                if (!string.IsNullOrEmpty(gpVersion))
                                {
                                    _ = table.AddRow("GlobalPlatform Version", gpVersion);
                                }
                                else
                                {
                                    _ = table.AddRow(name, $"[dim]{Convert.ToHexString(response)}[/]");
                                }
                            }
                            else
                            {
                                _ = table.AddRow(name, $"[dim]{Convert.ToHexString(response)}[/]");
                            }
                        }
                        else if (tag == GetDataCommand.DataObjects.CardCapabilities)
                        {
                            var capabilities = response.ParseAsCardCapabilities();
                            if (capabilities != null)
                            {
                                // Display SCP support from capabilities
                                    var scpSupport = ScpCapabilitiesParser.Parse(response);
                                    if (!string.IsNullOrEmpty(scpSupport))
                                    {
                                        _ = table.AddRow("SCP Support (Capabilities)", scpSupport);
                                    }

                                    // Display other capability information (algorithms, cipher suites, etc.)
                                    if (capabilities.Algorithms != null)
                                    {
                                        var hashAlgs = capabilities.Algorithms.GetHashAlgorithms();
                                        if (!string.IsNullOrEmpty(hashAlgs) && hashAlgs != "None")
                                        {
                                            _ = table.AddRow("Hash Algorithms", hashAlgs);
                                        }
                                    }

                                    // Display cipher suites if available
                                    if (capabilities.CipherSuites.Count > 0)
                                    {
                                        foreach (var kvp in capabilities.CipherSuites.Take(3)) // Limit to avoid clutter
                                        {
                                            var cipherNames = string.Join(", ", kvp.Value.Take(3).Select(c => c.ToFriendlyString()));
                                            _ = table.AddRow($"{kvp.Key} Ciphers", cipherNames);
                                        }
                                    }
                                }
                                else
                                {
                                    _ = table.AddRow(name, $"[dim]{Convert.ToHexString(response)}[/]");
                                }
                            }
                            else if (tag == GetDataCommand.DataObjects.DiversificationData)
                            {
                                // Extract and display SCP support from diversification data
                                var scpSupport = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(response));
                                _ = table.AddRow("SCP Support", scpSupport);
                            }
                            else if (tag == GetDataCommand.DataObjects.KeyInformationTemplate)
                            {
                                var keyInfo = response.ParseAsKeyInformation();
                                if (keyInfo != null && keyInfo.Keys.Count > 0)
                                {
                                    foreach (var key in keyInfo.Keys.OrderBy(k => k.KeyId))
                                    {
                                        var keyName = key.KeyId switch
                                        {
                                            1 => "ENC Key",
                                            2 => "MAC Key",
                                            3 => "DEK Key",
                                            _ => $"Key {key.KeyId}"
                                        };
                                        var keyDesc = $"v{key.KeyVersion} {key.PrimaryKeyType.ToFriendlyString()} ({key.KeyLength} bit)";
                                        _ = table.AddRow(keyName, keyDesc);
                                    }
                                }
                                else
                                {
                                    _ = table.AddRow("Key Information", "[dim]No keys found[/]");
                                }
                            }
                            else
                            {
                                _ = table.AddRow(name, $"[dim]{Convert.ToHexString(response)}[/]");
                            }
                        }
                        else
                        {
                            _ = table.AddRow(name, "[dim]Not supported[/]");
                        }
                    }
                else
                {
                    Logger.Debug($"Could not get {name}: {dataResult.Error.Message}");
                    _ = table.AddRow(name, "[red]Error retrieving data[/]");
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"Could not get {name}: {ex.Message}");
                _ = table.AddRow(name, "[red]Error retrieving data[/]");
            }
        }





        /// <summary>
        /// Settings for the info command.
        /// </summary>
        public class Settings : CardCommandSettings { }
    }
}
