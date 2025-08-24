using System;
using System.Linq;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Protocol;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using log4net;
using Spectre.Console;
using StatusSubset = Gp4Net.Domain.Commands.GetStatusCommand.StatusSubset;

namespace Gp4Net.Tool.Commands.Card;

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

                var table = new Table()
                    .AddColumn(new TableColumn("Property").NoWrap())
                    .AddColumn(new TableColumn("Value"));

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

                        if (selectResponse.RawData is { Length: > 0 })
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
                            
                            // Add chip information if available
                            var chipInfo = cplcResult.Value.GetChipInfo();
                            AddChipInfoToTable(table, chipInfo);
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
                        _ = table.AddRow("CPLC Data", $"[red]✗ Error: {cplcEx.Message}[/]");
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
                    await AddGetDataToTable(
                        ctx,
                        table,
                        "Security Domain Status",
                        GetDataCommand.DataObjects.SecurityDomainManagementData
                    );

                    // Only get applications if we have a secure channel (requires GET STATUS commands)
                    if (ctx.CardService.IsSecureChannelEstablished)
                    {
                        try
                        {
                            var statusResult = await ctx.GetGlobalPlatformService().GetStatusAsync(StatusSubset.ApplicationsAndSupplementaryDomains);
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

    private static void AddIsdDataToTable(Table table, SelectResponse selectResponse)
    {
        try
        {
            selectResponse.Fci.Match(
                fci =>
                {
                    // Add AID if present
                    if (fci.ApplicationAid.Length > 0)
                    {
                        _ = table.AddRow("ISD AID", Convert.ToHexString(fci.ApplicationAid));
                    }

                    // Add label if present
                    fci.ApplicationLabel.Match(
                        label => { _ = table.AddRow("ISD Label", label); return true; },
                        () => false);

                    // Add issuer identification number if present
                    if (fci.IssuerIdentificationNumber.Length > 0)
                    {
                        _ = table.AddRow(
                            "Issuer ID Number",
                            Convert.ToHexString(fci.IssuerIdentificationNumber)
                        );
                    }

                    // Add card image number if present
                    if (fci.CardImageNumber.Length > 0)
                    {
                        _ = table.AddRow(
                            "Card Image Number",
                            Convert.ToHexString(fci.CardImageNumber)
                        );
                    }

                    // Add discretionary data if present
                    if (fci.DiscretionaryData.Length > 0)
                    {
                        var decoded = SecurityDomainDataParser.Decode(fci.DiscretionaryData);
                        if (decoded.Length > 0)
                        {
                            _ = table.AddRow("Discretionary Data", decoded);
                        }
                    }
                    return true;
                },
                () => false);
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


    private static void AddCplcToTable(Table table, CplcData cplc)
    {
        _ = table.AddRow("[dim]───CPLC Data───[/]", string.Empty);
        _ = table.AddRow("IC Fabricator", $"{cplc.GetManufacturerName()} (0x{cplc.IcFabricator:X4})");
        _ = table.AddRow("IC Type", $"{cplc.GetChipModel()} (0x{cplc.IcType:X4})");
        _ = table.AddRow("Operating System", $"{cplc.GetOperatingSystemName()} (0x{cplc.OperatingSystemId:X4})");
        
        // Display all date fields with validity check
        AddDateField(table, "OS Release Date", cplc.OperatingSystemReleaseDate);
        AddDateField(table, "IC Fabrication Date", cplc.IcFabricationDate);
        
        _ = table.AddRow("IC Serial Number", $"0x{cplc.IcSerialNumber:X8} ({cplc.IcSerialNumber})");
        _ = table.AddRow("IC Batch ID", $"0x{cplc.IcBatchIdentifier:X4}");
        
        // Additional CPLC fields
        AddDateField(table, "Module Packaging Date", cplc.IcModulePackagingDate);
        AddDateField(table, "Embedding Date", cplc.IcEmbeddingDate);
        _ = table.AddRow("Pre-Personalizer", $"0x{cplc.IcPrePersonalizer:X4}");
        AddDateField(table, "Pre-Perso Equip Date", cplc.IcPrePersonalizationEquipmentDate);
        _ = table.AddRow("Pre-Perso Equip ID", $"0x{cplc.IcPrePersonalizationEquipmentId:X8}");
        AddDateField(table, "Personalization Date", cplc.IcPersonalizationDate);
    }
    
    private static void AddDateField(Table table, string name, ushort dateValue)
    {
        var dateStr = CplcData.IsValidDate(dateValue) 
            ? $"0x{dateValue:X4} ({CplcDateParser.FormatDate(dateValue)})"
            : $"0x{dateValue:X4} [dim](invalid date format)[/]";
        _ = table.AddRow(name, dateStr);
    }
    
    private static void AddChipInfoToTable(Table table, ChipInfo chipInfo)
    {
        _ = table.AddRow("[dim]───Chip Details───[/]", string.Empty);
        _ = table.AddRow("Chip Platform", $"{chipInfo.Platform} ({chipInfo.Architecture})");
        chipInfo.MemoryConfig.Match(
            Some: config => table.AddRow("Memory Config", chipInfo.GetMemoryDescription()),
            None: () => { }
        );
        _ = table.AddRow("Certifications", chipInfo.GetCertificationsString());
        chipInfo.JavaCardVersion.Match(
            Some: version => table.AddRow("Java Card Version", version),
            None: () => { }
        );
        chipInfo.GlobalPlatformVersion.Match(
            Some: version => table.AddRow("GlobalPlatform Version", version),
            None: () => { }
        );
        _ = table.AddRow("Crypto Support", chipInfo.GetCryptoSummary());
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
                if (response is { Length: > 0 })
                {
                    // Special handling for specific data types
                    if (tag == GetDataCommand.DataObjects.CardData)
                    {
                        var cardData = response.ParseAsCardData();
                        if (cardData.HasValue)
                        {
                            // Prefer OID-based version (matches GP Pro behavior)
                            var gpVersion = cardData.Value.GlobalPlatformVersionFromOid.GetValueOrDefault() ?? 
                                          cardData.Value.GlobalPlatformVersion.Map(v => v.ToString()).GetValueOrDefault();
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
                        if (capabilities.HasValue)
                        {
                            // Display SCP support from capabilities
                            var scpInfo = ScpCapabilitiesParser.ParseDetailed(response);
                            if (scpInfo.Protocols.Count > 0)
                            {
                                // Display each SCP protocol on its own line with details
                                _ = table.AddRow("SCP Support", scpInfo.Protocols[0].ToShortString());
                                foreach (var protocol in scpInfo.Protocols.Skip(1))
                                {
                                    _ = table.AddRow("", protocol.ToShortString());
                                }
                                
                                // Add detailed implementation descriptions
                                foreach (var protocol in scpInfo.Protocols)
                                {
                                    foreach (var impl in protocol.ImplementationOptions)
                                    {
                                        var description = GetImplementationDescription(impl);
                                        _ = table.AddRow($"  {impl:X2}", description);
                                    }
                                }
                            }

                            // Display other capability information (algorithms, cipher suites, etc.)
                            if (capabilities.Value.Algorithms.HasValue)
                            {
                                var hashAlgs = capabilities.Value.Algorithms.Value.GetHashAlgorithms();
                                if (!string.IsNullOrEmpty(hashAlgs) && hashAlgs != "None")
                                {
                                    _ = table.AddRow("Hash Algorithms", hashAlgs);
                                }
                            }

                            // Display cipher suites if available
                            if (capabilities.Value.CipherSuites.Count > 0)
                            {
                                foreach (var kvp in capabilities.Value.CipherSuites.Take(3)) // Limit to avoid clutter
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
                        // Diversification data doesn't always contain SCP support
                        // Only parse as SCP support if it follows the CF0A format
                        if (response.Length >= 12 && response[0] == 0xCF && response[1] == 0x0A)
                        {
                            var scpSupport = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(response));
                            if (!scpSupport.Contains("None") && !scpSupport.Contains("error"))
                            {
                                _ = table.AddRow("SCP Support (CF)", scpSupport);
                            }
                        }
                        _ = table.AddRow(name, $"[dim]{Convert.ToHexString(response)}[/]");
                    }
                    else if (tag == GetDataCommand.DataObjects.SecurityDomainManagementData)
                    {
                        var statusResult = response.ParseAsSecurityDomainStatus();
                        if (statusResult.HasValue)
                        {
                            _ = table.AddRow(name, statusResult.Value.GetShortDescription());
                        }
                        else
                        {
                            _ = table.AddRow(name, $"[dim]{Convert.ToHexString(response)}[/]");
                        }
                    }
                    else if (tag == GetDataCommand.DataObjects.KeyInformationTemplate)
                    {
                        var keyInfo = response.ParseAsKeyInformation();
                        if (keyInfo.HasValue && keyInfo.Value.Keys.Count > 0)
                        {
                            foreach (var key in keyInfo.Value.Keys.OrderBy(k => k.KeyId))
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
    /// Gets a human-readable description for an SCP implementation option.
    /// </summary>
    private static string GetImplementationDescription(ScpImplementation implementation)
    {
        // For SCP02, use the bitmap-based description system from extension methods
        if (implementation.IsScp02())
        {
            return implementation.GetDescription();
        }
        
        // For SCP03 and other protocols, use explicit descriptions
        return implementation switch
        {
            ScpImplementation.Scp03I10 => "AES-128",
            ScpImplementation.Scp03I20 => "AES-192", 
            ScpImplementation.Scp03I30 => "AES-256",
            ScpImplementation.Scp03I11 => "AES-128 (no R-MAC)",
            ScpImplementation.Scp03I60 => "Random card challenge",
            ScpImplementation.Scp03I70 => "Pseudo-random card challenge",
            _ => $"Implementation 0x{((byte)implementation):X2}"
        };
    }

    /// <summary>
    /// Settings for the info command.
    /// </summary>
    public class Settings : CardCommandSettings { }
}
