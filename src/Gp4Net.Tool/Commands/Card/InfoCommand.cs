using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
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
        public async Task<int> ExecuteAsync(ICommandContext context, Settings settings)
        {
            try
            {
                // Build custom pipeline for info command - never establish secure channel, always show card info
                var ctx = context.WithVerbose(settings.Verbose);
                ctx = await ctx.RequireCardConnection(settings);

                return await ctx.ExecuteAsync(ctx =>
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
                    var selectResponse = ctx.GlobalPlatformService.SelectIsd();
                    _ = table.AddRow("ISD Status", "[green]✓ Available[/]");

                    if (selectResponse.RawData != null && selectResponse.RawData.Length > 0)
                    {
                        AddIsdDataToTable(table, selectResponse);
                    }

                    // Add CPLC data to table (doesn't require secure channel)
                    try
                    {
                        var cplc = ctx.GlobalPlatformService.GetCplc();
                        if (cplc != null)
                        {
                            AddCplcToTable(table, cplc);
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Debug($"Could not get CPLC data: {ex.Message}");
                        _ = table.AddRow("CPLC Data", "[red]Not available[/]");
                    }

                    // Add other GET DATA commands to table (these don't require secure channel)
                    AddGetDataToTable(ctx, table, "Card Data", GetDataCommand.DataObjects.CardData);
                    AddGetDataToTable(
                        ctx,
                        table,
                        "Card Capabilities",
                        GetDataCommand.DataObjects.CardCapabilities
                    );
                    AddGetDataToTable(
                        ctx,
                        table,
                        "Key Info Template",
                        GetDataCommand.DataObjects.KeyInformationTemplate
                    );
                    AddGetDataToTable(
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
                            var applications = ctx.GlobalPlatformService.GetApplications();
                            var appCounts = applications
                                .GroupBy(a => a.Type)
                                .ToDictionary(g => g.Key, g => g.Count());

                            _ = table.AddRow("Total Applications", applications.Count.ToString());

                            foreach (var kvp in appCounts)
                            {
                                _ = table.AddRow($"  - {kvp.Key}", kvp.Value.ToString());
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Debug($"Could not get applications: {ex.Message}");
                            _ = table.AddRow("Applications", "[red]Error retrieving[/]");
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
                        var decoded = DecodeSecurityDomainData(fci.DiscretionaryData);
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

        private string DecodeSecurityDomainData(byte[] data)
        {
            try
            {
                if (data == null || data.Length == 0)
                {
                    return string.Empty;
                }

                var result = new List<string>();

                // Parse A5 tag (proprietary data)
                if (data.Length >= 2 && data[0] == 0xA5)
                {
                    int offset = 2; // Skip A5 and length

                    while (offset < data.Length)
                    {
                        if (data[offset] == 0x9F && offset + 1 < data.Length)
                        {
                            var tag = (data[offset] << 8) | data[offset + 1];
                            if (offset + 2 < data.Length)
                            {
                                var length = data[offset + 2];
                                if (offset + 3 + length <= data.Length)
                                {
                                    var value = data[(offset + 3)..(offset + 3 + length)];

                                    switch (tag)
                                    {
                                        case 0x9F65: // Maximum APDU size
                                            if (length >= 2)
                                            {
                                                var maxApdu = (value[0] << 8) | value[1];
                                                result.Add($"Max APDU: {maxApdu} bytes");
                                            }
                                            break;
                                        case 0x9F6E: // Application production lifecycle data
                                            if (length >= 1)
                                            {
                                                var lifecycle = value[0] switch
                                                {
                                                    0x01 => "Loaded",
                                                    0x03 => "Installed",
                                                    0x07 => "Selectable",
                                                    0x0F => "Personalized",
                                                    0x83 => "Blocked",
                                                    0x87 => "Locked",
                                                    _ => $"0x{value[0]:X2}"
                                                };
                                                result.Add($"Lifecycle: {lifecycle}");
                                            }
                                            break;
                                        default:
                                            result.Add(
                                                $"Tag {tag:X4}: {Convert.ToHexString(value)}"
                                            );
                                            break;
                                    }
                                }
                                offset += 3 + length;
                            }
                            else
                            {
                                break;
                            }
                        }
                        else
                        {
                            offset++;
                        }
                    }
                }

                return result.Count > 0 ? string.Join(", ", result) : Convert.ToHexString(data);
            }
            catch
            {
                return Convert.ToHexString(data);
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
        private void AddGetDataToTable(
            ICommandContext context,
            Table table,
            string name,
            ushort tag
        )
        {
            try
            {
                var response = context.GlobalPlatformService.GetData(tag);
                if (response != null)
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
                                _ = table.AddRow(name, $"[dim]{response.GetValueAsHexString()}[/]");
                            }
                        }
                        else
                        {
                            _ = table.AddRow(name, $"[dim]{response.GetValueAsHexString()}[/]");
                        }
                    }
                    else if (tag == GetDataCommand.DataObjects.CardCapabilities)
                    {
                        var capabilities = response.ParseAsCardCapabilities();
                        if (capabilities != null)
                        {
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
                            _ = table.AddRow(name, $"[dim]{response.GetValueAsHexString()}[/]");
                        }
                    }
                    else if (tag == GetDataCommand.DataObjects.DiversificationData)
                    {
                        if (response.Data != null)
                        {
                            // Extract and display SCP support from diversification data
                            var scpSupport = ParseScpSupportFromDiversificationData(response.Data);
                            _ = table.AddRow("SCP Support", scpSupport);
                        }
                        else
                        {
                            _ = table.AddRow("SCP Support", "[dim]No data[/]");
                        }
                    }
                    else if (tag == GetDataCommand.DataObjects.KeyInformationTemplate)
                    {
                        if (response.Data != null)
                        {
                            AddKeyInfoToTable(table, response.Data);
                        }
                        else
                        {
                            _ = table.AddRow(name, "[dim]No data[/]");
                        }
                    }
                    else
                    {
                        _ = table.AddRow(name, $"[dim]{response.GetValueAsHexString()}[/]");
                    }
                }
                else
                {
                    _ = table.AddRow(name, "[dim]Not supported[/]");
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"Could not get {name}: {ex.Message}");
                _ = table.AddRow(name, "[red]Error retrieving data[/]");
            }
        }

        private string ParseScpCapabilities(byte[] data)
        {
            try
            {
                if (data == null || data.Length == 0)
                {
                    return string.Empty;
                }

                var result = new List<string>();

                // GlobalPlatform Card Capabilities format analysis
                // Look for various SCP indicators in the TLV structure
                int offset = 0;

                while (offset < data.Length - 1)
                {
                    var tag = data[offset];

                    if (offset + 1 >= data.Length)
                    {
                        break;
                    }

                    var length = data[offset + 1];

                    if (offset + 2 + length > data.Length)
                    {
                        break;
                    }

                    switch (tag)
                    {
                        case 0x81: // Secure messaging support
                            for (int i = 0; i < length; i++)
                            {
                                var protocol = data[offset + 2 + i];
                                // Check for specific SCP protocol support indicators
                                if (protocol == 0x01 || protocol == 0x02)
                                {
                                    result.Add("SCP02");
                                }

                                if (protocol == 0x06 || protocol == 0x07)
                                {
                                    result.Add("SCP03");
                                }

                                if (protocol == 0x10)
                                {
                                    result.Add("SCP10");
                                }
                            }
                            break;

                        case 0x82: // Secure channel protocol data
                            // Sometimes contains direct protocol indicators
                            for (int i = 0; i < length; i++)
                            {
                                var value = data[offset + 2 + i];
                                // Look for SCP protocol version bytes
                                if (value == 0x02)
                                {
                                    result.Add("SCP02");
                                }

                                if (value == 0x03)
                                {
                                    result.Add("SCP03");
                                }
                            }
                            break;

                        case 0x83: // Additional security capabilities
                            // Look for AES support (indicator of SCP03)
                            if (length > 0)
                            {
                                var capabilities = data[offset + 2];
                                if ((capabilities & 0x01) != 0)
                                {
                                    result.Add("SCP02");
                                }

                                if ((capabilities & 0x02) != 0)
                                {
                                    result.Add("SCP03");
                                }
                            }
                            break;
                    }

                    offset += 2 + length;
                }

                // Remove duplicates and sort
                result = [.. result.Distinct().OrderBy(x => x)];

                return result.Count > 0 ? string.Join(", ", result) : string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Parses key information template data and adds key details to the table.
        /// Handles multiple keys and consolidates information by key ID.
        /// </summary>
        /// <param name="table">The table to add key information to.</param>
        /// <param name="data">The raw key information template data.</param>
        private void AddKeyInfoToTable(Table table, byte[] data)
        {
            try
            {
                if (data == null || data.Length < 3)
                {
                    _ = table.AddRow("Key Information", "[dim]Not available[/]");
                    return;
                }

                var keys = new List<(int keyId, int keyVer, string keyType, int keyLen)>();
                int offset = 0;

                while (offset < data.Length - 2)
                {
                    // Key Information Template format: C0 04 keyId keyVer keyType keyLen
                    if (data[offset] == 0xC0 && offset + 1 < data.Length)
                    {
                        var length = data[offset + 1];
                        if (offset + 2 + length <= data.Length && length >= 4)
                        {
                            var keyId = data[offset + 2];
                            var keyVer = data[offset + 3];
                            var keyType = data[offset + 4];
                            var keyLen = data[offset + 5];

                            var keyTypeStr = keyType switch
                            {
                                0x80 => "DES", 
                                0x81 => "3DES",
                                0x82 => "3DES",
                                0x83 => "AES",
                                0x88 => "AES", // AES key type from GP Pro trace  
                                0x90 => "HMAC-SHA1",
                                0x91 => "HMAC-SHA256",
                                _ => $"0x{keyType:X2}"
                            };

                            keys.Add((keyId, keyVer, keyTypeStr, keyLen));
                        }
                        offset += 2 + length;
                    }
                    else
                    {
                        offset++;
                    }
                }

                if (keys.Count > 0)
                {
                    // Show individual key information for each key
                    foreach (var key in keys.OrderBy(k => k.keyId))
                    {
                        var keyName = key.keyId switch
                        {
                            1 => "ENC Key",
                            2 => "MAC Key", 
                            3 => "DEK Key",
                            _ => $"Key {key.keyId}"
                        };

                        var keyInfo = $"v{key.keyVer} {key.keyType} ({key.keyLen * 8} bit)";
                        _ = table.AddRow(keyName, keyInfo);
                    }
                }
                else
                {
                    _ = table.AddRow("Key Information", "[dim]No keys found[/]");
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"Could not parse key information: {ex.Message}");
                _ = table.AddRow("Key Information", "[red]Error parsing keys[/]");
            }
        }

        /// <summary>
        /// Parses diversification data and returns it as a hex string.
        /// Used for key derivation in secure channel protocols.
        /// </summary>
        /// <param name="data">The raw diversification data.</param>
        /// <returns>Hex string representation of the data, or empty string if null/empty.</returns>
        private string ParseDiversificationData(byte[] data)
        {
            try
            {
                if (data == null || data.Length == 0)
                {
                    return string.Empty;
                }

                // Show full diversification data without truncation
                return Convert.ToHexString(data);
            }
            catch
            {
                // Safe fallback - data could be null here
                return data == null ? string.Empty : Convert.ToHexString(data);
            }
        }

        /// <summary>
        /// Parses SCP support information from diversification data (CF0A format).
        /// The CF tag contains the actual diversification data, which starts with length 0A (10 bytes).
        /// Format: 5 pairs of bytes (SCP version + i= parameter), 00 00 if not supported.
        /// </summary>
        /// <param name="data">The diversification data containing SCP support info.</param>
        /// <returns>Formatted SCP support string.</returns>
        private string ParseScpSupportFromDiversificationData(byte[] data)
        {
            try
            {
                if (data == null || data.Length < 12) // CF + 0A + 10 bytes
                {
                    return "[red]None[/]";
                }

                // Skip CF tag (1 byte) and length (1 byte) to get to actual content
                var contentStart = 2;
                var contentLength = data[1]; // Length byte after CF tag
                
                if (data.Length < contentStart + contentLength || contentLength < 10)
                {
                    return "[red]Parse error[/]";
                }

                var scpSupport = new List<string>();

                // Parse 5 pairs of bytes (SCP version + i= parameter) from the content
                for (int i = contentStart; i < contentStart + 10; i += 2)
                {
                    var scpVersion = data[i];
                    var iParameter = data[i + 1];

                    // Skip empty slots (00 00)
                    if (scpVersion == 0x00 && iParameter == 0x00)
                    {
                        continue;
                    }

                    scpSupport.Add($"SCP{scpVersion:X2} (i={iParameter:X2})");
                }

                return scpSupport.Count > 0 ? string.Join(", ", scpSupport) : "[red]None[/]";
            }
            catch
            {
                return "[red]Parse error[/]";
            }
        }

        /// <summary>
        /// Settings for the info command.
        /// </summary>
        public class Settings : CardCommandSettings { }
    }
}
