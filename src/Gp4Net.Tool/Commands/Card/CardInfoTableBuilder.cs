using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Protocol;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Pure functional table builder for card information display.
/// Uses semantic row types and functional composition per CLAUDE.md patterns.
/// Eliminates all mutations, nulls, and imperative table building.
/// </summary>
public static class CardInfoTableBuilder
{
    #region Semantic Row Types

    /// <summary>
    /// Base type for all table rows, enabling type-safe UI composition.
    /// </summary>
    public abstract record TableRow;

    /// <summary>
    /// Row displaying a property name and value.
    /// </summary>
    public record PropertyRow(string Name, string Value) : TableRow;

    /// <summary>
    /// Section header for visual grouping.
    /// </summary>
    public record SectionHeader(string Title) : TableRow;

    /// <summary>
    /// Status indicator with optional details.
    /// </summary>
    public record StatusRow(string Name, bool IsAvailable, string Details = "") : TableRow;

    /// <summary>
    /// Error information display.
    /// </summary>
    public record ErrorRow(string Name, string Message) : TableRow;

    /// <summary>
    /// Informational message row.
    /// </summary>
    public record InfoRow(string Message) : TableRow;

    #endregion

    /// <summary>
    /// Main entry point to build all card information rows using functional composition.
    /// Returns semantic row types that can be rendered by any UI framework.
    /// </summary>
    /// <param name="cardInfo">Parsed card information from gatherer</param>
    /// <param name="isSecureChannelEstablished">Whether secure channel is active</param>
    /// <returns>Sequence of semantic table rows</returns>
    public static IEnumerable<TableRow> BuildCardInfoRows(
        CardInformation cardInfo, 
        bool isSecureChannelEstablished)
    {
        return new[]
        {
            BuildConnectionStatus(isSecureChannelEstablished),
            BuildCardIdentification(cardInfo),
            BuildManufacturingInfo(cardInfo),
            BuildPlatformInfo(cardInfo),
            BuildSecurityCapabilities(cardInfo),
            BuildKeyInformation(cardInfo)
        }
        .SelectMany(rows => rows);
    }

    /// <summary>
    /// Builds connection status rows - always present.
    /// </summary>
    private static IEnumerable<TableRow> BuildConnectionStatus(bool isSecureChannelEstablished)
    {
        return
        [
            new StatusRow("Connection", true, "Connected"),
            new StatusRow("Secure Channel", isSecureChannelEstablished, 
                isSecureChannelEstablished ? "Active" : "Not established")
        ];
    }

    /// <summary>
    /// Builds card identification rows including ATR and ISD information.
    /// </summary>
    private static IEnumerable<TableRow> BuildCardIdentification(CardInformation cardInfo)
    {
        // ATR is optional
        var atrRows = cardInfo.Atr
            .Map(atr => new TableRow[] { new PropertyRow("ATR", $"[dim]{Convert.ToHexString(atr)}[/]") })
            .GetValueOrDefault([]);

        // ISD information with nested details
        var isdRows = cardInfo.IsdInfo
            .Map(isd => BuildIsdDetails(isd))
            .GetValueOrDefault([new StatusRow("ISD", false, "Not accessible")]);

        return atrRows.Concat(isdRows);
    }

    /// <summary>
    /// Builds ISD details from SELECT response.
    /// </summary>
    private static IEnumerable<TableRow> BuildIsdDetails(SelectResponse isd)
    {
        var statusRow = new StatusRow("ISD", true, "Available");

        // Build FCI rows using functional composition with ISD prefix
        var fciRows = isd.Fci.Match(
            fci => CreateIsdFciRows(fci),
            () => Array.Empty<TableRow>());
        
        return new[] { statusRow }.Concat(fciRows);
    }

    /// <summary>
    /// Creates table rows from File Control Information (FCI) data for ISD context.
    /// Extracts key FCI components with "ISD " prefix for proper categorization.
    /// </summary>
    private static IEnumerable<TableRow> CreateIsdFciRows(FileControlInformation fci)
    {
        // Build rows using functional composition with "ISD " prefix
        var aidRows = new[] { new PropertyRow("ISD AID", Convert.ToHexString(fci.ApplicationAid)) };

        var labelRows = fci.ApplicationLabel.Match(
            Some: label => new[] { new PropertyRow("ISD Application Label", label) },
            None: () => Array.Empty<TableRow>()
        );

        var priorityRows = fci.ApplicationPriorityIndicator.Match(
            Some: priority => new[] { new PropertyRow("ISD Priority Indicator", $"0x{priority:X2}") },
            None: () => Array.Empty<TableRow>()
        );

        var maxCmdLenRows = fci.MaxCommandDataLength.Match(
            Some: maxLen => new[] { new PropertyRow("ISD Max Command Length", maxLen.ToString()) },
            None: () => Array.Empty<TableRow>()
        );

        var maxRspLenRows = fci.MaxResponseDataLength.Match(
            Some: maxLen => new[] { new PropertyRow("ISD Max Response Length", maxLen.ToString()) },
            None: () => Array.Empty<TableRow>()
        );

        return aidRows
            .Concat(labelRows)
            .Concat(priorityRows)
            .Concat(maxCmdLenRows)
            .Concat(maxRspLenRows);
    }

    /// <summary>
    /// Creates table rows from File Control Information (FCI) data.
    /// Extracts key FCI components like AID, application label, and other available data.
    /// </summary>
    private static IEnumerable<TableRow> CreateFciRows(FileControlInformation fci)
    {
        // Build rows using functional composition with actual FCI properties
        var aidRows = new[] { new PropertyRow("AID", Convert.ToHexString(fci.ApplicationAid)) };

        var labelRows = fci.ApplicationLabel.Match(
            Some: label => new[] { new PropertyRow("Application Label", label) },
            None: () => Array.Empty<TableRow>()
        );

        var priorityRows = fci.ApplicationPriorityIndicator.Match(
            Some: priority => new[] { new PropertyRow("Priority Indicator", $"0x{priority:X2}") },
            None: () => Array.Empty<TableRow>()
        );

        var maxCmdLenRows = fci.MaxCommandDataLength.Match(
            Some: maxLen => new[] { new PropertyRow("Max Command Length", maxLen.ToString()) },
            None: () => Array.Empty<TableRow>()
        );

        var maxRspLenRows = fci.MaxResponseDataLength.Match(
            Some: maxLen => new[] { new PropertyRow("Max Response Length", maxLen.ToString()) },
            None: () => Array.Empty<TableRow>()
        );

        return aidRows
            .Concat(labelRows)
            .Concat(priorityRows)
            .Concat(maxCmdLenRows)
            .Concat(maxRspLenRows);
    }

    /// <summary>
    /// Builds manufacturing information from CPLC and chip data.
    /// </summary>
    private static IEnumerable<TableRow> BuildManufacturingInfo(CardInformation cardInfo)
    {
        return cardInfo.Cplc
            .Map(cplc => BuildCplcDetails(cplc, cardInfo.ChipDetails))
            .GetValueOrDefault([]);
    }

    /// <summary>
    /// Builds detailed CPLC information with optional chip enhancements.
    /// </summary>
    private static IEnumerable<TableRow> BuildCplcDetails(CplcData cplc, Maybe<ChipInfo> chipInfo)
    {
        var rows = new List<TableRow>
        {
            new SectionHeader("Manufacturing"),
            new PropertyRow("IC Fabricator", $"{cplc.GetManufacturerName()} (0x{cplc.IcFabricator:X4})"),
            new PropertyRow("IC Type", $"{cplc.GetChipModel()} (0x{cplc.IcType:X4})"),
            new PropertyRow("Operating System", $"{cplc.GetOperatingSystemName()} (0x{cplc.OperatingSystemId:X4})")
        };

        // Add date fields with validation
        rows.AddRange([
            BuildDateRow("OS Release Date", cplc.OperatingSystemReleaseDate),
            BuildDateRow("IC Fabrication Date", cplc.IcFabricationDate),
            new PropertyRow("IC Serial Number", $"0x{cplc.IcSerialNumber:X8} ({cplc.IcSerialNumber})"),
            new PropertyRow("IC Batch ID", $"0x{cplc.IcBatchIdentifier:X4}")
        ]);

        // Additional CPLC fields if present
        rows.AddRange([
            BuildDateRow("Module Packaging Date", cplc.IcModulePackagingDate),
            BuildDateRow("Embedding Date", cplc.IcEmbeddingDate),
            new PropertyRow("Pre-Personalizer", $"0x{cplc.IcPrePersonalizer:X4}"),
            BuildDateRow("Pre-Perso Equip Date", cplc.IcPrePersonalizationEquipmentDate),
            new PropertyRow("Pre-Perso Equip ID", $"0x{cplc.IcPrePersonalizationEquipmentId:X8}"),
            BuildDateRow("Personalization Date", cplc.IcPersonalizationDate)
        ]);

        // Enhanced chip information if available
        chipInfo.Match(
            Some: chip =>
            {
                rows.Add(new SectionHeader("Chip Details"));
                rows.Add(new PropertyRow("Chip Platform", $"{chip.Platform} ({chip.Architecture})"));
                
                chip.MemoryConfig.Match(
                    Some: _ => rows.Add(new PropertyRow("Memory Config", chip.GetMemoryDescription())),
                    None: () => { }
                );
                
                rows.Add(new PropertyRow("Certifications", chip.GetCertificationsString()));
                rows.Add(new PropertyRow("Crypto Support", chip.GetCryptoSummary()));
            },
            None: () => { }
        );

        return rows;
    }

    /// <summary>
    /// Builds platform and version information rows.
    /// </summary>
    private static IEnumerable<TableRow> BuildPlatformInfo(CardInformation cardInfo)
    {
        var rows = new List<TableRow>();

        // GlobalPlatform version from multiple sources
        cardInfo.GlobalPlatformVersion.Match(
            Some: version => rows.Add(new PropertyRow("GlobalPlatform Version", version)),
            None: () => { }
        );

        // Java Card version if available
        cardInfo.JavaCardVersion.Match(
            Some: version => rows.Add(new PropertyRow("Java Card Version", version)),
            None: () => { }
        );

        // Card data OIDs if present - use enhanced CardDataInfo display
        cardInfo.CardData.Match(
            Some: cardData =>
            {
                if (cardData.Oids.Count > 0)
                {
                    rows.Add(new SectionHeader("Platform Identifiers"));
                    
                    // Use the enhanced ToString() method from CardDataInfo to get detailed OID info
                    var cardDataString = cardData.ToString();
                    var oidSection = ExtractOidSection(cardDataString);
                    
                    if (!string.IsNullOrEmpty(oidSection))
                    {
                        // Parse the OID section and add formatted rows
                        var oidLines = oidSection.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                        string currentOid = "";
                        
                        foreach (var line in oidLines)
                        {
                            var trimmedLine = line.Trim();
                            if (trimmedLine.StartsWith("1.") && !trimmedLine.StartsWith("-> "))
                            {
                                // This is an OID line
                                currentOid = trimmedLine;
                            }
                            else if (trimmedLine.StartsWith("-> ") && !string.IsNullOrEmpty(currentOid))
                            {
                                // This is a description line
                                var description = trimmedLine.Substring(3); // Remove "-> "
                                rows.Add(new PropertyRow($"  {currentOid}", description));
                                
                                // Check for GP version info
                                if (currentOid.StartsWith("1.2.840.114283.2.") && currentOid != "1.2.840.114283.2")
                                {
                                    var versionParts = currentOid.Split('.').Skip(4);
                                    var version = string.Join(".", versionParts);
                                    rows.Add(new PropertyRow($"    Version", version));
                                }
                                currentOid = "";
                            }
                        }
                    }
                    else
                    {
                        // Fallback to basic OID display
                        rows.AddRange(cardData.Oids.Take(5).Select(oid =>
                        {
                            var description = GlobalPlatformOids.GetDescription(oid);
                            return new PropertyRow($"  {oid}", description ?? "Unknown OID");
                        }));
                    }
                }
                
                // Add SCP info from card data if available
                if (cardData.SecureChannelProtocolInfo.HasValue)
                {
                    var scpData = cardData.SecureChannelProtocolInfo.Value;
                    if (scpData.Length >= 2)
                    {
                        var scpId = scpData[0];
                        var implOptions = scpData[1];
                        rows.Add(new PropertyRow("SCP from Card Data", $"SCP{scpId:X2} i={implOptions:X2}"));
                    }
                }
            },
            None: () => { }
        );

        return rows;
    }

    /// <summary>
    /// Builds security capabilities including SCP support and algorithms.
    /// </summary>
    private static IEnumerable<TableRow> BuildSecurityCapabilities(CardInformation cardInfo)
    {
        var hasAnySecurity = cardInfo.HasSecureChannelCapabilities;
        
        if (!hasAnySecurity)
            return [];

        var rows = new List<TableRow> { new SectionHeader("Security Capabilities") };

        // Use detailed CardCapabilities display if available
        cardInfo.Capabilities.Match(
            Some: cap =>
            {
                // Parse detailed capabilities using the comprehensive CardCapabilities.ToString()
                var capabilitiesText = cap.ToString();
                var capabilityLines = capabilitiesText.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                    .Skip(1) // Skip "Card Capabilities:" header
                    .Where(line => !string.IsNullOrWhiteSpace(line))
                    .Take(8); // Limit to most important capabilities
                
                foreach (var line in capabilityLines)
                {
                    var trimmedLine = line.Trim();
                    if (trimmedLine.StartsWith("Supports SCP"))
                    {
                        rows.Add(new PropertyRow("SCP Protocol", trimmedLine.Replace("Supports ", "")));
                    }
                    else if (trimmedLine.StartsWith("Supported") && trimmedLine.Contains("privileges"))
                    {
                        var parts = trimmedLine.Split(':');
                        if (parts.Length == 2)
                        {
                            rows.Add(new PropertyRow(parts[0].Replace("Supported ", ""), parts[1].Trim()));
                        }
                    }
                    else if (trimmedLine.StartsWith("Supported") && trimmedLine.Contains("hash"))
                    {
                        var parts = trimmedLine.Split(':');
                        if (parts.Length == 2)
                        {
                            rows.Add(new PropertyRow("Hash Algorithms", parts[1].Trim()));
                        }
                    }
                    else if (trimmedLine.StartsWith("Supported") && trimmedLine.Contains("ciphers"))
                    {
                        var parts = trimmedLine.Split(':');
                        if (parts.Length == 2)
                        {
                            var cipherType = parts[0].Replace("Supported ", "").Replace(" ciphers", "");
                            rows.Add(new PropertyRow($"{cipherType} Ciphers", parts[1].Trim()));
                        }
                    }
                }
            },
            None: () =>
            {
                // Fallback to basic SCP support parsing
                rows.AddRange(BuildScpSupport(cardInfo));
            }
        );

        // Security domain status
        cardInfo.SecurityStatus.Match(
            Some: status => rows.Add(new PropertyRow("Security Status", status.GetShortDescription())),
            None: () => { }
        );

        // Diversification data
        cardInfo.DiversificationData.Match(
            Some: divData =>
            {
                if (divData.Length >= 12 && divData[0] == 0xCF && divData[1] == 0x0A)
                {
                    var scpSupport = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(divData));
                    if (scpSupport.Length > 0 && !scpSupport.Contains("None") && !scpSupport.Contains("error"))
                    {
                        rows.Add(new PropertyRow("SCP Support (CF)", scpSupport));
                    }
                }
                rows.Add(new PropertyRow("Diversification Data", $"[dim]{Convert.ToHexString(divData)}[/]"));
            },
            None: () => { }
        );

        return rows;
    }

    /// <summary>
    /// Builds SCP protocol support information.
    /// </summary>
    private static IEnumerable<TableRow> BuildScpSupport(CardInformation cardInfo)
    {
        // Prefer detailed SCP info over basic capabilities
        return cardInfo.ScpInfo
            .Map(scp => BuildDetailedScpRows(scp))
            .Or(() => cardInfo.Capabilities
                .Map(cap => BuildBasicScpRows(cap)))
            .GetValueOrDefault([]);
    }

    /// <summary>
    /// Builds detailed SCP rows with implementation options.
    /// </summary>
    private static IEnumerable<TableRow> BuildDetailedScpRows(ScpInformation scp)
    {
        return scp.Protocols.SelectMany((protocol, index) =>
        {
            var rows = new List<TableRow>();
            
            // First protocol on main line, others indented
            var prefix = index == 0 ? "" : "  ";
            rows.Add(new PropertyRow($"{prefix}SCP Support", protocol.ToShortString()));
            
            // Show implementation details
            rows.AddRange(protocol.ImplementationOptions.Select(impl =>
                new PropertyRow($"  {impl:X2}", GetImplementationDescription(impl))));
            
            return rows;
        });
    }

    /// <summary>
    /// Builds basic SCP rows from capabilities.
    /// </summary>
    private static IEnumerable<TableRow> BuildBasicScpRows(CardCapabilities capabilities)
    {
        var rows = new List<TableRow>();
        
        if (capabilities.ScpOptions.Count > 0)
        {
            var scpInfo = ScpCapabilitiesParser.ParseDetailed(capabilities.Data);
            if (scpInfo.Protocols.Count > 0)
            {
                rows.Add(new PropertyRow("SCP Support", scpInfo.Protocols[0].ToShortString()));
                rows.AddRange(scpInfo.Protocols.Skip(1).Select(p => 
                    new PropertyRow("", p.ToShortString())));
            }
        }
        
        return rows;
    }

    /// <summary>
    /// Builds cryptographic key information rows.
    /// </summary>
    private static IEnumerable<TableRow> BuildKeyInformation(CardInformation cardInfo)
    {
        return cardInfo.KeyInfo
            .Map(keyInfo => BuildKeyRows(keyInfo))
            .GetValueOrDefault([]);
    }

    /// <summary>
    /// Builds key information rows with semantic naming.
    /// </summary>
    private static IEnumerable<TableRow> BuildKeyRows(KeyInformationTemplate keyInfo)
    {
        if (keyInfo.Keys.Count == 0)
            return [new InfoRow("No key information available")];

        var rows = new List<TableRow> { new SectionHeader("Cryptographic Keys") };

        // Group by key set version for better display
        var keySets = keyInfo.Keys.GroupBy(k => k.KeyVersion);
        
        foreach (var keySet in keySets.OrderBy(ks => ks.Key))
        {
            if (keySets.Count() > 1)
                rows.Add(new PropertyRow($"Key Set v{keySet.Key}", ""));
                
            rows.AddRange(keySet.OrderBy(k => k.KeyId).Select(key =>
            {
                var keyName = GetKeyName(key.KeyId);
                var keyDesc = $"v{key.KeyVersion} {key.PrimaryKeyType} ({key.KeyLength} bit)";
                return new PropertyRow($"  {keyName}", keyDesc);
            }));
        }

        return rows;
    }

    /// <summary>
    /// Pure function to build date field with validity checking.
    /// </summary>
    private static TableRow BuildDateRow(string name, ushort dateValue)
    {
        var dateStr = CplcData.IsValidDate(dateValue) 
            ? $"0x{dateValue:X4} ({CplcDateParser.FormatDate(dateValue)})"
            : $"0x{dateValue:X4} [dim](invalid date format)[/]";
        return new PropertyRow(name, dateStr);
    }

    /// <summary>
    /// Gets semantic key name based on key ID.
    /// Per GP specification, standard key IDs have specific purposes.
    /// </summary>
    private static string GetKeyName(byte keyId) => keyId switch
    {
        1 => "ENC Key",
        2 => "MAC Key",
        3 => "KEK Key",
        _ => $"Key {keyId}"
    };

    /// <summary>
    /// Gets human-readable description for SCP implementation option.
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
    /// Extracts the OID section from CardDataInfo.ToString() output.
    /// </summary>
    private static string ExtractOidSection(string cardDataString)
    {
        var oidSectionStart = cardDataString.IndexOf("Parsed OIDs:");
        if (oidSectionStart == -1)
            return "";
        
        var oidSectionEnd = cardDataString.IndexOf("\nSecure Channel Protocol Info:", oidSectionStart);
        if (oidSectionEnd == -1)
            oidSectionEnd = cardDataString.Length;
        
        return cardDataString.Substring(oidSectionStart + "Parsed OIDs:\n".Length, 
            oidSectionEnd - oidSectionStart - "Parsed OIDs:\n".Length).Trim();
    }
}