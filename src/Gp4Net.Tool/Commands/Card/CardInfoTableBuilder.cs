using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Tool.Common;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Pure functional table builder for card information display.
/// Uses semantic row types and functional composition per project architecture guidelines.
/// Eliminates all mutations, nulls, and imperative table building.
/// </summary>
public static class CardInfoTableBuilder
{
    /// <summary>
    /// Base type for all card info rows, inheriting from semantic row system.
    /// </summary>
    public abstract record CardInfoRow : SemanticTableBuilder.SemanticRow;

    /// <summary>
    /// Row displaying a property name and value.
    /// </summary>
    public record PropertyRow(string Name, string Value) : CardInfoRow;

    /// <summary>
    /// Section header for visual grouping.
    /// </summary>
    public record SectionHeader(string Title) : CardInfoRow;

    /// <summary>
    /// Status indicator with optional details.
    /// </summary>
    public record StatusRow(string Name, bool IsAvailable, string Details = "") : CardInfoRow;

    /// <summary>
    /// Error information display.
    /// </summary>
    public record ErrorRow(string Name, string Message) : CardInfoRow;

    /// <summary>
    /// Informational message row.
    /// </summary>
    public record InfoRow(string Message) : CardInfoRow;

    /// <summary>
    /// Four-column row for detailed tag display (Tag, Tag Description, Value, Value Description).
    /// Used for Platform Identifiers section per GP specification.
    /// </summary>
    public record FourColumnRow(
        string Tag,
        string TagDescription,
        string Value,
        string ValueDescription
    ) : CardInfoRow;

    /// <summary>
    /// Main entry point to build all card information rows using functional composition.
    /// Returns semantic row types that can be rendered by any UI framework.
    /// </summary>
    /// <param name="cardInfo">Parsed card information from gatherer</param>
    /// <param name="isSecureChannelEstablished">Whether secure channel is active</param>
    /// <returns>Sequence of semantic table rows</returns>
    public static IEnumerable<CardInfoRow> BuildCardInfoRows(
        CardInformation cardInfo,
        bool isSecureChannelEstablished
    )
    {
        return new[]
        {
            BuildConnectionStatus(isSecureChannelEstablished),
            BuildCardIdentification(cardInfo),
            BuildManufacturingInfo(cardInfo),
            BuildPlatformInfo(cardInfo),
            BuildSecurityCapabilities(cardInfo),
            BuildKeyInformation(cardInfo),
        }.SelectMany(rows => rows);
    }

    /// <summary>
    /// Builds connection status rows - always present.
    /// </summary>
    private static IEnumerable<CardInfoRow> BuildConnectionStatus(bool isSecureChannelEstablished)
    {
        return
        [
            new StatusRow("Connection", true, "Connected"),
            new StatusRow(
                "Secure Channel",
                isSecureChannelEstablished,
                isSecureChannelEstablished ? "Active" : "Not established"
            ),
        ];
    }

    /// <summary>
    /// Builds card identification rows including ATR and ISD information.
    /// </summary>
    private static IEnumerable<CardInfoRow> BuildCardIdentification(CardInformation cardInfo)
    {
        // ATR is optional
        var atrRows = cardInfo
            .Atr.Map(atr =>
                new CardInfoRow[] { new PropertyRow("ATR", $"[dim]{Convert.ToHexString(atr)}[/]") }
            )
            .GetValueOrDefault([]);

        // ISD information with nested details
        var isdRows = cardInfo.IsdInfo.Map(isd => BuildIsdDetails(isd)).GetValueOrDefault([]);

        return atrRows.Concat(isdRows);
    }

    /// <summary>
    /// Builds ISD details from SELECT response.
    /// </summary>
    private static IEnumerable<CardInfoRow> BuildIsdDetails(SelectResponse isd)
    {
        // Build FCI rows using functional composition without redundant status
        return isd.Fci.Match(fci => CreateIsdFciRows(fci), () => []);
    }

    /// <summary>
    /// Creates table rows from File Control Information (FCI) data for ISD context.
    /// Extracts key FCI components with "ISD " prefix for proper categorization.
    /// </summary>
    private static IEnumerable<CardInfoRow> CreateIsdFciRows(FileControlInformation fci)
    {
        // Build rows using functional composition with "ISD " prefix
        CardInfoRow[] statusRows = [new StatusRow("ISD", true, "Available")];

        PropertyRow[] aidRows =
        [
            new PropertyRow("ISD AID", Convert.ToHexString(fci.ApplicationAid)),
        ];

        var labelRows = fci.ApplicationLabel.Match(
            Some: label => [new PropertyRow("ISD Application Label", label)],
            None: () => Array.Empty<CardInfoRow>()
        );

        var priorityRows = fci.ApplicationPriorityIndicator.Match(
            Some: priority => [new PropertyRow("ISD Priority Indicator", $"0x{priority:X2}")],
            None: () => Array.Empty<CardInfoRow>()
        );

        var maxCmdLenRows = fci.MaxCommandDataLength.Match(
            Some: maxLen => [new PropertyRow("ISD Max Command Length", maxLen.ToString())],
            None: () => Array.Empty<CardInfoRow>()
        );

        var maxRspLenRows = fci.MaxResponseDataLength.Match(
            Some: maxLen => [new PropertyRow("ISD Max Response Length", maxLen.ToString())],
            None: () => Array.Empty<CardInfoRow>()
        );

        return statusRows
            .Concat(aidRows)
            .Concat(labelRows)
            .Concat(priorityRows)
            .Concat(maxCmdLenRows)
            .Concat(maxRspLenRows);
    }

    /// <summary>
    /// Creates table rows from File Control Information (FCI) data.
    /// Extracts key FCI components like AID, application label, and other available data.
    /// </summary>
    private static IEnumerable<CardInfoRow> CreateFciRows(FileControlInformation fci)
    {
        // Build rows using functional composition with actual FCI properties
        PropertyRow[] aidRows = [new PropertyRow("AID", Convert.ToHexString(fci.ApplicationAid))];

        var labelRows = fci.ApplicationLabel.Match(
            Some: label => [new PropertyRow("Application Label", label)],
            None: () => Array.Empty<CardInfoRow>()
        );

        var priorityRows = fci.ApplicationPriorityIndicator.Match(
            Some: priority => [new PropertyRow("Priority Indicator", $"0x{priority:X2}")],
            None: () => Array.Empty<CardInfoRow>()
        );

        var maxCmdLenRows = fci.MaxCommandDataLength.Match(
            Some: maxLen => [new PropertyRow("Max Command Length", maxLen.ToString())],
            None: () => Array.Empty<CardInfoRow>()
        );

        var maxRspLenRows = fci.MaxResponseDataLength.Match(
            Some: maxLen => [new PropertyRow("Max Response Length", maxLen.ToString())],
            None: () => Array.Empty<CardInfoRow>()
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
    private static IEnumerable<CardInfoRow> BuildManufacturingInfo(CardInformation cardInfo)
    {
        return cardInfo
            .Cplc.Map(cplc => BuildCplcDetails(cplc, cardInfo.ChipDetails))
            .GetValueOrDefault([]);
    }

    /// <summary>
    /// Builds detailed CPLC information with optional chip enhancements.
    /// </summary>
    private static IEnumerable<CardInfoRow> BuildCplcDetails(
        CplcData cplc,
        Maybe<ChipInfo> chipInfo
    )
    {
        List<CardInfoRow> rows =
        [
            new SectionHeader("Manufacturing"),
            new PropertyRow(
                "IC Fabricator",
                $"{cplc.GetManufacturerName()} (0x{cplc.IcFabricator:X4})"
            ),
            new PropertyRow("IC Type", $"{cplc.GetChipModel()} (0x{cplc.IcType:X4})"),
            new PropertyRow(
                "Operating System",
                $"{cplc.GetOperatingSystemName()} (0x{cplc.OperatingSystemId:X4})"
            ),
        ];

        // Add date fields with validation
        rows.AddRange(
            [
                BuildDateRow("OS Release Date", cplc.OperatingSystemReleaseDate),
                BuildDateRow("IC Fabrication Date", cplc.IcFabricationDate),
                new PropertyRow(
                    "IC Serial Number",
                    $"0x{cplc.IcSerialNumber:X8} ({cplc.IcSerialNumber})"
                ),
                new PropertyRow("IC Batch ID", $"0x{cplc.IcBatchIdentifier:X4}"),
            ]
        );

        // Additional CPLC fields if present
        rows.AddRange(
            [
                BuildDateRow("Module Packaging Date", cplc.IcModulePackagingDate),
                BuildDateRow("Embedding Date", cplc.IcEmbeddingDate),
                new PropertyRow("Pre-Personalizer", $"0x{cplc.IcPrePersonalizer:X4}"),
                BuildDateRow("Pre-Perso Equip Date", cplc.IcPrePersonalizationEquipmentDate),
                new PropertyRow(
                    "Pre-Perso Equip ID",
                    $"0x{cplc.IcPrePersonalizationEquipmentId:X8}"
                ),
                BuildDateRow("Personalization Date", cplc.IcPersonalizationDate),
            ]
        );

        // Enhanced chip information if available
        chipInfo.Match(
            Some: chip =>
            {
                rows.Add(new SectionHeader("Chip Details"));
                rows.Add(
                    new PropertyRow("Chip Platform", $"{chip.Platform} ({chip.Architecture})")
                );

                chip.MemoryConfig.Match(
                    Some: _ =>
                        rows.Add(new PropertyRow("Memory Config", chip.GetMemoryDescription())),
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
    /// Builds platform and version information rows with 4-column display format.
    /// Shows Tag, Tag Description, Value, and Value Description per GP spec.
    /// </summary>
    private static IEnumerable<CardInfoRow> BuildPlatformInfo(CardInformation cardInfo)
    {
        // Build rows functionally using immutable concatenation
        var headerRow = new[] { new SectionHeader("Platform Identifiers") };

        // Build tag-based rows from structured Card Recognition Data
        var tagRows = cardInfo
            .CardData.Bind(d => d.CardRecognitionData)
            .Match(
                Some: recognitionData =>
                {
                    // Start with tag 73 header
                    var tag73Header = new[]
                    {
                        new FourColumnRow("[cyan]73[/]", "Card Recognition Data", "", "")
                            as CardInfoRow,
                    };

                    // Direct Card Recognition OID if present
                    var directOidRows = recognitionData
                        .CardRecognitionOid.Map(oid =>
                        {
                            var info = GetOidInfo(oid);
                            return new[]
                            {
                                new FourColumnRow(
                                    "  [cyan]06[/]",
                                    "OID",
                                    $"[yellow]{oid}[/]",
                                    info.Meaning
                                ) as CardInfoRow,
                            };
                        })
                        .GetValueOrDefault([]);

                    // Process each application tag with proper nesting
                    var appTagRows = recognitionData.ApplicationTags.SelectMany(appTag =>
                    {
                        var tagHex = $"  [cyan]{appTag.TagHex}[/]";
                        var tagDesc = appTag.TagName;

                        // Application tag header
                        var tagHeader = new[]
                        {
                            new FourColumnRow(tagHex, tagDesc, "", "") as CardInfoRow,
                        };

                        // Nested OID if present
                        var oidRow = appTag
                            .NestedOid.Map(oid =>
                            {
                                var info = GetOidInfo(oid);
                                return new[]
                                {
                                    new FourColumnRow(
                                        "    [cyan]06[/]",
                                        "OID",
                                        $"[yellow]{oid}[/]",
                                        info.Meaning
                                    ) as CardInfoRow,
                                };
                            })
                            .GetValueOrDefault([]);

                        return tagHeader.Concat(oidRow);
                    });

                    // JavaCard OIDs are already displayed as part of the structured tag data,
                    // so no need to add them again from the main OID list to avoid duplicates

                    return tag73Header.Concat(directOidRows).Concat(appTagRows).ToArray();
                },
                None: () =>
                {
                    // Fallback to basic OID display if no structured data available
                    return cardInfo.CardData.Match(
                        Some: cardData =>
                        {
                            if (!cardData.Oids.Any())
                                return [];

                            return cardData
                                .Oids.Select(oid =>
                                {
                                    var info = GetOidInfo(oid);
                                    return new FourColumnRow(
                                            "[cyan]06[/]",
                                            "OID",
                                            $"[yellow]{oid}[/]",
                                            info.Meaning
                                        ) as CardInfoRow;
                                })
                                .ToArray();
                        },
                        None: () => []
                    );
                }
            );

        return headerRow.Concat(tagRows);
    }

    /// <summary>
    /// Builds security capabilities including SCP support and cipher suites.
    /// </summary>
    private static IEnumerable<CardInfoRow> BuildSecurityCapabilities(CardInformation cardInfo)
    {
        bool hasAnySecurity =
            cardInfo.HasSecureChannelCapabilities || cardInfo.Capabilities.HasValue;

        if (!hasAnySecurity)
            return [];

        var headerRow = new[] { new SectionHeader("Security Capabilities") };

        // Build capabilities rows directly from CardCapabilities properties
        var capabilityRows = cardInfo.Capabilities.Match(
            Some: cap =>
            {
                // Build all capability rows using LINQ
                var scpRows = cap
                    .ScpOptions.GroupBy(o => o.ScpId)
                    .Select(group =>
                    {
                        var options = string.Join(
                            " ",
                            group.Select(o => $"i={o.Implementation:X2}")
                        );
                        var keyLengths =
                            cap.SupportedKeyLengths.TryGetValue(group.Key, out var lengths)
                            && lengths.Any()
                                ? $" (AES-{string.Join("/", lengths)})"
                                : "";
                        return new PropertyRow(
                            "SCP Protocol",
                            $"SCP{group.Key:X2} {options}{keyLengths}"
                        );
                    });

                var privilegeRows = cap
                    .AppPrivileges.Map(p =>
                        new[]
                        {
                            new PropertyRow(
                                "APP Privileges",
                                Gp4Net.Services.Helpers.PrivilegeHelpers.ToHumanReadableString(p)
                            ),
                        }
                    )
                    .GetValueOrDefault([]);

                // Show LFDB hash from CipherSuites first, then from Algorithms as fallback
                var lfdbHashRows =
                    cap.CipherSuites.TryGetValue(CipherUsage.LfdbEncryption, out var lfdbCiphers)
                    && lfdbCiphers.Any()
                        ?
                        [
                            new PropertyRow(
                                "Supported LFDB hash",
                                string.Join(", ", lfdbCiphers.Select(c => c.ToFriendlyString()))
                            )
                        ]
                        : cap
                            .Algorithms.Map(a =>
                                new[]
                                {
                                    new PropertyRow("Supported LFDB hash", a.GetHashAlgorithms()),
                                }
                            )
                            .GetValueOrDefault([]);

                // Show other cipher suites (excluding LFDB hash to avoid duplication)
                var cipherRows = cap
                    .CipherSuites.Where(kvp =>
                        kvp.Key != CipherUsage.LfdbEncryption && kvp.Value.Any()
                    )
                    .Select(kvp => new PropertyRow(
                        $"Supported {GetCipherUsageDisplayName(kvp.Key)} ciphers",
                        string.Join(", ", kvp.Value.Select(c => c.ToFriendlyString()))
                    ));

                return scpRows
                    .Concat(privilegeRows)
                    .Concat(lfdbHashRows)
                    .Concat(cipherRows)
                    .ToArray();
            },
            None: () => Array.Empty<CardInfoRow>()
        );

        // Sequence counter from security status
        var statusRows = cardInfo
            .SecurityStatus.Map(status =>
                status
                    .GetSequenceCounter()
                    .Map(counter =>
                        new CardInfoRow[] { new PropertyRow("Sequence Counter", $"0x{counter:X4}") }
                    )
                    .GetValueOrDefault([])
            )
            .GetValueOrDefault([]);

        // Diversification data - structured display
        var divRows = cardInfo
            .DiversificationData.Map(divData => BuildDiversificationDataRows(divData))
            .GetValueOrDefault([]);

        return headerRow.Concat(capabilityRows).Concat(statusRows).Concat(divRows);
    }

    /// <summary>
    /// Builds SCP protocol support information.
    /// </summary>
    private static IEnumerable<CardInfoRow> BuildScpSupport(CardInformation cardInfo)
    {
        // Prefer detailed SCP info over basic capabilities
        return cardInfo
            .ScpInfo.Map(scp => BuildDetailedScpRows(scp))
            .Or(() => cardInfo.Capabilities.Map(cap => BuildBasicScpRows(cap)))
            .GetValueOrDefault([]);
    }

    /// <summary>
    /// Builds detailed SCP rows with implementation options.
    /// </summary>
    private static IEnumerable<CardInfoRow> BuildDetailedScpRows(ScpInformation scp)
    {
        return scp.Protocols.SelectMany(
            (protocol, index) =>
            {
                // First protocol on main line, others indented
                string prefix = index == 0 ? "" : "  ";
                var header = new PropertyRow($"{prefix}SCP Support", protocol.ToShortString());

                // Show implementation details
                var details = protocol.ImplementationOptions.Select(impl => new PropertyRow(
                    $"  {impl:X2}",
                    GetImplementationDescription(protocol.Version, impl)
                ));

                return new[] { header }.Concat(details);
            }
        );
    }

    /// <summary>
    /// Builds basic SCP rows from capabilities.
    /// </summary>
    private static IEnumerable<CardInfoRow> BuildBasicScpRows(CardCapabilities capabilities)
    {
        if (capabilities.ScpOptions.Count == 0)
        {
            return [];
        }

        // Parse SCP capabilities directly from the ScpOptions list
        var protocols = capabilities
            .ScpOptions.GroupBy(opt => opt.ScpId)
            .Select(group => new ScpProtocolInfo(
                group.Key,
                group.Select(opt => (ScpImplementation)opt.Implementation).ToList()
            ))
            .OrderBy(p => p.Version)
            .ToList();

        if (protocols.Count == 0)
        {
            return [];
        }

        // Build rows functionally
        var firstRow = new PropertyRow("SCP Support", protocols[0].ToShortString());
        var additionalRows = protocols.Skip(1).Select(p => new PropertyRow("", p.ToShortString()));

        return new[] { firstRow }.Concat(additionalRows);
    }

    /// <summary>
    /// Builds cryptographic key information rows.
    /// </summary>
    private static IEnumerable<CardInfoRow> BuildKeyInformation(CardInformation cardInfo)
    {
        return cardInfo.KeyInfo.Map(keyInfo => BuildKeyRows(keyInfo)).GetValueOrDefault([]);
    }

    /// <summary>
    /// Builds key information rows with semantic naming.
    /// </summary>
    private static IEnumerable<CardInfoRow> BuildKeyRows(KeyInformationTemplate keyInfo)
    {
        if (keyInfo.Keys.Count == 0)
            return [new InfoRow("No key information available")];

        List<CardInfoRow> rows = [new SectionHeader("Cryptographic Keys")];

        // Group by key set version for better display
        var keySets = keyInfo.Keys.GroupBy(k => k.KeyVersion);

        foreach (var keySet in keySets.OrderBy(ks => ks.Key))
        {
            if (keySets.Count() > 1)
                rows.Add(new PropertyRow($"Key Set v{keySet.Key}", ""));

            rows.AddRange(
                keySet
                    .OrderBy(k => k.KeyId)
                    .Select(key =>
                    {
                        string keyName = GetKeyName(key.KeyId);
                        string keyDesc =
                            $"v{key.KeyVersion} {key.PrimaryKeyType} ({key.KeyLength} bit)";
                        return new PropertyRow($"  {keyName}", keyDesc);
                    })
            );
        }

        return rows;
    }

    /// <summary>
    /// Pure function to build date field with validity checking.
    /// </summary>
    private static CardInfoRow BuildDateRow(string name, ushort dateValue)
    {
        string dateStr = CplcData.IsValidDate(dateValue)
            ? $"0x{dateValue:X4} ({CplcDateParser.FormatDate(dateValue)})"
            : $"0x{dateValue:X4} [dim](invalid date format)[/]";
        return new PropertyRow(name, dateStr);
    }

    /// <summary>
    /// Gets semantic key name based on key ID.
    /// Per GP specification, standard key IDs have specific purposes.
    /// </summary>
    private static string GetKeyName(byte keyId) =>
        keyId switch
        {
            1 => "ENC Key",
            2 => "MAC Key",
            3 => "KEK Key",
            _ => $"Key {keyId}",
        };

    /// <summary>
    /// Gets human-readable description for SCP implementation option.
    /// </summary>
    private static string GetImplementationDescription(
        byte scpVersion,
        ScpImplementation implementation
    )
    {
        if (scpVersion == 0x02)
            return implementation.GetDescription();
        return scpVersion == 0x03
            ? implementation.GetScp03Description()
            : $"Implementation 0x{(byte)implementation:X2}";
    }

    /// <summary>
    /// Gets cipher usage display name for UI.
    /// </summary>
    private static string GetCipherUsageDisplayName(CipherUsage usage) =>
        usage switch
        {
            CipherUsage.LfdbEncryption => "LFDB Encryption",
            CipherUsage.TokenVerification => "Token Verification",
            CipherUsage.ReceiptGeneration => "Receipt Generation",
            CipherUsage.DapVerification => "DAP Verification",
            _ => usage.ToString(),
        };

    /// <summary>
    /// Builds diversification data rows with structured TLV display.
    /// </summary>
    private static IEnumerable<CardInfoRow> BuildDiversificationDataRows(byte[] divData)
    {
        if (divData.Length >= 2 && divData[0] == 0xCF)
        {
            var tag = divData[0];
            var length = divData[1];
            var data = divData.Length > 2 ? divData.Skip(2).ToArray() : [];

            return
            [
                new PropertyRow("Key Diversification Data", ""),
                new PropertyRow("  Tag", $"[cyan]{tag:X2}[/] (EMV Key Diversification)"),
                new PropertyRow("  Length", $"{length:X2} ({length} bytes)"),
                new PropertyRow("  Data", $"[dim]{Convert.ToHexString(data)}[/]")
            ];
        }

        return [new PropertyRow("Diversification Data", $"[dim]{Convert.ToHexString(divData)}[/]")];
    }

    /// <summary>
    /// Gets OID display information with proper tag description and meaning.
    /// </summary>
    private static (string TagDescription, string Meaning) GetOidInfo(string oid)
    {
        return oid switch
        {
            "1.2.840.114283.1"
                => (
                    "Card Recognition Data",
                    "GlobalPlatform card, also identifies GP as Tag Allocation Authority"
                ),
            "1.2.840.114283.2.2.3"
                => ("Card Management Type and Version", "Card Management v2.2.3"),
            "1.2.840.114283.3"
                => ("Card Identification Scheme", "Card uniquely identified by IIN and CIN"),
            var o when o.StartsWith("1.2.840.114283.4.2.")
                => ("Secure Channel Protocol of ISD", GetScpDescription(o)),
            var o when o.StartsWith("1.2.840.114283.4.3.")
                => ("Secure Channel Protocol of ISD", GetScpDescription(o)),
            "1.2.840.114283.5.7.2.0.0"
                => ("GlobalPlatform Conformance", "GlobalPlatform Conformance Testing"),
            var o when o.StartsWith("1.3.6.1.4.1.42.2.110.")
                => ("Java Card Runtime", "Java Card Runtime Environment"),
            _ => ("Object Identifier", GlobalPlatformOids.GetDescription(oid) ?? "Proprietary OID"),
        };
    }

    /// <summary>
    /// Gets SCP description from OID.
    /// </summary>
    private static string GetScpDescription(string oid)
    {
        var parts = oid.Split('.');
        if (parts.Length >= 6)
        {
            var scp = parts[5];
            byte implementation = 0;
            bool hasImplementation =
                parts.Length > 6 && byte.TryParse(parts[6], out implementation);
            string impl = hasImplementation ? $"{implementation:X2}" : "00";
            return scp switch
            {
                "2" when hasImplementation
                    => $"SCP02 with i={impl} (3DES, {((ScpImplementation)implementation).GetDescription()})",
                "3" when hasImplementation
                    => $"SCP03 with i={impl} (AES, {((ScpImplementation)implementation).GetScp03Description()})",
                _ => $"SCP{scp} with i={impl}",
            };
        }
        return "Unknown SCP";
    }

    /// <summary>
    /// Extracts the OID section from CardDataInfo.ToString() output.
    /// </summary>
    private static string ExtractOidSection(string cardDataString)
    {
        int oidSectionStart = cardDataString.IndexOf("Parsed OIDs:");
        if (oidSectionStart == -1)
            return "";

        int oidSectionEnd = cardDataString.IndexOf(
            "\nSecure Channel Protocol Info:",
            oidSectionStart
        );
        if (oidSectionEnd == -1)
            oidSectionEnd = cardDataString.Length;

        return cardDataString
            .Substring(
                oidSectionStart + "Parsed OIDs:\n".Length,
                oidSectionEnd - oidSectionStart - "Parsed OIDs:\n".Length
            )
            .Trim();
    }
}
