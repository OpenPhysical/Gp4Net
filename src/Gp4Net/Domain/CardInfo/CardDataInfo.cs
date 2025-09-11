using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Services;
using Org.BouncyCastle.Asn1;
using static Gp4Net.Services.TlvService;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Immutable record representing card data information from GET DATA responses.
/// Contains OID-based platform identification and version information.
/// Per GP Card Specification v2.3.1 Section E.2.1.1 - Card Data Object.
/// </summary>
/// <param name="Data">TLV-encoded card data bytes from GET DATA(0x0066) response</param>
/// <param name="Tags">Parsed TLV tags and their associated data</param>
/// <param name="GlobalPlatformVersion">GP version extracted from TLV structure</param>
/// <param name="SecureChannelProtocolInfo">SCP protocol data from card OIDs</param>
/// <param name="CardConfigurationDetails">Card configuration information</param>
/// <param name="CardChipDetails">Chip-specific details</param>
/// <param name="Oids">Object identifiers found in card data</param>
/// <param name="GlobalPlatformVersionFromOid">GP version string from OID parsing</param>
/// <param name="CardRecognitionData">Parsed Card Recognition Data from tag 73</param>
public record CardDataInfo(
    byte[] Data,
    IReadOnlyDictionary<ushort, byte[]> Tags,
    Maybe<Version> GlobalPlatformVersion,
    Maybe<byte[]> SecureChannelProtocolInfo,
    Maybe<byte[]> CardConfigurationDetails,
    Maybe<byte[]> CardChipDetails,
    IReadOnlyList<string> Oids,
    Maybe<string> GlobalPlatformVersionFromOid,
    Maybe<CardRecognitionData> CardRecognitionData
)
{
    /// <summary>
    /// Creates an empty CardDataInfo for cases where no card data is available.
    /// </summary>
    public static CardDataInfo Empty =>
        new(
            [],
            new Dictionary<ushort, byte[]>(),
            Maybe<Version>.None,
            Maybe<byte[]>.None,
            Maybe<byte[]>.None,
            Maybe<byte[]>.None,
            [],
            Maybe<string>.None,
            Maybe<CardRecognitionData>.None
        );

    /// <summary>
    /// Indicates whether this card data contains any meaningful information.
    /// </summary>
    public bool HasData => Data.Length > 0 || Tags.Count > 0 || Oids.Count > 0;

    /// <summary>
    /// Parses card data bytes into structured CardDataInfo using functional composition.
    /// Per GP Card Specification v2.3.1 Section E.2.1.1, parses TLV-encoded data object.
    /// </summary>
    /// <param name="data">TLV-encoded card data from GET DATA(0x0066) response</param>
    /// <returns>Result containing parsed CardDataInfo or SmartCardError</returns>
    public static Result<CardDataInfo, SmartCardError> Parse(byte[] data)
    {
        // Eliminate null by requiring non-null data at system boundary
        return data.Length == 0
            ? Result.Success<CardDataInfo, SmartCardError>(Empty)
            : ParseCardDataElements(data);
    }

    /// <summary>
    /// Pure function to parse card data elements into structured information.
    /// Uses functional composition to avoid mutations and side effects.
    /// </summary>
    private static Result<CardDataInfo, SmartCardError> ParseCardDataElements(byte[] data)
    {
        return Result.Try(
            () =>
            {
                var tags = ParseTlvTags(data);
                var oids = ExtractOids(data);
                var gpVersionFromOid = ExtractGpVersionFromOids(oids);
                var gpVersion = ExtractGpVersionFromTags(tags);
                var cardRecognitionData = ParseCardRecognitionData(tags);

                return new CardDataInfo(
                    data,
                    tags,
                    gpVersion,
                    tags.TryGetValue(0x64, out byte[] scpInfo)
                        ? Maybe<byte[]>.From(scpInfo)
                        : Maybe<byte[]>.None,
                    tags.TryGetValue(0x65, out byte[] configDetails)
                        ? Maybe<byte[]>.From(configDetails)
                        : Maybe<byte[]>.None,
                    tags.TryGetValue(0x66, out byte[] chipDetails)
                        ? Maybe<byte[]>.From(chipDetails)
                        : Maybe<byte[]>.None,
                    oids,
                    gpVersionFromOid,
                    cardRecognitionData
                );
            },
            ex => SmartCardError.InvalidData($"Failed to parse card data: {ex.Message}")
        );
    }

    /// <summary>
    /// Pure function to parse TLV tags from card data.
    /// Returns immutable dictionary of tags to byte arrays.
    /// </summary>
    private static IReadOnlyDictionary<ushort, byte[]> ParseTlvTags(byte[] data)
    {
        return TlvParser
            .ParseMultiple(data.ToImmutableArray())
            .Match(
                onSuccess: parseResult =>
                    parseResult
                        .Objects.Select(element =>
                            element
                                .Tag.ToNumber()
                                .Match(
                                    onSuccess: tagNumber => new
                                    {
                                        HasTag = true,
                                        Tag = (ushort)tagNumber,
                                        Data = element.TlvData.Bytes.ToArray(),
                                    },
                                    onFailure: _ => new
                                    {
                                        HasTag = false,
                                        Tag = (ushort)0,
                                        Data = Array.Empty<byte>(),
                                    }
                                )
                        )
                        .Where(x => x.HasTag)
                        .ToDictionary(x => x.Tag, x => x.Data),
                onFailure: _ => new Dictionary<ushort, byte[]>()
            );
    }

    /// <summary>
    /// Pure function to extract OIDs from card data recursively.
    /// Per ASN.1 encoding rules, OIDs use tag 0x06.
    /// </summary>
    private static IReadOnlyList<string> ExtractOids(byte[] data)
    {
        return ExtractOidsRecursive(data).Distinct().ToImmutableList();
    }

    /// <summary>
    /// Recursively extracts OIDs from TLV structures.
    /// </summary>
    private static IEnumerable<string> ExtractOidsRecursive(byte[] data)
    {
        return TlvParser
            .ParseMultiple(data.ToImmutableArray())
            .Match(
                onSuccess: parseResult =>
                    parseResult.Objects.SelectMany(element =>
                        element
                            .Tag.ToNumber()
                            .Match(
                                onSuccess: tagNumber =>
                                    tagNumber == 0x06
                                        ? ParseOid(element.TlvData.Bytes.ToArray())
                                            .Match(
                                                Some: oid => new[] { oid },
                                                None: () => Enumerable.Empty<string>()
                                            )
                                    : element.TlvData.Bytes.Length >= 2
                                        ? ExtractOidsRecursive(element.TlvData.Bytes.ToArray())
                                    : Enumerable.Empty<string>(),
                                onFailure: _ => Enumerable.Empty<string>()
                            )
                    ),
                onFailure: _ => Enumerable.Empty<string>()
            );
    }

    /// <summary>
    /// Pure function to parse a single OID from bytes using BouncyCastle.
    /// </summary>
    private static Maybe<string> ParseOid(byte[] oidBytes)
    {
        // Use Result.Try for functional exception handling
        return Result.Try(() =>
        {
            // Create DER-encoded OID from content
            byte[] derBytes = new byte[oidBytes.Length + 2];
            derBytes[0] = 0x06; // OID tag
            derBytes[1] = (byte)oidBytes.Length;
            Buffer.BlockCopy(oidBytes, 0, derBytes, 2, oidBytes.Length);

            var asn1Object = Asn1Object.FromByteArray(derBytes);
            return asn1Object is DerObjectIdentifier oidObj
                ? Maybe<string>.From(oidObj.Id)
                : Maybe<string>.None;
        })
        .Match(
            success => success,
            _ => Maybe<string>.None
        );
    }

    /// <summary>
    /// Pure function to extract GlobalPlatform version from OIDs.
    /// Per GP Card Specification, GP version OIDs follow pattern 1.2.840.114283.2.x.y.z
    /// </summary>
    private static Maybe<string> ExtractGpVersionFromOids(IReadOnlyList<string> oids)
    {
        string result = oids.Where(oid =>
                oid.StartsWith("1.2.840.114283.2.") && oid != "1.2.840.114283.2"
            )
            .Select(oid => oid.Split('.'))
            .Where(parts => parts.Length >= 7)
            .Select(parts => string.Join(".", parts.Skip(4)))
            .FirstOrDefault();
        return string.IsNullOrEmpty(result) ? Maybe<string>.None : Maybe<string>.From(result);
    }

    /// <summary>
    /// Pure function to extract GlobalPlatform version from TLV tags.
    /// Version information is typically stored in tag 0x73 in BCD format.
    /// </summary>
    private static Maybe<Version> ExtractGpVersionFromTags(IReadOnlyDictionary<ushort, byte[]> tags)
    {
        return tags.TryGetValue(0x73, out byte[] gpVersionData)
            ? ParseGlobalPlatformVersion(gpVersionData)
            : Maybe<Version>.None;
    }

    /// <summary>
    /// Pure function to parse GlobalPlatform version from BCD-encoded bytes.
    /// Per GP specification, versions are encoded in Binary Coded Decimal format.
    /// </summary>
    private static Maybe<Version> ParseGlobalPlatformVersion(byte[] data)
    {
        if (data.Length == 0)
            return Maybe<Version>.None;

        // Try BCD parsing first, then fallback to raw binary
        var bcdResult = Result.Try(() =>
            data.Length switch
            {
                >= 3 => Maybe<Version>.From(
                    new Version(BcdToByte(data[0]), BcdToByte(data[1]), BcdToByte(data[2]))
                ),
                2 => Maybe<Version>.From(new Version(BcdToByte(data[0]), BcdToByte(data[1]))),
                1 => Maybe<Version>.From(new Version(BcdToByte(data[0]), 0)),
                _ => Maybe<Version>.None,
            }
        );

        return bcdResult.Match(
            success => success,
            _ =>
            {
                // Fallback to raw binary interpretation if BCD parsing fails
                var binaryResult = Result.Try(() =>
                    data.Length switch
                    {
                        >= 3 => Maybe<Version>.From(new Version(data[0], data[1], data[2])),
                        2 => Maybe<Version>.From(new Version(data[0], data[1])),
                        1 => Maybe<Version>.From(new Version(data[0], 0)),
                        _ => Maybe<Version>.None,
                    }
                );
                
                return binaryResult.Match(
                    success => success,
                    _ => Maybe<Version>.None
                );
            }
        );
    }

    /// <summary>
    /// Pure function to convert BCD byte to decimal.
    /// Each BCD byte contains two decimal digits: high nibble * 10 + low nibble.
    /// </summary>
    private static int BcdToByte(byte bcd)
    {
        return (bcd >> 4) * 10 + (bcd & 0x0F);
    }

    /// <summary>
    /// Parse Card Recognition Data from tag 73 using CardDataParser.
    /// </summary>
    private static Maybe<CardRecognitionData> ParseCardRecognitionData(IReadOnlyDictionary<ushort, byte[]> tags)
    {
        return tags.TryGetValue(0x73, out byte[] tag73Data)
            ? CardDataParser.ParseCardRecognitionData(tag73Data)
                .Match(
                    success => Maybe<CardRecognitionData>.From(success),
                    _ => Maybe<CardRecognitionData>.None
                )
            : Maybe<CardRecognitionData>.None;
    }

    /// <summary>
    /// Custom string representation showing parsed card information including OID details.
    /// </summary>
    public override string ToString()
    {
        List<string> parts =
        [
            $"Data = {(Data.Length > 0 ? $"System.Byte[{Data.Length}]" : "System.Byte[]")}",
            "Tags = System.Collections.Generic.Dictionary`2[System.UInt16,System.Byte[]]",
            $"GlobalPlatformVersion = {(GlobalPlatformVersion.HasValue ? GlobalPlatformVersion.Value.ToString() : "No value")}",
            $"SecureChannelProtocolInfo = {(SecureChannelProtocolInfo.HasValue ? "System.Byte[]" : "No value")}",
            $"CardConfigurationDetails = {(CardConfigurationDetails.HasValue ? "System.Byte[]" : "No value")}",
            $"CardChipDetails = {(CardChipDetails.HasValue ? "System.Byte[]" : "No value")}",
            "Oids = System.Collections.Generic.List`1[System.String]",
        ];

        if (GlobalPlatformVersionFromOid.HasValue)
        {
            parts.Add($"GlobalPlatformVersionFromOid = {GlobalPlatformVersionFromOid.Value}");
        }
        else
        {
            parts.Add("GlobalPlatformVersionFromOid = No value");
        }

        parts.Add($"HasData = {HasData}");

        string result = $"CardDataInfo {{ {string.Join(", ", parts)} }}";

        // Add parsed OIDs section if we have OIDs
        if (Oids.Count > 0)
        {
            result += "\n\nParsed OIDs:\n";
            foreach (string oid in Oids)
            {
                string description = GetOidDescription(oid);
                result += $"{oid}\n-> {description}\n";

                // Add GP version info for version OIDs
                if (oid.StartsWith("1.2.840.114283.2.") && oid != "1.2.840.114283.2")
                {
                    var versionParts = oid.Split('.').Skip(4);
                    result += $"-> GP Version: {string.Join(".", versionParts)}\n";
                }
            }
        }

        // Add Secure Channel Protocol Info section if available
        if (SecureChannelProtocolInfo.HasValue)
        {
            result += "\nSecure Channel Protocol Info:\n";
            byte[] scpData = SecureChannelProtocolInfo.Value;
            result += $"Raw data: {Convert.ToHexString(scpData)}\n";

            // Parse SCP info according to GP specification
            if (scpData.Length >= 2)
            {
                byte scpId = scpData[0];
                byte implOptions = scpData[1];
                result += $"SCP ID: {scpId:X2}, Implementation Options: {implOptions:X2}\n";
            }
        }

        return result;
    }

    /// <summary>
    /// Gets human-readable description for common GlobalPlatform and JavaCard OIDs per official specifications.
    /// Based on GlobalPlatform Card Specification v2.3.1 Section H.1.
    /// </summary>
    private static string GetOidDescription(string oid)
    {
        return oid switch
        {
            // GlobalPlatform OIDs per GP Card Specification v2.3.1 Section H.1
            "1.2.840.114283.1" =>
                "Card Recognition Data, also identifies GlobalPlatform as the Tag Allocation Authority",
            "1.2.840.114283.2" => "Card Management Type and Version",
            "1.2.840.114283.3" =>
                "Card Identification Scheme - card uniquely identified by IIN and CIN",

            // JavaCard OIDs (Oracle/Sun Microsystems enterprise OID space)
            "1.3.6.1.4.1.42.2.110.1.3" => "JavaCard Runtime Environment version 3.x",

            // Pattern matching for versioned OIDs
            _ when oid.StartsWith("1.2.840.114283.2.") => "Card Management Type and Version",
            _ when oid.StartsWith("1.2.840.114283.4.") =>
                "Secure Channel Protocol of Security Domain and implementation options",
            _ when oid.StartsWith("1.3.6.1.4.1.42.2.110.") => "JavaCard Runtime Environment",

            _ => "Unknown OID",
        };
    }
}
