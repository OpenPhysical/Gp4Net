using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Gp4Net.Core.Asn1;
using Gp4Net.Core.Tlv;
using Org.BouncyCastle.Asn1;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Represents detailed information retrieved from a card, such as raw data,
/// tags, and various configuration details.
/// </summary>
public class CardDataInfo
{
    /// <summary>
    /// Gets or sets the raw binary data associated with the card.
    /// </summary>
    /// <remarks>
    /// The <c>RawData</c> property represents the unprocessed byte array
    /// containing all the data extracted from the card. This data forms the
    /// base for parsing and extracting specific details, such as tags,
    /// OIDs, and configuration settings.
    /// </remarks>
    public byte[] RawData { get; set; } = [];

    /// <summary>
    /// Represents a collection of tags and their associated data extracted from the card.
    /// </summary>
    /// <remarks>
    /// Each tag is identified by a unique 16-bit identifier (ushort) and is associated with a corresponding byte array
    /// containing the tag's data. This property is populated during the parsing of card-related data.
    /// </remarks>
    public Dictionary<ushort, byte[]> Tags { get; } = [];

    /// <summary>
    /// Represents the GlobalPlatform version of the card.
    /// The GlobalPlatform version is extracted from the card data
    /// during parsing and indicates the supported GlobalPlatform specification.
    /// This property is read-only and may be null if the version information
    /// is not available in the provided data.
    /// </summary>
    public Version? GlobalPlatformVersion { get; private set; }

    /// <summary>
    /// Gets the secure channel protocol information extracted from the card data.
    /// This property represents a portion of the card's tag data that contains
    /// information about the secure communication protocol supported by the card.
    /// The value is extracted from the card data and corresponds to the tag
    /// associated with secure channel protocol information, if available.
    /// </summary>
    public byte[]? SecureChannelProtocolInfo { get; private set; }

    /// <summary>
    /// Represents the card configuration details as a byte array, which may
    /// include information such as available features or settings on the card.
    /// This property is populated during the parsing of the raw card data.
    /// </summary>
    public byte[]? CardConfigurationDetails { get; private set; }

    /// <summary>
    /// Represents the details associated with the card chip as retrieved from the parsed data tags.
    /// </summary>
    /// <remarks>
    /// This property is populated from the data tag with identifier 0x66 during the parsing process.
    /// It may contain chip-specific information in a byte array format, or be null if the tag is not found in the input data.
    /// </remarks>
    public byte[]? CardChipDetails { get; private set; }

    /// <summary>
    /// Represents a collection of Object Identifiers (OIDs)
    /// extracted from card data information.
    /// </summary>
    /// <remarks>
    /// - The OIDs provide identifiers that can be used for
    /// identifying protocols, features, or specific data structures.
    /// - This property contains a list of OIDs parsed from raw
    /// card data using predefined parsing logic.
    /// </remarks>
    /// <value>
    /// A list of strings where each string represents an
    /// extracted OID in the standard dot-separated notation.
    /// </value>
    public List<string> Oids { get; } = [];

    /// <summary>
    /// Gets the GlobalPlatform version extracted from the corresponding OID
    /// (Object Identifier) found during the parsing of card data. This property
    /// represents the version information for GlobalPlatform formatted as a string,
    /// typically derived from a specific OID pattern in the data.
    /// </summary>
    /// <remarks>
    /// If no valid GlobalPlatform version OID is found during parsing, this
    /// property will return <c>null</c>.
    /// </remarks>
    public string? GlobalPlatformVersionFromOid { get; private set; }

    /// Parses the given byte array to extract card information and populate a CardDataInfo object.
    /// <param name="data">The byte array containing card data to be parsed.</param>
    /// <returns>A CardDataInfo object populated with the extracted card information.</returns>
    /// <exception cref="ArgumentNullException">Thrown if the input data is null.</exception>
    public static CardDataInfo Parse(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        var cardData = new CardDataInfo { RawData = [.. data] };

        // Parse all DER elements from the data recursively
        ParseDerElements(data, cardData, isTopLevel: true);

        // Extract GlobalPlatform version from OIDs (matching GP Pro behavior)
        foreach (var oid in cardData.Oids)
        {
            if (!oid.StartsWith("1.2.840.114283.2.") || oid == "1.2.840.114283.2")
            {
                continue;
            }

            var parts = oid.Split('.');
            if (parts.Length < 7)
            {
                continue;
            }

            // Extract version components after the standard GP prefix (1.2.840.114283)
            var versionParts = parts.Skip(4);
            cardData.GlobalPlatformVersionFromOid = string.Join(".", versionParts);
        }

        if (cardData.Tags.TryGetValue(0x73, out var gpVersionData))
        {
            cardData.GlobalPlatformVersion = ParseGlobalPlatformVersion(gpVersionData);
        }

        _ = cardData.Tags.TryGetValue(0x64, out var cardDataSecureChannelProtocolInfo);
        _ = cardData.Tags.TryGetValue(0x65, out var cardConfigurationDetails);
        _ = cardData.Tags.TryGetValue(0x66, out var cardChipDetails);
        cardData.SecureChannelProtocolInfo = cardDataSecureChannelProtocolInfo;
        cardData.CardConfigurationDetails = cardConfigurationDetails;
        cardData.CardChipDetails = cardChipDetails;

        return cardData;
    }

    private static void ParseDerElements(
        byte[] data,
        CardDataInfo cardData,
        bool isTopLevel = false
    )
    {
        foreach (var element in SimpleTlvParser.Enumerate(data))
        {
            // Only store top-level tags in the Tags dictionary
            if (isTopLevel)
            {
                cardData.Tags[(ushort)element.Tag] = element.Content;
            }

            // Special handling for OIDs (tag 0x06)
            if (element.Tag == 0x06)
            {
                // Parse OID using BouncyCastle
                try
                {
                    // Create DER-encoded OID from content
                    var derBytes = new byte[element.Content.Length + 2];
                    derBytes[0] = 0x06; // OID tag
                    derBytes[1] = (byte)element.Content.Length;
                    Buffer.BlockCopy(element.Content, 0, derBytes, 2, element.Content.Length);

                    var asn1Object = Asn1Object.FromByteArray(derBytes);
                    if (asn1Object is DerObjectIdentifier oidObj)
                    {
                        var oidString = oidObj.Id;
                        if (!cardData.Oids.Contains(oidString))
                        {
                            cardData.Oids.Add(oidString);
                        }
                    }
                }
                catch
                {
                    // Skip invalid OIDs
                }
            }
            else if (element.Content.Length >= 2)
            {
                // Try to parse as DER to see if it contains nested structures
                // Only recurse if we find at least one complete DER element
                var nestedElements = SimpleTlvParser.Enumerate(element.Content).ToList();
                if (nestedElements.Any())
                {
                    // Additional check: ensure we consumed all the content
                    // This helps avoid false positives where random data looks like DER
                    var totalConsumed = nestedElements.Sum(e => e.TotalLength);
                    if (totalConsumed == element.Content.Length)
                    {
                        // Recursively parse nested structures
                        ParseDerElements(element.Content, cardData, isTopLevel: false);
                    }
                }
            }
        }
    }

    /// Parses the GlobalPlatform version from the provided byte array.
    /// GlobalPlatform versions are typically encoded in BCD (Binary Coded Decimal) format.
    /// <param name="data">The byte array containing the GlobalPlatform version information.</param>
    /// <return>
    /// A <see cref="System.Version"/> object representing the parsed GlobalPlatform version,
    /// or null if the data length is insufficient to determine a valid version.
    /// </return>
    private static Version? ParseGlobalPlatformVersion(byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return null;
        }

        try
        {
            // Parse as BCD (Binary Coded Decimal) format
            // Each byte represents two decimal digits in BCD format
            return data.Length switch
            {
                >= 3 => new Version(BcdToByte(data[0]), BcdToByte(data[1]), BcdToByte(data[2])),
                2 => new Version(BcdToByte(data[0]), BcdToByte(data[1])),
                1 => new Version(BcdToByte(data[0]), 0),
                _ => null
            };
        }
        catch
        {
            // Fallback to raw binary interpretation if BCD parsing fails
            return data.Length switch
            {
                >= 3 => new Version(data[0], data[1], data[2]),
                2 => new Version(data[0], data[1]),
                1 => new Version(data[0], 0),
                _ => null
            };
        }
    }

    /// <summary>
    /// Converts a BCD (Binary Coded Decimal) byte to its decimal equivalent.
    /// </summary>
    /// <param name="bcd">The BCD byte to convert.</param>
    /// <returns>The decimal equivalent.</returns>
    private static int BcdToByte(byte bcd)
    {
        return ((bcd >> 4) * 10) + (bcd & 0x0F);
    }

    /// <summary>
    /// Converts the current state of the CardDataInfo instance, including parsed OIDs,
    /// GlobalPlatform version, secure channel protocol information, card configuration details,
    /// card chip details, and all tag data, into a readable string format.
    /// </summary>
    /// <returns>
    /// A string representation of the CardDataInfo instance, providing detailed information
    /// about its parsed contents and metadata.
    /// </returns>
    public override string ToString()
    {
        var sb = new StringBuilder();
        _ = sb.AppendLine("Card Data:");

        if (Oids.Count > 0)
        {
            _ = sb.AppendLine("  Parsed OIDs:");
            foreach (var oid in Oids)
            {
                var description = KnownOids.GetDescription(oid);
                _ = sb.AppendLine($"    Tag 6: {oid}");
                if (!string.IsNullOrEmpty(description))
                {
                    _ = sb.AppendLine($"    -> {description}");
                }
            }
        }

        if (!string.IsNullOrEmpty(GlobalPlatformVersionFromOid))
        {
            _ = sb.AppendLine($"  -> GP Version: {GlobalPlatformVersionFromOid}");
        }

        if (GlobalPlatformVersion != null)
        {
            _ = sb.AppendLine($"  GlobalPlatform Version (from tag 73): {GlobalPlatformVersion}");
        }

        if (SecureChannelProtocolInfo != null)
        {
            _ = sb.AppendLine(
                $"  Secure Channel Protocol Info: {BitConverter.ToString(SecureChannelProtocolInfo)}"
            );
        }

        if (CardConfigurationDetails != null)
        {
            _ = sb.AppendLine(
                $"  Card Configuration Details: {BitConverter.ToString(CardConfigurationDetails)}"
            );
        }

        if (CardChipDetails != null)
        {
            _ = sb.AppendLine($"  Card/Chip Details: {BitConverter.ToString(CardChipDetails)}");
        }

        _ = sb.AppendLine("  All Tags:");
        foreach (var tag in Tags.OrderBy(static t => t.Key))
        {
            _ = sb.AppendLine($"    Tag {tag.Key:X2}: {BitConverter.ToString(tag.Value)}");
        }

        return sb.ToString();
    }
}
