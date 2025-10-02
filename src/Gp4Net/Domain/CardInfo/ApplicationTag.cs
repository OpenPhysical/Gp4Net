using CSharpFunctionalExtensions;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Represents an application-specific tag from GlobalPlatform Card Recognition Data.
/// Per GP Card Specification v2.3.1 Section E.2.1.1, these are tags like 60, 63, 64, etc.
/// that contain nested OIDs within the Card Recognition Data (tag 73).
/// </summary>
/// <param name="TagNumber">The application tag number (e.g., 0x60, 0x63, 0x64)</param>
/// <param name="TagName">Human-readable name for the tag</param>
/// <param name="NestedOid">Optional OID contained within this application tag</param>
/// <param name="RawData">The complete raw data of this tag including nested TLV</param>
public record ApplicationTag(
    byte TagNumber,
    string TagName,
    Maybe<string> NestedOid,
    byte[] RawData
)
{
    /// <summary>
    /// Gets the tag number as a hex string for display.
    /// </summary>
    public string TagHex => $"{TagNumber:X2}";

    /// <summary>
    /// Indicates whether this tag contains a nested OID.
    /// </summary>
    public bool HasNestedOid => NestedOid.HasValue;

    /// <summary>
    /// Creates an ApplicationTag from parsed TLV data.
    /// </summary>
    public static ApplicationTag Create(byte tagNumber, byte[] data, Maybe<string> oid)
    {
        var tagName = GetTagName(tagNumber);
        return new ApplicationTag(tagNumber, tagName, oid, data);
    }

    /// <summary>
    /// Gets the standard name for known application tags per GP specification.
    /// </summary>
    private static string GetTagName(byte tagNumber) =>
        tagNumber switch
        {
            0x60 => "Application tag 0", // Card Management Type and Version
            0x63 => "Application tag 3", // Card Identification Scheme
            0x64 => "Application tag 4", // Secure Channel Protocol
            0x65 => "Application tag 5", // Card configuration details (optional)
            0x66 => "Application tag 6", // Card/chip details (optional)
            0x67 => "Application tag 7", // ISD Trust Point certificate info (optional)
            0x68 => "Application tag 8", // ISD certificate info (conditional)
            _ => $"Application tag {tagNumber:X2}",
        };

    /// <summary>
    /// Gets a description of what this tag contains based on GP specification.
    /// </summary>
    public string GetDescription() =>
        TagNumber switch
        {
            0x60 => "Card Management Type and Version",
            0x63 => "Card Identification Scheme",
            0x64 => "Secure Channel Protocol of ISD",
            0x65 => "Card Configuration Details",
            0x66 => "Card/Chip Details",
            0x67 => "ISD Trust Point Certificate Information",
            0x68 => "ISD Certificate Information",
            _ => "Unknown Application Tag",
        };
}
