using CSharpFunctionalExtensions;
using Gp4Net.Domain.Commands;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Immutable record representing all information gathered from a smart card.
/// Replaces mutable classes with functional composition using Maybe types to eliminate nulls.
/// Per GP Card Specification v2.3.1 Section 11, contains card production life cycle,
/// capabilities, security domain information, and cryptographic key details.
/// </summary>
/// <param name="Atr">Answer to Reset bytes identifying card characteristics</param>
/// <param name="Cplc">Card Production Life Cycle data including manufacturing details</param>
/// <param name="Capabilities">Card capabilities including SCP protocol support and privileges</param>
/// <param name="KeyInfo">Key information template showing available cryptographic keys</param>
/// <param name="CardData">Card data object with OID-based version and platform identification</param>
/// <param name="ScpInfo">Structured SCP protocol and implementation option details</param>
/// <param name="SecurityStatus">Security domain management data and status information</param>
/// <param name="DiversificationData">Key diversification data for SCP key derivation</param>
/// <param name="IsdInfo">Issuer Security Domain information from SELECT response</param>
/// <param name="ChipDetails">Chip identification and hardware platform information</param>
public record CardInformation(
    Maybe<byte[]> Atr,
    Maybe<CplcData> Cplc,
    Maybe<CardCapabilities> Capabilities,
    Maybe<KeyInformationTemplate> KeyInfo,
    Maybe<CardDataInfo> CardData,
    Maybe<ScpInformation> ScpInfo,
    Maybe<SecurityDomainStatus> SecurityStatus,
    Maybe<byte[]> DiversificationData,
    Maybe<SelectResponse> IsdInfo,
    Maybe<ChipInfo> ChipDetails
)
{
    /// <summary>
    /// Creates an empty CardInformation with all fields set to None.
    /// Used as the starting point for functional composition.
    /// </summary>
    public static CardInformation Empty => new(
        Maybe<byte[]>.None,
        Maybe<CplcData>.None,
        Maybe<CardCapabilities>.None,
        Maybe<KeyInformationTemplate>.None,
        Maybe<CardDataInfo>.None,
        Maybe<ScpInformation>.None,
        Maybe<SecurityDomainStatus>.None,
        Maybe<byte[]>.None,
        Maybe<SelectResponse>.None,
        Maybe<ChipInfo>.None
    );

    /// <summary>
    /// Indicates whether the card has any meaningful data populated.
    /// Used to validate that card information gathering was successful.
    /// </summary>
    public bool HasAnyData => Atr.HasValue || Cplc.HasValue || Capabilities.HasValue ||
                             KeyInfo.HasValue || CardData.HasValue || ScpInfo.HasValue;

    /// <summary>
    /// Indicates whether secure channel capabilities are available.
    /// Per GP Card Specification, SCP support can be determined from either
    /// Card Capabilities or Diversification Data.
    /// </summary>
    public bool HasSecureChannelCapabilities =>
        Capabilities.Map(c => c.ScpOptions.Count > 0).GetValueOrDefault(false) ||
        ScpInfo.Map(s => s.Protocols.Count > 0).GetValueOrDefault(false);

    /// <summary>
    /// Gets a summary of manufacturing information for display purposes.
    /// Combines CPLC data with chip identification details.
    /// </summary>
    public Maybe<string> ManufacturingDetails =>
        from cplc in Cplc
        from chip in ChipDetails
        select $"{cplc.GetManufacturerName()} {chip.Platform} ({cplc.GetChipModel()})";

    /// <summary>
    /// Gets the GlobalPlatform version from available sources.
    /// Prefers OID-based version from Card Data over numeric version.
    /// Per GP Card Specification v2.3.1 Section E.2.1.1.
    /// </summary>
    public Maybe<string> GlobalPlatformVersion =>
        CardData.Bind(cd => cd.GlobalPlatformVersionFromOid)
        .Or(() => CardData.Bind(cd => cd.GlobalPlatformVersion.Map(v => v.ToString())));

    /// <summary>
    /// Gets the Java Card version if available from Card Data OIDs.
    /// Per Java Card Specification, identified by specific OID patterns.
    /// </summary>
    public Maybe<string> JavaCardVersion =>
        ChipDetails.Bind(cd => cd.JavaCardVersion);
}