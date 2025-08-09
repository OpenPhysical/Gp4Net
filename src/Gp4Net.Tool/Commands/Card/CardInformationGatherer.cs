using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Services;
using Gp4Net.Tool.Services;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Pure functional pipeline to gather and parse card information from multiple GET DATA commands.
/// Eliminates imperative data gathering with functional composition and Result types.
/// Per GP Card Specification v2.3.1, gathers data from standard data objects.
/// </summary>
public static class CardInformationGatherer
{
    /// <summary>
    /// Main entry point to gather all available card information using functional composition.
    /// Transforms imperative try/catch patterns into Result-based error handling.
    /// </summary>
    /// <param name="cardService">Card service for APDU communication</param>
    /// <param name="gpService">GlobalPlatform service for high-level operations</param>
    /// <returns>Result containing complete CardInformation or SmartCardError</returns>
    public static async Task<Result<CardInformation, SmartCardError>> GatherCardInformationAsync(
        ICardService cardService,
        IGlobalPlatformService gpService)
    {
        // Gather basic card data (no secure channel required)
        var basicData = await GatherBasicCardDataAsync(cardService, gpService);
        
        // Parse and enrich the basic data 
        return basicData.Bind(basic => ParseAndEnrichCardInformation(basic));
    }

    /// <summary>
    /// Gathers basic card information that doesn't require secure channel.
    /// Uses functional composition to combine multiple GET DATA operations.
    /// </summary>
    private static async Task<Result<BasicCardData, SmartCardError>> GatherBasicCardDataAsync(
        ICardService cardService, 
        IGlobalPlatformService gpService)
    {
        // Get ATR (always available)
        var atr = cardService.GetAtr();

        // Parallel gathering of all GET DATA commands
        var isdResult = await gpService.SelectIsdAsync();
        var cplcResult = await gpService.GetCplcAsync();
        var cardDataResult = await gpService.GetDataAsync(GetDataCommand.DataObjects.CardData);
        var capabilitiesResult = await gpService.GetDataAsync(GetDataCommand.DataObjects.CardCapabilities);
        var keyInfoResult = await gpService.GetDataAsync(GetDataCommand.DataObjects.KeyInformationTemplate);
        var diversificationResult = await gpService.GetDataAsync(GetDataCommand.DataObjects.DiversificationData);
        var securityResult = await gpService.GetDataAsync(GetDataCommand.DataObjects.SecurityDomainManagementData);

        return Result.Success<BasicCardData, SmartCardError>(new BasicCardData(
            atr != null ? Maybe<byte[]>.From(atr) : Maybe<byte[]>.None,
            isdResult.IsSuccess ? Maybe<SelectResponse>.From(isdResult.Value) : Maybe<SelectResponse>.None,
            cplcResult.IsSuccess ? Maybe<CplcData>.From(cplcResult.Value) : Maybe<CplcData>.None,
            cardDataResult.IsSuccess ? Maybe<byte[]>.From(cardDataResult.Value) : Maybe<byte[]>.None,
            capabilitiesResult.IsSuccess ? Maybe<byte[]>.From(capabilitiesResult.Value) : Maybe<byte[]>.None,
            keyInfoResult.IsSuccess ? Maybe<byte[]>.From(keyInfoResult.Value) : Maybe<byte[]>.None,
            diversificationResult.IsSuccess ? Maybe<byte[]>.From(diversificationResult.Value) : Maybe<byte[]>.None,
            securityResult.IsSuccess ? Maybe<byte[]>.From(securityResult.Value) : Maybe<byte[]>.None
        ));
    }

    /// <summary>
    /// Parses raw card data into structured CardInformation using pure functions.
    /// Eliminates mutations and exceptions with functional error handling.
    /// </summary>
    private static Result<CardInformation, SmartCardError> ParseAndEnrichCardInformation(BasicCardData basicData)
    {
        // Parse each data element using pure functions
        var parsedCardData = ParseCardDataSafely(basicData.CardDataBytes);
        var parsedCapabilities = ParseCapabilitiesSafely(basicData.CapabilitiesBytes);
        var parsedKeyInfo = ParseKeyInfoSafely(basicData.KeyInfoBytes);
        var parsedSecurityStatus = ParseSecurityStatusSafely(basicData.SecurityStatusBytes);
        var parsedScpInfo = ExtractScpInfoSafely(basicData.CapabilitiesBytes, basicData.DiversificationData);
        var parsedChipInfo = ExtractChipInfoSafely(basicData.Cplc);

        return Result.Success<CardInformation, SmartCardError>(new CardInformation(
            basicData.Atr,
            basicData.Cplc,
            parsedCapabilities,
            parsedKeyInfo,
            parsedCardData,
            parsedScpInfo,
            parsedSecurityStatus,
            basicData.DiversificationData,
            basicData.IsdInfo,
            parsedChipInfo
        ));
    }

    /// <summary>
    /// Pure function to parse card data bytes with error handling.
    /// </summary>
    private static Maybe<CardDataInfo> ParseCardDataSafely(Maybe<byte[]> cardDataBytes)
    {
        return cardDataBytes
            .Bind(bytes =>
            {
                var result = CardDataInfo.Parse(bytes);
                return result.IsSuccess ? Maybe<CardDataInfo>.From(result.Value) : Maybe<CardDataInfo>.None;
            });
    }

    /// <summary>
    /// Pure function to parse capabilities with error handling.
    /// </summary>
    private static Maybe<CardCapabilities> ParseCapabilitiesSafely(Maybe<byte[]> capabilitiesBytes)
    {
        return capabilitiesBytes
            .Bind(bytes =>
            {
                var result = CardCapabilities.TryParse(Maybe<byte[]>.From(bytes));
                return result.IsSuccess ? Maybe<CardCapabilities>.From(result.Value) : Maybe<CardCapabilities>.None;
            });
    }

    /// <summary>
    /// Pure function to parse key information with error handling.
    /// </summary>
    private static Maybe<KeyInformationTemplate> ParseKeyInfoSafely(Maybe<byte[]> keyInfoBytes)
    {
        return keyInfoBytes
            .Bind(bytes =>
            {
                var result = KeyInformationTemplate.Parse(bytes);
                return result.IsSuccess ? Maybe<KeyInformationTemplate>.From(result.Value) : Maybe<KeyInformationTemplate>.None;
            });
    }

    /// <summary>
    /// Pure function to parse security status with error handling.
    /// </summary>
    private static Maybe<SecurityDomainStatus> ParseSecurityStatusSafely(Maybe<byte[]> securityStatusBytes)
    {
        return securityStatusBytes
            .Bind(bytes =>
            {
                var result = SecurityDomainStatus.Parse(bytes);
                return result.IsSuccess ? Maybe<SecurityDomainStatus>.From(result.Value) : Maybe<SecurityDomainStatus>.None;
            });
    }

    /// <summary>
    /// Pure function to extract SCP information from capabilities and diversification data.
    /// Per GP Card Specification v2.3.1 Section 6.3.1, SCP info can come from either source.
    /// </summary>
    private static Maybe<ScpInformation> ExtractScpInfoSafely(
        Maybe<byte[]> capabilitiesBytes, 
        Maybe<byte[]> diversificationData)
    {
        // Try capabilities first
        var fromCapabilities = capabilitiesBytes
            .Bind(bytes =>
            {
                var result = CardCapabilities.TryParse(Maybe<byte[]>.From(bytes));
                return result.IsSuccess && result.Value.ScpOptions.Count > 0
                    ? Maybe<ScpInformation>.From(ScpCapabilitiesParser.ParseDetailed(bytes))
                    : Maybe<ScpInformation>.None;
            });

        // If no SCP info from capabilities, try diversification data
        return fromCapabilities.HasValue 
            ? fromCapabilities 
            : diversificationData.Map(bytes =>
            {
                // Parse SCP support from diversification data
                var scpSupport = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(bytes));
                // Convert to ScpInformation - for now just return None as we need proper parsing
                return Maybe<ScpInformation>.None;
            }).GetValueOrDefault(Maybe<ScpInformation>.None);
    }

    /// <summary>
    /// Pure function to extract chip information from CPLC data.
    /// </summary>
    private static Maybe<ChipInfo> ExtractChipInfoSafely(Maybe<CplcData> cplc)
    {
        return cplc.Map(cplcData => ChipInfo.FromCplcData(cplcData));
    }

    /// <summary>
    /// Immutable record to hold basic card data before parsing.
    /// Intermediate structure for functional composition.
    /// </summary>
    private record BasicCardData(
        Maybe<byte[]> Atr,
        Maybe<SelectResponse> IsdInfo,
        Maybe<CplcData> Cplc,
        Maybe<byte[]> CardDataBytes,
        Maybe<byte[]> CapabilitiesBytes,
        Maybe<byte[]> KeyInfoBytes,
        Maybe<byte[]> DiversificationData,
        Maybe<byte[]> SecurityStatusBytes
    );
}