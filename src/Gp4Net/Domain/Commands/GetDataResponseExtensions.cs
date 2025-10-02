using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.CardInfo;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Extension methods for parsing GET DATA response bytes into domain objects.
/// </summary>
public static class GetDataResponseExtensions
{
    /// <summary>
    /// Parses the byte array as card data.
    /// </summary>
    /// <param name="data">The raw GET DATA response.</param>
    /// <returns>Parsed card data or None if parsing fails.</returns>
    public static Maybe<CardDataInfo> ParseAsCardData(this byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return Maybe<CardDataInfo>.None;
        }

        return CardDataInfo
            .Parse(data)
            .Match(
                success =>
                {
                    // Return None if no meaningful data was parsed (no OIDs and no known card data tags)
                    bool hasKnownTags = success.Tags.Keys.Any(tag =>
                        tag == 0x64
                        || // Secure Channel Protocol Info
                        tag == 0x65
                        || // Card Configuration Details
                        tag == 0x66
                        || // Card Chip Details
                        tag == 0x73
                    ); // GlobalPlatform Version

                    if (success.Oids.Count == 0 && !hasKnownTags)
                    {
                        return Maybe<CardDataInfo>.None;
                    }
                    return Maybe<CardDataInfo>.From(success);
                },
                failure => Maybe<CardDataInfo>.None
            );
    }

    /// <summary>
    /// Parses the byte array as card capabilities.
    /// </summary>
    /// <param name="data">The raw GET DATA response.</param>
    /// <returns>Parsed card capabilities or None if parsing fails.</returns>
    public static Maybe<CardCapabilities> ParseAsCardCapabilities(this byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return Maybe<CardCapabilities>.None;
        }

        // Reject obviously malformed data (too short to contain meaningful TLV)
        if (data.Length < 3)
        {
            return Maybe<CardCapabilities>.None;
        }

        var result = CardCapabilities.TryParse(Maybe<byte[]>.From(data));
        return result.Match(
            onSuccess: capabilities =>
            {
                // If the raw data has content but no capabilities were parsed, it's likely malformed
                // Check if we have any meaningful capabilities or if this looks like malformed data
                if (
                    data.Length >= 3
                    && capabilities.ScpOptions.Count == 0
                    && !capabilities.SdPrivileges.HasValue
                    && !capabilities.AppPrivileges.HasValue
                    && !capabilities.Algorithms.HasValue
                    && capabilities.CipherSuites.Count == 0
                )
                {
                    // Additional check: if all bytes are the same (like 0xFF, 0xFF, 0xFF), it's likely malformed
                    if (data.All(b => b == data[0]))
                    {
                        return Maybe<CardCapabilities>.None;
                    }
                }
                return Maybe<CardCapabilities>.From(capabilities);
            },
            onFailure: error => Maybe<CardCapabilities>.None
        );
    }

    /// <summary>
    /// Parses the byte array as key information template.
    /// </summary>
    /// <param name="data">The raw GET DATA response.</param>
    /// <returns>Parsed key information template or None if parsing fails.</returns>
    public static Maybe<KeyInformationTemplate> ParseAsKeyInformation(this byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return Maybe<KeyInformationTemplate>.None;
        }

        // Reject obviously malformed data (too short to contain meaningful TLV)
        if (data.Length < 3)
        {
            return Maybe<KeyInformationTemplate>.None;
        }

        return KeyInformationTemplate
            .Parse(data)
            .Match(
                success =>
                {
                    // If the raw data has content but no keys were parsed, it's likely malformed
                    if (data.Length >= 3 && success.Keys.Count == 0)
                    {
                        // Additional check: if all bytes are the same (like 0xFF, 0xFF, 0xFF), it's likely malformed
                        if (data.All(b => b == data[0]))
                        {
                            return Maybe<KeyInformationTemplate>.None;
                        }
                    }
                    return Maybe<KeyInformationTemplate>.From(success);
                },
                failure => Maybe<KeyInformationTemplate>.None
            );
    }

    /// <summary>
    /// Parses the byte array as CPLC (Card Production Life Cycle) data.
    /// </summary>
    /// <param name="data">The raw GET DATA response.</param>
    /// <returns>Parsed CPLC data or None if parsing fails.</returns>
    public static Maybe<CplcData> ParseAsCplc(this byte[] data)
    {
        if (data == null || data.Length != 42) // CPLC data is always 42 bytes
        {
            return Maybe<CplcData>.None;
        }

        return CplcData
            .Parse(data)
            .Match(success => Maybe<CplcData>.From(success), failure => Maybe<CplcData>.None);
    }

    /// <summary>
    /// Parses the byte array as security domain status (tag C1).
    /// </summary>
    /// <param name="data">The raw GET DATA response.</param>
    /// <returns>Parsed security domain status or None if parsing fails.</returns>
    public static Maybe<SecurityDomainStatus> ParseAsSecurityDomainStatus(this byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return Maybe<SecurityDomainStatus>.None;
        }

        return SecurityDomainStatus
            .Parse(Maybe<byte[]>.From(data))
            .Match(
                success => Maybe<SecurityDomainStatus>.From(success),
                failure => Maybe<SecurityDomainStatus>.None
            );
    }
}
