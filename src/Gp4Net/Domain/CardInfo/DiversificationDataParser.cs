using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core.Tlv;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Parses diversification data and SCP support information.
/// </summary>
public static class DiversificationDataParser
{
    /// <summary>
    /// Parses diversification data as a hex string.
    /// </summary>
    /// <param name="data">The raw diversification data.</param>
    /// <returns>Hex string representation of the data.</returns>
    public static string ParseAsHex(Maybe<byte[]> data)
    {
        return data.Match(
            Some: bytes => bytes.Length == 0 ? string.Empty : Convert.ToHexString(bytes),
            None: () => string.Empty
        );
    }

    /// <summary>
    /// Parses SCP support information from diversification data (CF0A format).
    /// The CF tag contains the actual diversification data, which starts with length 0A (10 bytes).
    /// Format: 5 pairs of bytes (SCP version + i= parameter), 00 00 if not supported.
    /// </summary>
    /// <param name="data">The diversification data containing SCP support info.</param>
    /// <returns>Formatted SCP support string.</returns>
    public static string ParseScpSupport(Maybe<byte[]> data)
    {
        return data.Match(
            Some: bytes => ParseScpSupportFromBytes(bytes),
            None: () => "[red]None[/]"
        );
    }

    private static string ParseScpSupportFromBytes(byte[] data)
    {
        if (data.Length is 0 or < 3) // Minimum: tag + length + some content
        {
            return "[red]None[/]";
        }

        try
        {
            // Use TlvParser to find CF tag (diversification data)
            Maybe<TlvObject> cfElementMaybe = TlvParser.FindByTag(data, 0xCF);

            // No CF tag found - treat as no data available
            if (!cfElementMaybe.HasValue)
            {
                return "[red]None[/]";
            }

            TlvObject cfElement = cfElementMaybe.Value;

            // CF tag found but content too short for SCP data (needs 10 bytes for 5 pairs)
            if (cfElement.Value.Length < 10)
            {
                return "[red]Parse error[/]";
            }

            // Parse 5 pairs of bytes (SCP version + i= parameter) from the CF content using functional approach
            var scpPairs = Enumerable.Range(0, 5)
                .Select(pairIndex => new
                {
                    ScpVersion = cfElement.Value[pairIndex * 2],
                    IParameter = cfElement.Value[pairIndex * 2 + 1]
                })
                .Where(pair => !(pair.ScpVersion == 0x00 && pair.IParameter == 0x00)) // Skip empty slots
                .ToList();

            // Check for invalid SCP versions - fail if any found
            foreach (var pair in scpPairs)
            {
                if (pair.ScpVersion > 0x11)
                {
                    // This is likely card identification data, not SCP support
                    return "[red]None[/]";
                }
            }

            List<string> scpSupport = scpPairs
                .Select(pair => $"SCP{pair.ScpVersion:X2} (i={pair.IParameter:X2})")
                .ToList();

            return scpSupport.Count > 0 ? string.Join(", ", scpSupport) : "[red]None[/]";
        }
        catch
        {
            // TLV parsing failed entirely
            return "[red]None[/]";
        }
    }
}