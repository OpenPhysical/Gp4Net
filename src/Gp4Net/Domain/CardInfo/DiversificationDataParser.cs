using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.Core;
using Gp4Net.Core.Tlv;

namespace Gp4Net.Domain.CardInfo
{
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
        public static string ParseAsHex(Option<byte[]> data)
        {
            return data.Match(
                some: bytes => bytes.Length == 0 ? string.Empty : Convert.ToHexString(bytes),
                none: () => string.Empty
            );
        }

        /// <summary>
        /// Parses SCP support information from diversification data (CF0A format).
        /// The CF tag contains the actual diversification data, which starts with length 0A (10 bytes).
        /// Format: 5 pairs of bytes (SCP version + i= parameter), 00 00 if not supported.
        /// </summary>
        /// <param name="data">The diversification data containing SCP support info.</param>
        /// <returns>Formatted SCP support string.</returns>
        public static string ParseScpSupport(Option<byte[]> data)
        {
            return data.Match(
                some: bytes => ParseScpSupportFromBytes(bytes),
                none: () => "[red]None[/]"
            );
        }

        private static string ParseScpSupportFromBytes(byte[] data)
        {
            if (data.Length == 0 || data.Length < 3) // Minimum: tag + length + some content
            {
                return "[red]None[/]";
            }

            try
            {
                // Use SimpleTlvParser to find CF tag (diversification data)
                var cfElement = SimpleTlvParser.Enumerate(data).FirstOrDefault(e => e.Tag == 0xCF);
                
                // No CF tag found - treat as no data available
                if (cfElement.Content == null)
                {
                    return "[red]None[/]";
                }
                
                // CF tag found but content too short for SCP data (needs 10 bytes for 5 pairs)
                if (cfElement.Content.Length < 10)
                {
                    return "[red]Parse error[/]";
                }

                var scpSupport = new List<string>();

                // Parse 5 pairs of bytes (SCP version + i= parameter) from the CF content
                for (int i = 0; i < 10; i += 2)
                {
                    var scpVersion = cfElement.Content[i];
                    var iParameter = cfElement.Content[i + 1];

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
                // TLV parsing failed entirely
                return "[red]None[/]";
            }
        }
    }
}