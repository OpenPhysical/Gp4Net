using System;
using System.Collections.Generic;

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
        public static string ParseAsHex(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return string.Empty;
            }

            // Show full diversification data without truncation
            return Convert.ToHexString(data);
        }

        /// <summary>
        /// Parses SCP support information from diversification data (CF0A format).
        /// The CF tag contains the actual diversification data, which starts with length 0A (10 bytes).
        /// Format: 5 pairs of bytes (SCP version + i= parameter), 00 00 if not supported.
        /// </summary>
        /// <param name="data">The diversification data containing SCP support info.</param>
        /// <returns>Formatted SCP support string.</returns>
        public static string ParseScpSupport(byte[] data)
        {
            if (data == null || data.Length < 12) // CF + 0A + 10 bytes
            {
                return "[red]None[/]";
            }

            // Skip CF tag (1 byte) and length (1 byte) to get to actual content
            var contentStart = 2;
            var contentLength = data[1]; // Length byte after CF tag
            
            if (data.Length < contentStart + contentLength || contentLength < 10)
            {
                return "[red]Parse error[/]";
            }

            var scpSupport = new List<string>();

            // Parse 5 pairs of bytes (SCP version + i= parameter) from the content
            for (int i = contentStart; i < contentStart + 10; i += 2)
            {
                var scpVersion = data[i];
                var iParameter = data[i + 1];

                // Skip empty slots (00 00)
                if (scpVersion == 0x00 && iParameter == 0x00)
                {
                    continue;
                }

                scpSupport.Add($"SCP{scpVersion:X2} (i={iParameter:X2})");
            }

            return scpSupport.Count > 0 ? string.Join(", ", scpSupport) : "[red]None[/]";
        }
    }
}