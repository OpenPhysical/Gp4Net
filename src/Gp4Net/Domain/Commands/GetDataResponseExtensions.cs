using System;
using System.Linq;
using Gp4Net.Core;
using Gp4Net.Domain.CardInfo;

namespace Gp4Net.Domain.Commands
{
    /// <summary>
    /// Extension methods for parsing GET DATA response bytes into domain objects.
    /// </summary>
    public static class GetDataResponseExtensions
    {
        /// <summary>
        /// Parses the byte array as card data.
        /// </summary>
        /// <param name="data">The raw GET DATA response.</param>
        /// <returns>Parsed card data or null if parsing fails.</returns>
        public static CardDataInfo? ParseAsCardData(this byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            try
            {
                var cardData = CardDataInfo.Parse(data);
                // Return null if no meaningful data was parsed (no OIDs and no known card data tags)
                var hasKnownTags = cardData.Tags.Keys.Any(tag => 
                    tag == 0x64 || // Secure Channel Protocol Info
                    tag == 0x65 || // Card Configuration Details
                    tag == 0x66 || // Card Chip Details
                    tag == 0x73);  // GlobalPlatform Version
                    
                if (cardData.Oids.Count == 0 && !hasKnownTags)
                {
                    return null;
                }
                return cardData;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Parses the byte array as card capabilities.
        /// </summary>
        /// <param name="data">The raw GET DATA response.</param>
        /// <returns>Parsed card capabilities or null if parsing fails.</returns>
        public static CardCapabilities? ParseAsCardCapabilities(this byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            // Reject obviously malformed data (too short to contain meaningful TLV)
            if (data.Length < 3)
            {
                return null;
            }

            var result = CardCapabilities.TryParse(new Option<byte[]>.Some(data));
            return result.Match(
                success: capabilities => {
                    // If the raw data has content but no capabilities were parsed, it's likely malformed
                    // Check if we have any meaningful capabilities or if this looks like malformed data
                    if (data.Length >= 3 && 
                        capabilities.ScpOptions.Count == 0 && 
                        capabilities.SdPrivileges == null && 
                        capabilities.AppPrivileges == null && 
                        capabilities.Algorithms == null &&
                        capabilities.CipherSuites.Count == 0)
                    {
                        // Additional check: if all bytes are the same (like 0xFF, 0xFF, 0xFF), it's likely malformed
                        if (data.All(b => b == data[0]))
                        {
                            return null;
                        }
                    }
                    return capabilities;
                },
                failure: error => null
            );
        }

        /// <summary>
        /// Parses the byte array as key information template.
        /// </summary>
        /// <param name="data">The raw GET DATA response.</param>
        /// <returns>Parsed key information template or null if parsing fails.</returns>
        public static KeyInformationTemplate? ParseAsKeyInformation(this byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            // Reject obviously malformed data (too short to contain meaningful TLV)
            if (data.Length < 3)
            {
                return null;
            }

            try
            {
                var keyInfo = KeyInformationTemplate.Parse(data);
                // If the raw data has content but no keys were parsed, it's likely malformed
                if (data.Length >= 3 && keyInfo.Keys.Count == 0)
                {
                    // Additional check: if all bytes are the same (like 0xFF, 0xFF, 0xFF), it's likely malformed
                    if (data.All(b => b == data[0]))
                    {
                        return null;
                    }
                }
                return keyInfo;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Parses the byte array as CPLC (Card Production Life Cycle) data.
        /// </summary>
        /// <param name="data">The raw GET DATA response.</param>
        /// <returns>Parsed CPLC data or null if parsing fails.</returns>
        public static CplcData? ParseAsCplc(this byte[] data)
        {
            if (data == null || data.Length != 42) // CPLC data is always 42 bytes
            {
                return null;
            }

            try
            {
                return CplcData.Parse(data);
            }
            catch
            {
                return null;
            }
        }
    }
}