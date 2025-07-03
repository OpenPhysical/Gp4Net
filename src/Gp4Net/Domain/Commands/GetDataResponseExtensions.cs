using System;
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
                return CardDataInfo.Parse(data);
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

            try
            {
                return CardCapabilities.Parse(data);
            }
            catch
            {
                return null;
            }
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

            try
            {
                return KeyInformationTemplate.Parse(data);
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