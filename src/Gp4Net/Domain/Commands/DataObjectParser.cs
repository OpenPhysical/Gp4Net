using System;
using System.Text.RegularExpressions;

namespace Gp4Net.Domain.Commands
{
    /// <summary>
    /// Parser for raw data object format used in PUT DATA and STORE DATA commands.
    /// </summary>
    public static class DataObjectParser
    {
        /// <summary>
        /// Parses a raw data object in hex tag format (e.g., "9F70:040102" or "9F70=040102").
        /// </summary>
        /// <param name="dataObject">The data object string to parse.</param>
        /// <returns>A tuple containing the tag and data bytes.</returns>
        public static (ushort tag, byte[] data) ParseRawDataObject(string dataObject)
        {
            if (string.IsNullOrWhiteSpace(dataObject))
            {
                throw new ArgumentException("Data object cannot be null or empty");
            }

            // Support both ':' and '=' as separators
            var match = Regex.Match(dataObject, @"^([0-9A-Fa-f]{4})[:=]([0-9A-Fa-f]+)$");
            if (!match.Success)
            {
                throw new ArgumentException($"Invalid data object format: {dataObject}. Expected format: 9F70:040102 or 9F70=040102");
            }

            var tagHex = match.Groups[1].Value;
            var dataHex = match.Groups[2].Value;

            // Ensure even number of hex characters for data
            if (dataHex.Length % 2 != 0)
            {
                throw new ArgumentException($"Data must have even number of hex characters: {dataHex}");
            }

            var tag = Convert.ToUInt16(tagHex, 16);
            var data = Convert.FromHexString(dataHex);

            return (tag, data);
        }

        /// <summary>
        /// Validates that the parsed data object is well-formed.
        /// </summary>
        /// <param name="tag">The tag value.</param>
        /// <param name="data">The data bytes.</param>
        /// <returns>True if valid, false otherwise.</returns>
        public static bool ValidateDataObject(ushort tag, byte[] data)
        {
            // Tag should be in valid range (0x0000 is invalid)
            if (tag == 0x0000)
            {
                return false;
            }

            // Data should not be null (empty data is allowed for some tags)
            if (data == null)
            {
                return false;
            }

            // Additional validation could be added here based on specific tag requirements
            return true;
        }
    }
}