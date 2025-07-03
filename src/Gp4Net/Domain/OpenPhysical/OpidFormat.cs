using System;
using System.Text.RegularExpressions;
using JetBrains.Annotations;

namespace Gp4Net.Domain.OpenPhysical
{
    /// <summary>
    /// Represents the format types for OpenPhysical IDs (OPID).
    /// </summary>
    [PublicAPI]
    public enum OpidFormat
    {
        /// <summary>
        /// Format 2: IIII-III-III (12 digits total).
        /// </summary>
        Format2 = 2,

        /// <summary>
        /// Format 3: IIII-III-IIII (13 digits total).
        /// </summary>
        Format3 = 3,

        /// <summary>
        /// Format 4: IIII-IIII-IIII (14 digits total).
        /// </summary>
        Format4 = 4,

        /// <summary>
        /// Format 5: IIII-IIII-IIIII (15 digits total).
        /// </summary>
        Format5 = 5,

        /// <summary>
        /// Format 6: IIII-IIIII-IIIII (16 digits total).
        /// </summary>
        Format6 = 6,

        /// <summary>
        /// Format 7: IIII-IIII-IIII-IIII (17 digits total).
        /// </summary>
        Format7 = 7,

        /// <summary>
        /// Format 8: IIIII-IIII-IIII-IIII (18 digits total).
        /// </summary>
        Format8 = 8,

        /// <summary>
        /// Format 9: IIII-IIII-IIII-IIIII (18 digits total).
        /// </summary>
        Format9 = 9
    }

    /// <summary>
    /// Extension methods for OpidFormat enum.
    /// </summary>
    [PublicAPI]
    public static class OpidFormatExtensions
    {
        /// <summary>
        /// Gets the regex pattern for validating the OPID format.
        /// </summary>
        /// <param name="format">The OPID format.</param>
        /// <returns>The regex pattern for the format.</returns>
        /// <exception cref="ArgumentException">Thrown when the format is not supported.</exception>
        public static string GetPattern(this OpidFormat format) =>
            format switch
            {
                OpidFormat.Format2 => @"^\d{4}-\d{3}-\d{3}$", // 12 digits: 4-3-3
                OpidFormat.Format3 => @"^\d{4}-\d{3}-\d{4}$", // 13 digits: 4-3-4
                OpidFormat.Format4 => @"^\d{4}-\d{4}-\d{4}$", // 14 digits: 4-4-4
                OpidFormat.Format5 => @"^\d{4}-\d{4}-\d{5}$", // 15 digits: 4-4-5
                OpidFormat.Format6 => @"^\d{4}-\d{5}-\d{5}$", // 16 digits: 4-5-5
                OpidFormat.Format7 => @"^\d{4}-\d{4}-\d{4}-\d{4}$", // 17 digits: 4-4-4-4
                OpidFormat.Format8 => @"^\d{5}-\d{4}-\d{4}-\d{4}$", // 18 digits: 5-4-4-4
                OpidFormat.Format9 => @"^\d{4}-\d{4}-\d{4}-\d{5}$", // 18 digits: 4-4-4-5
                _ => throw new ArgumentException($"Unknown OPID format: {format}")
            };

        /// <summary>
        /// Gets the expected total digit count for the format.
        /// </summary>
        /// <param name="format">The OPID format.</param>
        /// <returns>The expected total number of digits.</returns>
        public static int GetExpectedDigitCount(this OpidFormat format) =>
            format switch
            {
                OpidFormat.Format2 => 12,
                OpidFormat.Format3 => 13,
                OpidFormat.Format4 => 14,
                OpidFormat.Format5 => 15,
                OpidFormat.Format6 => 16,
                OpidFormat.Format7 => 17,
                OpidFormat.Format8 => 18,
                OpidFormat.Format9 => 18,
                _ => throw new ArgumentException($"Unknown OPID format: {format}")
            };

        /// <summary>
        /// Gets a human-readable description of the format pattern.
        /// </summary>
        /// <param name="format">The OPID format.</param>
        /// <returns>A description of the format pattern.</returns>
        public static string GetDescription(this OpidFormat format) =>
            format switch
            {
                OpidFormat.Format2 => "IIII-III-III",
                OpidFormat.Format3 => "IIII-III-IIII",
                OpidFormat.Format4 => "IIII-IIII-IIII",
                OpidFormat.Format5 => "IIII-IIII-IIIII",
                OpidFormat.Format6 => "IIII-IIIII-IIIII",
                OpidFormat.Format7 => "IIII-IIII-IIII-IIII",
                OpidFormat.Format8 => "IIIII-IIII-IIII-IIII",
                OpidFormat.Format9 => "IIII-IIII-IIII-IIIII",
                _ => throw new ArgumentException($"Unknown OPID format: {format}")
            };

        /// <summary>
        /// Validates whether a string matches the pattern for this format.
        /// </summary>
        /// <param name="format">The OPID format.</param>
        /// <param name="opid">The OPID string to validate.</param>
        /// <returns>True if the string matches the format pattern.</returns>
        public static bool IsValidPattern(this OpidFormat format, string opid)
        {
            if (string.IsNullOrEmpty(opid))
            {
                return false;
            }

            return Regex.IsMatch(opid, format.GetPattern());
        }

        /// <summary>
        /// Tries to parse a format indicator into an OpidFormat enum.
        /// </summary>
        /// <param name="formatIndicator">The format indicator (2-9).</param>
        /// <param name="format">The parsed format if successful.</param>
        /// <returns>True if the format indicator is valid.</returns>
        public static bool TryParseFormat(int formatIndicator, out OpidFormat format)
        {
            if (formatIndicator >= 2 && formatIndicator <= 9)
            {
                format = (OpidFormat)formatIndicator;
                return true;
            }

            format = default;
            return false;
        }
    }
}
