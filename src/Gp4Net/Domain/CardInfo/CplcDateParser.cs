using System;

namespace Gp4Net.Domain.CardInfo
{
    /// <summary>
    /// Utility class for parsing CPLC date format.
    /// CPLC dates are encoded as 2 bytes representing days since January 1, 2000.
    /// </summary>
    public static class CplcDateParser
    {
        private static readonly DateTime BaseDate = new DateTime(2000, 1, 1);

        /// <summary>
        /// Invalid date value (all bits set).
        /// </summary>
        public const ushort InvalidDateMax = 0xFFFF;

        /// <summary>
        /// Invalid date value (all bits clear).
        /// </summary>
        public const ushort InvalidDateMin = 0x0000;

        /// <summary>
        /// Parses a CPLC date value to a DateTime.
        /// </summary>
        /// <param name="cplcDate">The 2-byte CPLC date value.</param>
        /// <returns>The parsed date, or null if the date is invalid.</returns>
        public static DateTime? ParseDate(ushort cplcDate)
        {
            if (!IsValidDate(cplcDate))
            {
                return null;
            }

            try
            {
                return BaseDate.AddDays(cplcDate);
            }
            catch (ArgumentOutOfRangeException)
            {
                // Date value would result in DateTime outside valid range
                return null;
            }
        }

        /// <summary>
        /// Formats a CPLC date value as a string.
        /// </summary>
        /// <param name="cplcDate">The 2-byte CPLC date value.</param>
        /// <returns>Formatted date string or indication of invalid date.</returns>
        public static string FormatDate(ushort cplcDate)
        {
            var date = ParseDate(cplcDate);
            if (date.HasValue)
            {
                return date.Value.ToString("yyyy-MM-dd");
            }

            if (cplcDate == InvalidDateMax || cplcDate == InvalidDateMin)
            {
                return "(invalid date format)";
            }

            return $"(invalid date: {cplcDate:X4})";
        }

        /// <summary>
        /// Checks if a CPLC date value is valid.
        /// </summary>
        /// <param name="cplcDate">The date value to check.</param>
        /// <returns>True if the date is valid, false otherwise.</returns>
        public static bool IsValidDate(ushort cplcDate)
        {
            return cplcDate != InvalidDateMin && cplcDate != InvalidDateMax;
        }

        /// <summary>
        /// Converts a DateTime to CPLC date format.
        /// </summary>
        /// <param name="date">The date to convert.</param>
        /// <returns>The CPLC date value.</returns>
        public static ushort ToCplcDate(DateTime date)
        {
            if (date < BaseDate)
            {
                throw new ArgumentException("Date cannot be before January 1, 2000", nameof(date));
            }

            var days = (date - BaseDate).Days;
            if (days > 0xFFFE) // Reserve 0xFFFF for invalid
            {
                throw new ArgumentException(
                    "Date is too far in the future for CPLC format",
                    nameof(date)
                );
            }

            return (ushort)days;
        }

        /// <summary>
        /// Formats CPLC data with date interpretation for display.
        /// </summary>
        /// <param name="fieldName">Name of the field.</param>
        /// <param name="dateValue">The CPLC date value.</param>
        /// <returns>Formatted string for display.</returns>
        public static string FormatDateField(string fieldName, ushort dateValue)
        {
            var dateStr = FormatDate(dateValue);
            return $"{fieldName}: {dateValue:X4} {dateStr}";
        }
    }
}
