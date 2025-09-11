using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Domain.CardInfo;

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
    public const ushort INVALID_DATE_MAX = 0xFFFF;

    /// <summary>
    /// Invalid date value (all bits clear).
    /// </summary>
    public const ushort INVALID_DATE_MIN = 0x0000;

    /// <summary>
    /// Parses a CPLC date value to a DateTime.
    /// </summary>
    /// <param name="cplcDate">The 2-byte CPLC date value.</param>
    /// <returns>The parsed date, or None if the date is invalid.</returns>
    public static Maybe<DateTime> ParseDate(ushort cplcDate)
    {
        if (!IsValidDate(cplcDate))
        {
            return Maybe<DateTime>.None;
        }

        // Check bounds to avoid DateTime overflow
        // Since ushort max is 65535, and BaseDate is 2000-01-01, max date would be ~2179
        // This is well within DateTime range, but we validate for safety
        // No additional check needed - ushort range is inherently safe

        return Maybe<DateTime>.From(BaseDate.AddDays(cplcDate));
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

        if (cplcDate is INVALID_DATE_MAX or INVALID_DATE_MIN)
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
        return cplcDate != INVALID_DATE_MIN && cplcDate != INVALID_DATE_MAX;
    }

    /// <summary>
    /// Converts a DateTime to CPLC date format.
    /// </summary>
    /// <param name="date">The date to convert.</param>
    /// <returns>A Result containing the CPLC date value.</returns>
    public static Result<ushort, SmartCardError> ToCplcDate(DateTime date)
    {
        if (date < BaseDate)
        {
            return Result.Failure<ushort, SmartCardError>(
                SmartCardError.InvalidArgument("Date cannot be before January 1, 2000")
            );
        }

        int days = (date - BaseDate).Days;
        if (days > 0xFFFE) // Reserve 0xFFFF for invalid
        {
            return Result.Failure<ushort, SmartCardError>(
                SmartCardError.InvalidArgument("Date is too far in the future for CPLC format")
            );
        }

        return Result.Success<ushort, SmartCardError>((ushort)days);
    }

    /// <summary>
    /// Formats CPLC data with date interpretation for display.
    /// </summary>
    /// <param name="fieldName">Name of the field.</param>
    /// <param name="dateValue">The CPLC date value.</param>
    /// <returns>Formatted string for display.</returns>
    public static string FormatDateField(string fieldName, ushort dateValue)
    {
        string dateStr = FormatDate(dateValue);
        return $"{fieldName}: {dateValue:X4} {dateStr}";
    }
}
