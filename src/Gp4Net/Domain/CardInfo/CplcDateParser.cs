using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Domain.CardInfo;

/// <summary>A valid industry CPLC YDDD production-date value.</summary>
public readonly record struct CplcProductionDate(byte YearDigit, ushort DayOfYear)
{
    /// <summary>Resolves the one-digit year using an explicitly chosen decade.</summary>
    public Result<DateTime, SmartCardError> Resolve(int decade)
    {
        if (decade < 1 || decade % 10 != 0)
            return SmartCardError.InvalidArgument(
                "The CPLC decade must be a positive multiple of ten"
            );

        int year = decade + YearDigit;
        int maximumDay = DateTime.IsLeapYear(year) ? 366 : 365;
        return DayOfYear is >= 1 && DayOfYear <= maximumDay
            ? Result.Success<DateTime, SmartCardError>(
                new DateTime(year, 1, 1).AddDays(DayOfYear - 1)
            )
            : Result.Failure<DateTime, SmartCardError>(
                SmartCardError.InvalidData($"Day {DayOfYear} is invalid for {year}")
            );
    }
}

/// <summary>Parses the industry YDDD form used by CPLC production-date fields.</summary>
public static class CplcDateParser
{
    public const ushort INVALID_DATE_MAX = 0xFFFF;
    public const ushort INVALID_DATE_MIN = 0x0000;

    public static Maybe<CplcProductionDate> Parse(ushort value)
    {
        if (value is INVALID_DATE_MIN or INVALID_DATE_MAX)
            return Maybe<CplcProductionDate>.None;

        int year = value >> 12;
        int hundreds = value >> 8 & 0x0F;
        int tens = value >> 4 & 0x0F;
        int ones = value & 0x0F;
        if (year > 9 || hundreds > 9 || tens > 9 || ones > 9)
            return Maybe<CplcProductionDate>.None;

        int day = hundreds * 100 + tens * 10 + ones;
        return day is >= 1 and <= 366
            ? Maybe<CplcProductionDate>.From(new CplcProductionDate((byte)year, (ushort)day))
            : Maybe<CplcProductionDate>.None;
    }

    public static Maybe<DateTime> ParseDate(ushort value, int decade) =>
        Parse(value)
            .Bind(parsed =>
                parsed
                    .Resolve(decade)
                    .Match(date => Maybe<DateTime>.From(date), _ => Maybe<DateTime>.None)
            );

    public static string FormatDate(ushort value) =>
        Parse(value)
            .Match(
                parsed => $"YDDD(year digit {parsed.YearDigit}, day {parsed.DayOfYear:000})",
                () => $"(invalid date: {value:X4})"
            );

    public static bool IsValidDate(ushort value) => Parse(value).HasValue;

    public static Result<ushort, SmartCardError> ToCplcDate(DateTime date)
    {
        int day = date.DayOfYear;
        int encoded = (date.Year % 10) << 12 | day / 100 << 8 | day / 10 % 10 << 4 | day % 10;
        return Result.Success<ushort, SmartCardError>((ushort)encoded);
    }

    public static string FormatDateField(string fieldName, ushort dateValue) =>
        $"{fieldName}: {dateValue:X4} {FormatDate(dateValue)}";
}
