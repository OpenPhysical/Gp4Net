using System.Text.RegularExpressions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Domain.OpenPhysical;

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
    Format9 = 9,
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
    /// <returns>A Result containing the regex pattern for the format.</returns>
    public static Result<string, SmartCardError> GetPattern(this OpidFormat format)
    {
        return format switch
        {
            OpidFormat.Format2 => Result.Success<string, SmartCardError>(@"^\d{4}-\d{3}-\d{3}$"), // 12 digits: 4-3-3
            OpidFormat.Format3 => Result.Success<string, SmartCardError>(@"^\d{4}-\d{3}-\d{4}$"), // 13 digits: 4-3-4
            OpidFormat.Format4 => Result.Success<string, SmartCardError>(@"^\d{4}-\d{4}-\d{4}$"), // 14 digits: 4-4-4
            OpidFormat.Format5 => Result.Success<string, SmartCardError>(@"^\d{4}-\d{4}-\d{5}$"), // 15 digits: 4-4-5
            OpidFormat.Format6 => Result.Success<string, SmartCardError>(@"^\d{4}-\d{5}-\d{5}$"), // 16 digits: 4-5-5
            OpidFormat.Format7
                => Result.Success<string, SmartCardError>(@"^\d{4}-\d{4}-\d{4}-\d{4}$"), // 17 digits: 4-4-4-4
            OpidFormat.Format8
                => Result.Success<string, SmartCardError>(@"^\d{5}-\d{4}-\d{4}-\d{4}$"), // 18 digits: 5-4-4-4
            OpidFormat.Format9
                => Result.Success<string, SmartCardError>(@"^\d{4}-\d{4}-\d{4}-\d{5}$"), // 18 digits: 4-4-4-5
            _
                => Result.Failure<string, SmartCardError>(
                    SmartCardError.Unsupported($"Unknown OPID format: {format}")
                ),
        };
    }

    /// <summary>
    /// Gets the expected total digit count for the format.
    /// </summary>
    /// <param name="format">The OPID format.</param>
    /// <returns>A Result containing the expected total number of digits.</returns>
    public static Result<int, SmartCardError> GetExpectedDigitCount(this OpidFormat format)
    {
        return format switch
        {
            OpidFormat.Format2 => Result.Success<int, SmartCardError>(12),
            OpidFormat.Format3 => Result.Success<int, SmartCardError>(13),
            OpidFormat.Format4 => Result.Success<int, SmartCardError>(14),
            OpidFormat.Format5 => Result.Success<int, SmartCardError>(15),
            OpidFormat.Format6 => Result.Success<int, SmartCardError>(16),
            OpidFormat.Format7 => Result.Success<int, SmartCardError>(17),
            OpidFormat.Format8 => Result.Success<int, SmartCardError>(18),
            OpidFormat.Format9 => Result.Success<int, SmartCardError>(18),
            _
                => Result.Failure<int, SmartCardError>(
                    SmartCardError.Unsupported($"Unknown OPID format: {format}")
                ),
        };
    }

    /// <summary>
    /// Gets a human-readable description of the format pattern.
    /// </summary>
    /// <param name="format">The OPID format.</param>
    /// <returns>A Result containing a description of the format pattern.</returns>
    public static Result<string, SmartCardError> GetDescription(this OpidFormat format)
    {
        return format switch
        {
            OpidFormat.Format2 => Result.Success<string, SmartCardError>("IIII-III-III"),
            OpidFormat.Format3 => Result.Success<string, SmartCardError>("IIII-III-IIII"),
            OpidFormat.Format4 => Result.Success<string, SmartCardError>("IIII-IIII-IIII"),
            OpidFormat.Format5 => Result.Success<string, SmartCardError>("IIII-IIII-IIIII"),
            OpidFormat.Format6 => Result.Success<string, SmartCardError>("IIII-IIIII-IIIII"),
            OpidFormat.Format7 => Result.Success<string, SmartCardError>("IIII-IIII-IIII-IIII"),
            OpidFormat.Format8 => Result.Success<string, SmartCardError>("IIIII-IIII-IIII-IIII"),
            OpidFormat.Format9 => Result.Success<string, SmartCardError>("IIII-IIII-IIII-IIIII"),
            _
                => Result.Failure<string, SmartCardError>(
                    SmartCardError.Unsupported($"Unknown OPID format: {format}")
                ),
        };
    }

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

        return format.GetPattern().Match(pattern => Regex.IsMatch(opid, pattern), _ => false);
    }

    /// <summary>
    /// Tries to parse a format indicator into an OpidFormat enum.
    /// </summary>
    /// <param name="formatIndicator">The format indicator (2-9).</param>
    /// <param name="format">The parsed format if successful.</param>
    /// <returns>True if the format indicator is valid.</returns>
    public static bool TryParseFormat(int formatIndicator, out OpidFormat format)
    {
        if (formatIndicator is >= 2 and <= 9)
        {
            format = (OpidFormat)formatIndicator;
            return true;
        }

        format = default;
        return false;
    }
}
