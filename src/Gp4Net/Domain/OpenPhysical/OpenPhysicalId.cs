using System;
using System.Linq;
using CSharpFunctionalExtensions;
using JetBrains.Annotations;

namespace Gp4Net.Domain.OpenPhysical;

/// <summary>
/// Represents an OpenPhysical ID (OPID) with parsing and validation capabilities.
/// </summary>
[PublicAPI]
public class OpenPhysicalId
{
    /// <summary>
    /// The fixed manager URL for all OpenPhysical cards.
    /// </summary>
    public const string OPEN_PHYSICAL_MANAGER_URL = "https://www.openphysical.org/";

    /// <summary>
    /// Gets the Issuer Identification Number (first 4 digits).
    /// </summary>
    public string Iin { get; }

    /// <summary>
    /// Gets the Card Image Number (remaining digits without dashes).
    /// </summary>
    public string Cin { get; }

    /// <summary>
    /// Gets the format indicator.
    /// </summary>
    public OpidFormat Format { get; }

    /// <summary>
    /// Gets the manager URL (always the OpenPhysical URL).
    /// </summary>
    public static string ManagerUrl
    {
        get { return OPEN_PHYSICAL_MANAGER_URL; }
    }

    /// <summary>
    /// Initializes a new instance of the OpenPhysicalId class.
    /// </summary>
    /// <param name="iin">The Issuer Identification Number.</param>
    /// <param name="cin">The Card Image Number (without dashes).</param>
    /// <param name="format">The format indicator.</param>
    private OpenPhysicalId(string iin, string cin, OpidFormat format)
    {
        Iin = iin;
        Cin = cin;
        Format = format;
    }

    /// <summary>
    /// Tries to parse an OPID string into an OpenPhysicalId instance.
    /// </summary>
    /// <param name="opid">The OPID string to parse (e.g., "1234-567-890").</param>
    /// <param name="result">The parsed OpenPhysicalId if successful.</param>
    /// <returns>True if parsing was successful, false otherwise.</returns>
    public static bool TryParse(string? opid, out OpenPhysicalId? result)
    {
        result = null;

        if (string.IsNullOrWhiteSpace(opid))
        {
            return false;
        }

        // Remove all dashes and validate that all characters are digits
        string digitsOnly = opid.Replace("-", "");
        if (digitsOnly.Length < 5 || !digitsOnly.All(char.IsDigit))
        {
            return false;
        }

        // Extract IIN (first 4 digits), format indicator (5th digit), and CIN (remaining)
        string iin = digitsOnly.Substring(0, 4);
        if (!int.TryParse(digitsOnly.Substring(4, 1), out int formatIndicator))
        {
            return false;
        }

        // Validate format indicator
        if (!OpidFormatExtensions.TryParseFormat(formatIndicator, out var format))
        {
            return false;
        }

        string cin = digitsOnly.Substring(5);

        // Validate that the total digit count matches the expected count for this format
        var expectedCountValid = format
            .GetExpectedDigitCount()
            .Match(expectedCount => digitsOnly.Length == expectedCount, _ => false);

        if (!expectedCountValid)
        {
            return false;
        }

        // Validate that the original OPID string matches the pattern for this format
        if (!format.IsValidPattern(opid))
        {
            return false;
        }

        result = new OpenPhysicalId(iin, cin, format);
        return true;
    }

    /// <summary>
    /// Tries to reconstruct an OpenPhysicalId from card data components.
    /// </summary>
    /// <param name="iin">The IIN from the card.</param>
    /// <param name="cin">The CIN from the card.</param>
    /// <param name="managerUrl">The manager URL from the card.</param>
    /// <param name="result">The reconstructed OpenPhysicalId if valid.</param>
    /// <returns>True if the card data represents a valid OPID.</returns>
    public static bool TryFromCardData(
        string? iin,
        string? cin,
        string? managerUrl,
        out OpenPhysicalId? result
    )
    {
        result = null;

        // Validate manager URL
        if (managerUrl != OPEN_PHYSICAL_MANAGER_URL)
        {
            return false;
        }

        // Validate IIN (must be exactly 4 digits)
        if (string.IsNullOrEmpty(iin) || iin.Length != 4 || !iin.All(char.IsDigit))
        {
            return false;
        }

        // Validate CIN (must be all digits)
        if (string.IsNullOrEmpty(cin) || !cin.All(char.IsDigit))
        {
            return false;
        }

        // Reconstruct the full digit string to determine format
        string fullDigits = iin + cin;
        if (fullDigits.Length < 5)
        {
            return false;
        }

        // Extract format indicator
        if (!int.TryParse(fullDigits.Substring(4, 1), out int formatIndicator))
        {
            return false;
        }

        if (!OpidFormatExtensions.TryParseFormat(formatIndicator, out var format))
        {
            return false;
        }

        // Validate that the total length matches the expected format
        var expectedLengthValid = format
            .GetExpectedDigitCount()
            .Match(expectedLength => fullDigits.Length == expectedLength, _ => false);

        if (!expectedLengthValid)
        {
            return false;
        }

        // Extract the actual CIN (everything after the format indicator)
        string actualCin = fullDigits.Substring(5);

        result = new OpenPhysicalId(iin, actualCin, format);
        return true;
    }

    /// <summary>
    /// Converts the OPID back to its display format with dashes.
    /// </summary>
    /// <returns>The formatted OPID string (e.g., "1234-567-890").</returns>
    public string ToDisplayFormat()
    {
        // Reconstruct the full digit string
        string fullDigits = Iin + (int)Format + Cin;

        // Apply the appropriate dash pattern based on format
        // All OpidFormat enum values (2-9) are handled explicitly
        return Format switch
        {
            OpidFormat.Format2
                => $"{fullDigits.Substring(0, 4)}-{fullDigits.Substring(4, 3)}-{fullDigits.Substring(7, 3)}",
            OpidFormat.Format3
                => $"{fullDigits.Substring(0, 4)}-{fullDigits.Substring(4, 3)}-{fullDigits.Substring(7, 4)}",
            OpidFormat.Format4
                => $"{fullDigits.Substring(0, 4)}-{fullDigits.Substring(4, 4)}-{fullDigits.Substring(8, 4)}",
            OpidFormat.Format5
                => $"{fullDigits.Substring(0, 4)}-{fullDigits.Substring(4, 4)}-{fullDigits.Substring(8, 5)}",
            OpidFormat.Format6
                => $"{fullDigits.Substring(0, 4)}-{fullDigits.Substring(4, 5)}-{fullDigits.Substring(9, 5)}",
            OpidFormat.Format7
                => $"{fullDigits.Substring(0, 4)}-{fullDigits.Substring(4, 4)}-{fullDigits.Substring(8, 4)}-{fullDigits.Substring(12, 4)}",
            OpidFormat.Format8
                => $"{fullDigits.Substring(0, 5)}-{fullDigits.Substring(5, 4)}-{fullDigits.Substring(9, 4)}-{fullDigits.Substring(13, 4)}",
            OpidFormat.Format9
                => $"{fullDigits.Substring(0, 4)}-{fullDigits.Substring(4, 4)}-{fullDigits.Substring(8, 4)}-{fullDigits.Substring(12, 5)}",
            _ => string.Empty, // Invalid format - should never occur due to validation in constructor
        };
    }

    /// <summary>
    /// Gets a string representation of the OPID.
    /// </summary>
    /// <returns>The OPID in display format.</returns>
    public override string ToString()
    {
        return ToDisplayFormat();
    }

    /// <summary>
    /// Determines whether the specified object is equal to the current OPID.
    /// </summary>
    /// <param name="obj">The object to compare with the current OPID.</param>
    /// <returns>True if the specified object is equal to the current OPID.</returns>
    public override bool Equals(object? obj)
    {
        return obj is OpenPhysicalId other
            && Iin == other.Iin
            && Cin == other.Cin
            && Format == other.Format;
    }

    /// <summary>
    /// Returns a hash code for the current OPID.
    /// </summary>
    /// <returns>A hash code for the current OPID.</returns>
    public override int GetHashCode()
    {
        return HashCode.Combine(Iin, Cin, Format);
    }

    /// <summary>
    /// Validates that card data components would form a valid OPID.
    /// </summary>
    /// <param name="iin">The IIN to validate.</param>
    /// <param name="cin">The CIN to validate.</param>
    /// <param name="managerUrl">The manager URL to validate.</param>
    /// <returns>True if the components would form a valid OPID.</returns>
    public static bool IsValidOpidData(string iin, string cin, string managerUrl)
    {
        return TryFromCardData(iin, cin, managerUrl, out _);
    }
}
