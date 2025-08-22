using System;
using System.Collections.Generic;
using System.Linq;
using JetBrains.Annotations;

namespace Gp4Net.Domain.OpenPhysical;

/// <summary>
/// Provides validation functionality for OpenPhysical IDs (OPID).
/// </summary>
[PublicAPI]
public static class OpidValidator
{
    /// <summary>
    /// Validates whether a string is a valid OPID format.
    /// </summary>
    /// <param name="opid">The OPID string to validate.</param>
    /// <returns>True if the OPID is valid, false otherwise.</returns>
    public static bool IsValidOpid(string opid)
    {
        return OpenPhysicalId.TryParse(opid, out _);
    }

    /// <summary>
    /// Validates an OPID and returns detailed validation results.
    /// </summary>
    /// <param name="opid">The OPID string to validate.</param>
    /// <returns>A validation result with details about any issues.</returns>
    public static OpidValidationResult ValidateOpid(string opid)
    {
        if (string.IsNullOrWhiteSpace(opid))
        {
            return OpidValidationResult.Failure("OPID cannot be null or empty");
        }

        // Check for valid characters (digits and dashes only)
        if (!opid.All(c => char.IsDigit(c) || c == '-'))
        {
            return OpidValidationResult.Failure("OPID can only contain digits and dashes");
        }

        // Remove dashes and check minimum length
        var digitsOnly = opid.Replace("-", "");
        if (digitsOnly.Length < 5)
        {
            return OpidValidationResult.Failure(
                "OPID must have at least 5 digits (4 for IIN + 1 format indicator)"
            );
        }

        // Validate format indicator
        if (!int.TryParse(digitsOnly.Substring(4, 1), out var formatIndicator))
        {
            return OpidValidationResult.Failure(
                "Format indicator (5th digit) must be a valid digit"
            );
        }

        if (!OpidFormatExtensions.TryParseFormat(formatIndicator, out var format))
        {
            return OpidValidationResult.Failure(
                $"Format indicator '{formatIndicator}' is not supported. Valid formats are 2-9"
            );
        }

        // Check total digit count
        var expectedCount = format.GetExpectedDigitCount();
        if (digitsOnly.Length != expectedCount)
        {
            return OpidValidationResult.Failure(
                $"Format {formatIndicator} requires exactly {expectedCount} digits, but got {digitsOnly.Length}"
            );
        }

        // Validate dash pattern
        if (!format.IsValidPattern(opid))
        {
            return OpidValidationResult.Failure(
                $"OPID does not match the required pattern for format {formatIndicator}: {format.GetDescription()}"
            );
        }

        return OpidValidationResult.Success();
    }

    /// <summary>
    /// Validates whether card data components would form a valid OPID.
    /// </summary>
    /// <param name="iin">The Issuer Identification Number.</param>
    /// <param name="cin">The Card Image Number.</param>
    /// <param name="managerUrl">The manager URL.</param>
    /// <returns>A validation result for the card data.</returns>
    public static OpidValidationResult ValidateCardData(
        string iin,
        string cin,
        string managerUrl
    )
    {
        // Check manager URL
        if (managerUrl != OpenPhysicalId.OpenPhysicalManagerUrl)
        {
            return OpidValidationResult.Failure(
                $"Manager URL is '{managerUrl}', expected '{OpenPhysicalId.OpenPhysicalManagerUrl}'"
            );
        }

        // Check IIN
        if (string.IsNullOrEmpty(iin))
        {
            return OpidValidationResult.Failure("IIN cannot be null or empty");
        }

        if (iin.Length != 4)
        {
            return OpidValidationResult.Failure(
                $"IIN must be exactly 4 digits, got {iin.Length}"
            );
        }

        if (!iin.All(char.IsDigit))
        {
            return OpidValidationResult.Failure("IIN must contain only digits");
        }

        // Check CIN
        if (string.IsNullOrEmpty(cin))
        {
            return OpidValidationResult.Failure("CIN cannot be null or empty");
        }

        if (!cin.All(char.IsDigit))
        {
            return OpidValidationResult.Failure("CIN must contain only digits");
        }

        // Try to reconstruct and validate the full OPID
        var fullDigits = iin + cin;
        if (fullDigits.Length < 5)
        {
            return OpidValidationResult.Failure(
                "Combined IIN and CIN must have at least 5 digits"
            );
        }

        if (!int.TryParse(fullDigits.Substring(4, 1), out var formatIndicator))
        {
            return OpidValidationResult.Failure("Format indicator (5th digit) is not valid");
        }

        if (!OpidFormatExtensions.TryParseFormat(formatIndicator, out var format))
        {
            return OpidValidationResult.Failure(
                $"Format indicator '{formatIndicator}' is not supported"
            );
        }

        var expectedLength = format.GetExpectedDigitCount();
        if (fullDigits.Length != expectedLength)
        {
            return OpidValidationResult.Failure(
                $"Format {formatIndicator} requires {expectedLength} total digits, but IIN+CIN has {fullDigits.Length}"
            );
        }

        return OpidValidationResult.Success();
    }

    /// <summary>
    /// Gets detailed format information for all supported OPID formats.
    /// </summary>
    /// <returns>A dictionary of format information.</returns>
    public static Dictionary<OpidFormat, string> GetSupportedFormats()
    {
        var formats = new Dictionary<OpidFormat, string>();

        foreach (var format in Enum.GetValues<OpidFormat>())
        {
            formats[format] =
                $"{format.GetDescription()} ({format.GetExpectedDigitCount()} digits)";
        }

        return formats;
    }
}

/// <summary>
/// Represents the result of OPID validation.
/// </summary>
[PublicAPI]
public class OpidValidationResult
{
    /// <summary>
    /// Gets a value indicating whether the validation was successful.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets the error message if validation failed.
    /// </summary>
    public string ErrorMessage { get; }

    private OpidValidationResult(bool isValid, string errorMessage)
    {
        IsValid = isValid;
        ErrorMessage = errorMessage;
    }

    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    /// <returns>A successful validation result.</returns>
    public static OpidValidationResult Success()
    {
        return new(true, null);
    }

    /// <summary>
    /// Creates a failed validation result with an error message.
    /// </summary>
    /// <param name="errorMessage">The error message.</param>
    /// <returns>A failed validation result.</returns>
    public static OpidValidationResult Failure(string errorMessage)
    {
        return new(false, errorMessage);
    }

    /// <summary>
    /// Returns a string representation of the validation result.
    /// </summary>
    /// <returns>The validation result as a string.</returns>
    public override string ToString()
    {
        return IsValid ? "Valid" : $"Invalid: {ErrorMessage}";
    }
}