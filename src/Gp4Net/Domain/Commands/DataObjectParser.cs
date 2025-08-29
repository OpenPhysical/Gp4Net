using System;
using System.Text.RegularExpressions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Parser for raw data object format used in PUT DATA and STORE DATA commands.
/// </summary>
public static class DataObjectParser
{
    /// <summary>
    /// Parses a raw data object in hex tag format (e.g., "9F70:040102" or "9F70=040102").
    /// </summary>
    /// <param name="dataObject">The data object string to parse.</param>
    /// <returns>A Result containing the tag and data bytes, or an error.</returns>
    public static Result<(ushort tag, byte[] data), SmartCardError> ParseRawDataObject(string dataObject)
    {
        if (string.IsNullOrWhiteSpace(dataObject))
        {
            return Result.Failure<(ushort tag, byte[] data), SmartCardError>(
                SmartCardError.InvalidArgument("Data object cannot be null or empty"));
        }

        // Support both ':' and '=' as separators, 2-4 character tags, and allow any data
        Match match = Regex.Match(dataObject, @"^([0-9A-Fa-f]{2,4})[:=](.*)$");
        if (!match.Success)
        {
            return Result.Failure<(ushort tag, byte[] data), SmartCardError>(
                SmartCardError.InvalidArgument("Invalid data object format"));
        }

        string tagHex = match.Groups[1].Value;
        string dataHex = match.Groups[2].Value;

        // Validate hex characters in data if not empty
        if (!string.IsNullOrEmpty(dataHex))
        {
            if (!Regex.IsMatch(dataHex, @"^[0-9A-Fa-f]*$"))
            {
                return Result.Failure<(ushort tag, byte[] data), SmartCardError>(
                    SmartCardError.InvalidArgument("Data must contain only hex characters"));
            }

            // Ensure even number of hex characters for data
            if (dataHex.Length % 2 != 0)
            {
                return Result.Failure<(ushort tag, byte[] data), SmartCardError>(
                    SmartCardError.InvalidArgument("Data must have even number of hex characters"));
            }
        }

        return Result.Try(() => Convert.ToUInt16(tagHex, 16), ex =>
                SmartCardError.InvalidArgument($"Invalid tag format: {ex.Message}"))
            .Bind(parsedTag =>
                Result.Try(() => string.IsNullOrEmpty(dataHex) ? [] : Convert.FromHexString(dataHex), ex =>
                    SmartCardError.InvalidArgument($"Invalid data format: {ex.Message}"))
                .Map(parsedData => (parsedTag, parsedData)));
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
        // Additional validation could be added here based on specific tag requirements
        return Maybe<byte[]>.From(data).HasValue;
    }
}