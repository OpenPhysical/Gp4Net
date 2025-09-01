using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Common validation and helper methods for security processors.
/// Eliminates DRY violations by centralizing shared security logic.
/// </summary>
[PublicAPI]
public static class SecurityValidation
{
    /// <summary>
    /// Validates response security processor inputs.
    /// </summary>
    /// <param name="response">The response data to validate.</param>
    /// <param name="sessionKeys">The session keys.</param>
    /// <param name="macChainingValue">The MAC chaining value.</param>
    /// <returns>Success with the response data or failure with error.</returns>
    public static Result<byte[], SmartCardError> ValidateResponseInputs(
        byte[] response,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue
    )
    {
        if (response.Length < 2)
        {
            return SmartCardError.InvalidData("Response must contain at least status word");
        }

        if (macChainingValue.IsDefaultOrEmpty)
        {
            return SmartCardError.InvalidArgument("MAC chaining value cannot be empty");
        }

        return Result.Success<byte[], SmartCardError>(response);
    }

    /// <summary>
    /// Validates command security processor inputs.
    /// </summary>
    /// <param name="command">The command to validate.</param>
    /// <param name="sessionKeys">The session keys.</param>
    /// <param name="macChainingValue">The MAC chaining value.</param>
    /// <returns>Success with the command or failure with error.</returns>
    public static Result<IApduCommand, SmartCardError> ValidateCommandInputs(
        IApduCommand command,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue
    )
    {
        if (macChainingValue.IsDefaultOrEmpty)
        {
            return SmartCardError.InvalidArgument("MAC chaining value cannot be empty");
        }

        return Result.Success<IApduCommand, SmartCardError>(command);
    }

    /// <summary>
    /// Checks if response contains data beyond the status word.
    /// </summary>
    /// <param name="response">The response to check.</param>
    /// <returns>True if response contains data, false otherwise.</returns>
    public static bool HasResponseData(byte[] response)
    {
        return response?.Length > 2;
    }

    /// <summary>
    /// Determines if R-MAC should be added to a response based on status word.
    /// Per GP specification, R-MAC is only applied for success and warning status words.
    /// </summary>
    /// <param name="response">The response to check.</param>
    /// <returns>True if R-MAC should be added, false otherwise.</returns>
    public static bool ShouldAddRMac(byte[] response)
    {
        if (response == null || response.Length < 2)
        {
            return false;
        }

        ushort sw = (ushort)(response[^2] << 8 | response[^1]);

        // Per GP spec: R-MAC only for success and warning status words
        return sw == Gp4Net.Constants.Constants.StatusWords.Legacy.Success || (sw & 0xFF00) == 0x6200 || (sw & 0xFF00) == 0x6300;
    }

    /// <summary>
    /// Checks if a response contains an R-MAC.
    /// </summary>
    /// <param name="response">The response to check.</param>
    /// <returns>True if response contains R-MAC, false otherwise.</returns>
    public static bool HasRMac(byte[] response)
    {
        return response?.Length >= 10; // Minimum: 2 status bytes + 8 MAC bytes
    }
}
