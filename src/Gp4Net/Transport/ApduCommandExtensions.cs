using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;
using WSCT.ISO7816;

namespace Gp4Net.Transport;

/// <summary>
/// Extension methods for APDU commands.
/// </summary>
[PublicAPI]
public static class ApduCommandExtensions
{
    /// <summary>
    /// Converts a CommandAPDU to a byte array with functional error handling.
    /// </summary>
    /// <param name="command">The command to convert.</param>
    /// <returns>A result containing the APDU as a byte array or an error.</returns>
    public static Result<byte[], SmartCardError> ToApdu(this Maybe<CommandAPDU> command)
    {
        return command
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Map(cmd => cmd.ToBytes());
    }

    /// <summary>
    /// Converts a CommandAPDU to a byte array with functional error handling (convenience overload).
    /// </summary>
    /// <param name="command">The command to convert.</param>
    /// <returns>A result containing the APDU as a byte array or an error.</returns>
    public static Result<byte[], SmartCardError> ToApdu(this CommandAPDU command)
    {
        return Maybe<CommandAPDU>.From(command).ToApdu();
    }
}
