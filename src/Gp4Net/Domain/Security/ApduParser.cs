using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Pure static APDU parsing operations shared across security processors.
/// All functions are stateless and side-effect free.
/// </summary>
[PublicAPI]
public static class ApduParser
{
    /// <summary>
    /// Parses a secured command APDU to extract its components.
    /// Handles both SCP02 and SCP03 command structures.
    /// </summary>
    /// <param name="securedCommand">The secured command bytes to parse.</param>
    /// <returns>Parsed secured command with extracted components, or an error.</returns>
    public static Result<ParsedSecuredCommand, SmartCardError> ParseSecuredCommand(
        byte[] securedCommand
    )
    {
        if (securedCommand.Length < 5)
        {
            return Result.Failure<ParsedSecuredCommand, SmartCardError>(
                SmartCardError.InvalidData("Secured command too short")
            );
        }

        byte cla = securedCommand[0];
        byte ins = securedCommand[1];
        byte p1 = securedCommand[2];
        byte p2 = securedCommand[3];
        byte lc = securedCommand[4];

        if (securedCommand.Length < 5 + lc)
        {
            return Result.Failure<ParsedSecuredCommand, SmartCardError>(
                SmartCardError.InvalidData("Secured command length inconsistent with Lc")
            );
        }

        // Extract data field (contains original data + MAC)
        byte[] dataField = new byte[lc];
        Array.Copy(securedCommand, 5, dataField, 0, lc);

        // Parse data field to separate original data from MAC
        byte[] originalData;
        byte[] mac = Array.Empty<byte>();
        byte? le = null;

        if (lc >= 8) // Minimum MAC size
        {
            // Last 8 bytes are typically the MAC
            mac = new byte[8];
            Array.Copy(dataField, dataField.Length - 8, mac, 0, 8);

            // Remaining bytes are original data
            originalData = new byte[dataField.Length - 8];
            Array.Copy(dataField, 0, originalData, 0, originalData.Length);
        }
        else
        {
            originalData = dataField;
        }

        // Check for Le byte
        if (securedCommand.Length > 5 + lc)
        {
            le = securedCommand[5 + lc];
        }

        return Result.Success<ParsedSecuredCommand, SmartCardError>(
            new ParsedSecuredCommand(cla, ins, p1, p2, originalData, mac, le)
        );
    }

    /// <summary>
    /// Builds an original (unprotected) command APDU from parsed components.
    /// Reconstructs the command in standard APDU format.
    /// </summary>
    /// <param name="cla">The class byte.</param>
    /// <param name="ins">The instruction byte.</param>
    /// <param name="p1">The P1 parameter byte.</param>
    /// <param name="p2">The P2 parameter byte.</param>
    /// <param name="data">The command data.</param>
    /// <param name="le">The expected response length (optional).</param>
    /// <returns>The reconstructed original command bytes.</returns>
    public static Result<byte[], SmartCardError> BuildOriginalCommand(
        byte cla,
        byte ins,
        byte p1,
        byte p2,
        byte[] data,
        Maybe<byte> le
    )
    {
        ArgumentNullException.ThrowIfNull(data);

        var expectedLength = le.Map(value => (int)value);
        return ApduBuilder
            .CreateCommand(cla, ins, p1, p2, Maybe<byte[]>.From(data), expectedLength)
            .Map(cmd => cmd.ToBytes());
    }
}

/// <summary>
/// Represents a parsed secured command with extracted components.
/// Immutable data structure for secure command parsing results.
/// </summary>
/// <param name="Cla">The class byte (may be modified for secure messaging).</param>
/// <param name="Ins">The instruction byte.</param>
/// <param name="P1">The P1 parameter byte.</param>
/// <param name="P2">The P2 parameter byte.</param>
/// <param name="Data">The original command data (without MAC).</param>
/// <param name="Mac">The MAC bytes if present.</param>
/// <param name="Le">The expected response length if present.</param>
[PublicAPI]
public readonly record struct ParsedSecuredCommand(
    byte Cla,
    byte Ins,
    byte P1,
    byte P2,
    byte[] Data,
    byte[] Mac,
    byte? Le
);
