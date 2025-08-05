using System;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
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
    public static Result<ParsedSecuredCommand, SmartCardError> ParseSecuredCommand(byte[] securedCommand)
    {
        if (securedCommand.Length < 5)
        {
            return Result.Failure<ParsedSecuredCommand, SmartCardError>(
                SmartCardError.InvalidData("Secured command too short"));
        }

        var cla = securedCommand[0];
        var ins = securedCommand[1];
        var p1 = securedCommand[2];
        var p2 = securedCommand[3];
        var lc = securedCommand[4];

        if (securedCommand.Length < 5 + lc)
        {
            return Result.Failure<ParsedSecuredCommand, SmartCardError>(
                SmartCardError.InvalidData("Secured command length inconsistent with Lc"));
        }

        // Extract data field (contains original data + MAC)
        var dataField = new byte[lc];
        Array.Copy(securedCommand, 5, dataField, 0, lc);

        // Parse data field to separate original data from MAC
        byte[] originalData;
        byte[] mac = null;
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
            new ParsedSecuredCommand(cla, ins, p1, p2, originalData, mac, le));
    }

    /// <summary>
    /// Builds MAC input data for command MAC calculation.
    /// Formats input according to protocol-specific requirements.
    /// </summary>
    /// <param name="parsedCommand">The parsed secured command.</param>
    /// <param name="protocolVersion">The SCP protocol version.</param>
    /// <returns>The formatted MAC input data.</returns>
    public static byte[] BuildMacInput(ParsedSecuredCommand parsedCommand, byte protocolVersion)
    {
        if (protocolVersion == ProtocolIdentifiers.Scp03)
        {
            // SCP03 MAC input: fixed CLA (0x84) + INS + P1 + P2 + modified Lc + data
            var macInput = new System.Collections.Generic.List<byte>
            {
                0x84, // Fixed CLA for SCP03 MAC calculation
                parsedCommand.Ins,
                parsedCommand.P1,
                parsedCommand.P2,
                (byte)(parsedCommand.Data.Length + 8) // Modified Lc for MAC calculation
            };
            macInput.AddRange(parsedCommand.Data);
            return macInput.ToArray();
        }
        else
        {
            // SCP02 MAC input: original CLA + INS + P1 + P2 + modified Lc + data
            var macInput = new System.Collections.Generic.List<byte>
            {
                parsedCommand.Cla,
                parsedCommand.Ins,
                parsedCommand.P1,
                parsedCommand.P2,
                (byte)(parsedCommand.Data.Length + 8) // Modified Lc for MAC calculation
            };
            macInput.AddRange(parsedCommand.Data);
            return macInput.ToArray();
        }
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
    public static byte[] BuildOriginalCommand(byte cla, byte ins, byte p1, byte p2, byte[] data, byte? le)
    {
        var command = new System.Collections.Generic.List<byte> { cla, ins, p1, p2 };
        
        if (data.Length > 0)
        {
            command.Add((byte)data.Length);
            command.AddRange(data);
        }
        
        if (le.HasValue)
        {
            command.Add(le.Value);
        }
        
        return command.ToArray();
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
    byte? Le);