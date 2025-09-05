using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.CardEmulator.Domain;

/// <summary>
/// Represents a parsed APDU command with its components.
/// </summary>
/// <param name="Cla">Command class byte.</param>
/// <param name="Ins">Instruction byte.</param>
/// <param name="P1">Parameter 1.</param>
/// <param name="P2">Parameter 2.</param>
/// <param name="FullCommand">Complete command bytes including header and data.</param>
public record ParsedCommand(byte Cla, byte Ins, byte P1, byte P2, byte[] FullCommand)
{
    /// <summary>
    /// Gets the data portion of the APDU command.
    /// Handles both short and extended APDUs according to ISO 7816-4.
    /// </summary>
    public byte[] Data 
    {
        get
        {
            if (FullCommand.Length <= 4)
                return Array.Empty<byte>();
            
            if (FullCommand.Length == 5)
                return Array.Empty<byte>(); // Case 2: CLA INS P1 P2 Le
                
            // Check for extended APDU (first byte of Lc is 0x00)
            if (FullCommand[4] == 0x00 && FullCommand.Length >= 7)
            {
                // Extended APDU: CLA INS P1 P2 00 Lc1 Lc2 [data]
                int dataLength = (FullCommand[5] << 8) | FullCommand[6];
                if (FullCommand.Length >= 7 + dataLength)
                    return FullCommand[7..(7 + dataLength)];
            }
            else
            {
                // Short APDU: CLA INS P1 P2 Lc [data]
                int lc = FullCommand[4];
                if (FullCommand.Length >= 5 + lc)
                    return FullCommand[5..(5 + lc)];
            }
            
            return Array.Empty<byte>();
        }
    }
    
    /// <summary>
    /// Parses raw command bytes into a structured ParsedCommand.
    /// </summary>
    /// <param name="command">Raw command bytes to parse.</param>
    /// <returns>Parsed command if valid, or error message.</returns>
    public static Result<ParsedCommand> Parse(byte[] command)
    {
        if (command.Length < 4)
        {
            return Result.Failure<ParsedCommand>("Command must be at least 4 bytes");
        }
        
        return Result.Success(new ParsedCommand(
            Cla: command[0],
            Ins: command[1],
            P1: command[2],
            P2: command[3],
            FullCommand: command
        ));
    }
}