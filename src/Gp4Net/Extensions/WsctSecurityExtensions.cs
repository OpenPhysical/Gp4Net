using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Security;
using JetBrains.Annotations;
using WSCT.ISO7816;

namespace Gp4Net.Extensions;

/// <summary>
/// Extension methods for WSCT CommandAPDU and ResponseAPDU types to support secure channel operations.
/// These methods provide clean functional interfaces for MAC calculation and command securing.
/// </summary>
[PublicAPI]
public static class WsctSecurityExtensions
{
    /// <summary>
    /// Extracts the bytes needed for MAC calculation from a CommandAPDU.
    /// MAC input consists of CLA|INS|P1|P2|Lc|Data (excluding any MAC if present, never including Le).
    /// </summary>
    /// <param name="command">The command APDU to extract MAC input from.</param>
    /// <param name="macSize">Size of the MAC in bytes (default 8 for SCP02/03).</param>
    /// <returns>A MacInput record containing the bytes for MAC calculation and extracted components.</returns>
    public static Result<MacInput, SmartCardError> GetMacInput(
        this CommandAPDU command,
        int macSize = 8)
    {
        return Maybe<CommandAPDU>
            .From(command)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Bind(cmd => ExtractMacInputInternal(cmd, macSize));
    }

    private static Result<MacInput, SmartCardError> ExtractMacInputInternal(
        CommandAPDU command,
        int macSize)
    {
        var isSecured = (command.Cla & 0x04) != 0;

        // Get the binary representation (WSCT handles all encoding complexity)
        var fullCommand = command.BinaryCommand;

        return Maybe<byte[]>
            .From(fullCommand)
            .Where(bytes => bytes.Length >= 4)
            .ToResult(SmartCardError.InvalidData("Invalid command structure"))
            .Bind(bytes => BuildMacInput(command, isSecured, macSize));
    }

    private static Result<MacInput, SmartCardError> BuildMacInput(
        CommandAPDU command,
        bool isSecured,
        int macSize)
    {
        var udc = Maybe<byte[]>.From(command.Udc);

        if (isSecured)
        {
            return udc
                .Where(data => data.Length >= macSize)
                .Match(
                    Some: data => ExtractSecuredMacInput(command, data, macSize),
                    None: () => BuildUnsecuredMacInput(command, udc)
                );
        }

        return BuildUnsecuredMacInput(command, udc);
    }

    private static Result<MacInput, SmartCardError> ExtractSecuredMacInput(
        CommandAPDU command,
        byte[] udcData,
        int macSize)
    {
        // MAC is the last 'macSize' bytes of Udc
        var extractedMac = new byte[macSize];
        Array.Copy(udcData, udcData.Length - macSize, extractedMac, 0, macSize);

        // Plaintext data is Udc without the MAC
        var plaintextData = new byte[udcData.Length - macSize];
        Array.Copy(udcData, 0, plaintextData, 0, plaintextData.Length);

        // Get the full binary command bytes
        var binaryCommand = command.BinaryCommand;

        // For secured commands, we need to rebuild MAC input with plaintext data
        // MAC input = CLA|INS|P1|P2|Lc|PlaintextData (no MAC, no Le)

        // Find the data section in the binary command
        var headerSize = 4; // CLA|INS|P1|P2
        var dataStartPos = headerSize;

        // Determine Lc encoding size
        if (binaryCommand.Length > headerSize)
        {
            var lcByte = binaryCommand[headerSize];
            if (lcByte == 0x00 && binaryCommand.Length > headerSize + 2)
            {
                // Extended Lc format: 00|XX|XX
                dataStartPos += 3;
            }
            else
            {
                // Short Lc format: single byte
                dataStartPos += 1;
            }
        }

        // Build MAC input bytes with plaintext data
        var macInputSize = dataStartPos + plaintextData.Length;
        var macInputBytes = new byte[macInputSize];

        // Copy header and Lc
        Array.Copy(binaryCommand, 0, macInputBytes, 0, dataStartPos);

        // Update Lc value if needed to reflect plaintext data size
        if (dataStartPos == headerSize + 1)
        {
            // Short Lc - update with plaintext length
            macInputBytes[headerSize] = (byte)plaintextData.Length;
        }
        else if (dataStartPos == headerSize + 3)
        {
            // Extended Lc - update with plaintext length
            macInputBytes[headerSize] = 0x00;
            macInputBytes[headerSize + 1] = (byte)(plaintextData.Length >> 8);
            macInputBytes[headerSize + 2] = (byte)(plaintextData.Length & 0xFF);
        }

        // Copy plaintext data
        if (plaintextData.Length > 0)
        {
            Array.Copy(plaintextData, 0, macInputBytes, dataStartPos, plaintextData.Length);
        }

        return Result.Success<MacInput, SmartCardError>(
            new MacInput(macInputBytes, extractedMac, plaintextData));
    }

    private static Result<MacInput, SmartCardError> BuildUnsecuredMacInput(
        CommandAPDU command,
        Maybe<byte[]> udc)
    {
        var udcData = udc.GetValueOrDefault(Array.Empty<byte>());

        // Get the full binary command
        var binaryCommand = command.BinaryCommand;

        // For MAC calculation, we need CLA|INS|P1|P2|Lc|Data (no Le)
        // Check if Le is present by examining the command structure
        var macInputBytes = binaryCommand;

        // Le is present if command has Le property set
        var le = Maybe<byte>.From((byte)command.Le);
        if (le.HasValue)
        {
            // Find where Le bytes start
            // Structure: Header(4) + Lc(1-3) + Data + Le(1-2)
            var headerSize = 4;
            var dataSize = udcData.Length;

            // Determine Lc size
            var lcSize = 1;
            if (binaryCommand.Length > headerSize && binaryCommand[headerSize] == 0x00)
            {
                lcSize = 3;
            }

            // Calculate where Le starts
            var leStartPos = headerSize + lcSize + dataSize;

            // Copy everything except Le
            if (leStartPos < binaryCommand.Length)
            {
                macInputBytes = new byte[leStartPos];
                Array.Copy(binaryCommand, 0, macInputBytes, 0, leStartPos);
            }
        }

        return Result.Success<MacInput, SmartCardError>(
            new MacInput(macInputBytes, Array.Empty<byte>(), udcData));
    }

    /// <summary>
    /// Creates a secured CommandAPDU by appending a MAC to the data field.
    /// </summary>
    /// <param name="plaintext">The plaintext command to secure.</param>
    /// <param name="mac">The calculated MAC to append.</param>
    /// <returns>A new CommandAPDU with the MAC appended and secure messaging bit set.</returns>
    public static Result<CommandAPDU, SmartCardError> WithMac(
        this CommandAPDU plaintext,
        byte[] mac)
    {
        return Maybe<CommandAPDU>
            .From(plaintext)
            .ToResult(SmartCardError.InvalidArgument("Plaintext command cannot be null"))
            .Bind(cmd => Maybe<byte[]>
                .From(mac)
                .Where(m => m.Length > 0)
                .ToResult(SmartCardError.InvalidArgument("MAC cannot be null or empty"))
                .Bind(m => ApplyMacInternal(cmd, m)));
    }

    private static Result<CommandAPDU, SmartCardError> ApplyMacInternal(
        CommandAPDU plaintext,
        byte[] mac)
    {
        var plaintextData = Maybe<byte[]>
            .From(plaintext.Udc)
            .GetValueOrDefault(Array.Empty<byte>());

        // Append MAC to existing data
        var securedData = new byte[plaintextData.Length + mac.Length];

        if (plaintextData.Length > 0)
            Array.Copy(plaintextData, 0, securedData, 0, plaintextData.Length);
        Array.Copy(mac, 0, securedData, plaintextData.Length, mac.Length);

        // Create secured command with MAC appended
        var secured = new CommandAPDU
        {
            Cla = (byte)(plaintext.Cla | 0x04), // Set secure messaging bit
            Ins = plaintext.Ins,
            P1 = plaintext.P1,
            P2 = plaintext.P2,
            Udc = securedData,
            Le = plaintext.Le  // WSCT preserves and handles Le properly
        };

        return Result.Success<CommandAPDU, SmartCardError>(secured);
    }

    /// <summary>
    /// Extracts the plaintext CommandAPDU from a secured command by removing the MAC and clearing the secure bit.
    /// </summary>
    /// <param name="secured">The secured command containing a MAC.</param>
    /// <param name="macSize">Size of the MAC to remove (default 8 bytes).</param>
    /// <returns>A new CommandAPDU without the MAC and with the secure bit cleared.</returns>
    public static Result<CommandAPDU, SmartCardError> WithoutMac(
        this CommandAPDU secured,
        int macSize = 8)
    {
        return Maybe<CommandAPDU>
            .From(secured)
            .ToResult(SmartCardError.InvalidArgument("Secured command cannot be null"))
            .Bind(cmd => RemoveMacInternal(cmd, macSize));
    }

    private static Result<CommandAPDU, SmartCardError> RemoveMacInternal(
        CommandAPDU secured,
        int macSize)
    {
        // If not secured, return as-is
        if ((secured.Cla & 0x04) == 0)
            return Result.Success<CommandAPDU, SmartCardError>(secured);

        // Extract data without MAC
        var plaintextData = Maybe<byte[]>
            .From(secured.Udc)
            .Where(data => data.Length >= macSize)
            .Map(data =>
            {
                var result = new byte[data.Length - macSize];
                Array.Copy(data, 0, result, 0, result.Length);
                return result;
            })
            .GetValueOrDefault(secured.Udc);

        // Create plaintext command
        var plaintext = new CommandAPDU
        {
            Cla = (byte)(secured.Cla & ~0x04), // Clear secure messaging bit
            Ins = secured.Ins,
            P1 = secured.P1,
            P2 = secured.P2,
            Udc = plaintextData
        };

        return Result.Success<CommandAPDU, SmartCardError>(plaintext);
    }
}
