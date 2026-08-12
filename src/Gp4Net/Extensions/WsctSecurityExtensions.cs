using System;
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
    /// <param name="modifyHeader">Uses the modified-APDU method from GP Card Specification v2.3.1 Appendix E.4.4.</param>
    /// <returns>A MacInput record containing the bytes for MAC calculation and extracted components.</returns>
    public static Result<MacInput, SmartCardError> GetMacInput(
        this CommandAPDU command,
        int macSize = 8,
        bool modifyHeader = true
    )
    {
        return Maybe<CommandAPDU>
            .From(command)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Bind(cmd => ExtractMacInputInternal(cmd, macSize, modifyHeader));
    }

    private static Result<MacInput, SmartCardError> ExtractMacInputInternal(
        CommandAPDU command,
        int macSize,
        bool modifyHeader
    )
    {
        var isSecured = (command.Cla & 0x04) != 0;

        // Get the binary representation (WSCT handles all encoding complexity)
        var fullCommand = command.BinaryCommand;

        return Maybe<byte[]>
            .From(fullCommand)
            .Where(bytes => bytes.Length >= 4)
            .ToResult(SmartCardError.InvalidData("Invalid command structure"))
            .Bind(_ => BuildMacInput(command, isSecured, macSize, modifyHeader));
    }

    private static Result<MacInput, SmartCardError> BuildMacInput(
        CommandAPDU command,
        bool isSecured,
        int macSize,
        bool modifyHeader
    )
    {
        var udc = Maybe<byte[]>.From(command.Udc);

        if (isSecured)
        {
            return udc.Where(data => data.Length >= macSize)
                .Match(
                    Some: data => ExtractSecuredMacInput(command, data, macSize),
                    None: () => BuildUnsecuredMacInput(command, udc, macSize, modifyHeader)
                );
        }

        return BuildUnsecuredMacInput(command, udc, macSize, modifyHeader);
    }

    private static Result<MacInput, SmartCardError> ExtractSecuredMacInput(
        CommandAPDU command,
        byte[] udcData,
        int macSize
    )
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

        // GP Card Spec 2.3.1, E.4.4 and SCP03 1.1.2, 6.2.4: clear the
        // logical-channel bits and set the secure-messaging indication.
        bool isSecured = (command.Cla & 0x04) != 0;
        macInputBytes[0] = isSecured
            ? (byte)((command.Cla & 0xF0) | 0x04)
            : (byte)(command.Cla & 0xF0);

        // Update Lc value if needed to reflect plaintext data size
        int secureLc = plaintextData.Length + macSize;
        if (secureLc < macSize)
        {
            secureLc = macSize;
        }

        if (dataStartPos == headerSize + 1)
        {
            // Short Lc - update with plaintext length plus MAC
            macInputBytes[headerSize] = (byte)secureLc;
        }
        else if (dataStartPos == headerSize + 3)
        {
            // Extended Lc - update with plaintext length plus MAC
            macInputBytes[headerSize] = 0x00;
            macInputBytes[headerSize + 1] = (byte)(secureLc >> 8);
            macInputBytes[headerSize + 2] = (byte)(secureLc & 0xFF);
        }

        // Copy plaintext data
        if (plaintextData.Length > 0)
        {
            Array.Copy(plaintextData, 0, macInputBytes, dataStartPos, plaintextData.Length);
        }

        return Result.Success<MacInput, SmartCardError>(
            new MacInput(macInputBytes, extractedMac, plaintextData)
        );
    }

    private static Result<MacInput, SmartCardError> BuildUnsecuredMacInput(
        CommandAPDU command,
        Maybe<byte[]> udc,
        int macSize,
        bool modifyHeader
    )
    {
        var udcData = udc.GetValueOrDefault([]);
        int dataLength = udcData.Length;
        int macInputLc = modifyHeader ? dataLength + macSize : dataLength;

        bool requiresExtendedLc =
            macInputLc > byte.MaxValue
            || (command.BinaryCommand.Length > 5 && command.BinaryCommand[4] == 0x00);

        int headerSize = requiresExtendedLc ? 4 + 3 : 4 + (macInputLc > 0 ? 1 : 0);
        int totalSize = headerSize + dataLength;
        var macInputBytes = new byte[totalSize];

        int offset = 0;
        // GP Card Specification v2.3.1, Appendix E.4.4; SCP03 Amendment D v1.2, section 6.2.4.
        macInputBytes[offset++] = (byte)((command.Cla & 0xF0) | (modifyHeader ? 0x04 : 0x00));
        macInputBytes[offset++] = command.Ins;
        macInputBytes[offset++] = command.P1;
        macInputBytes[offset++] = command.P2;

        if (macInputLc > 0)
        {
            if (requiresExtendedLc)
            {
                macInputBytes[offset++] = 0x00;
                macInputBytes[offset++] = (byte)(macInputLc >> 8);
                macInputBytes[offset++] = (byte)(macInputLc & 0xFF);
            }
            else
            {
                macInputBytes[offset++] = (byte)macInputLc;
            }
        }

        if (dataLength > 0)
        {
            Array.Copy(udcData, 0, macInputBytes, offset, dataLength);
        }

        return Result.Success<MacInput, SmartCardError>(new MacInput(macInputBytes, [], udcData));
    }

    /// <summary>
    /// Creates a secured CommandAPDU by appending a MAC to the data field.
    /// </summary>
    /// <param name="plaintext">The plaintext command to secure.</param>
    /// <param name="mac">The calculated MAC to append.</param>
    /// <returns>A new CommandAPDU with the MAC appended and secure messaging bit set.</returns>
    public static Result<CommandAPDU, SmartCardError> WithMac(
        this CommandAPDU plaintext,
        byte[] mac
    )
    {
        return Maybe<CommandAPDU>
            .From(plaintext)
            .ToResult(SmartCardError.InvalidArgument("Plaintext command cannot be null"))
            .Bind(cmd =>
                Maybe<byte[]>
                    .From(mac)
                    .Where(m => m.Length > 0)
                    .ToResult(SmartCardError.InvalidArgument("MAC cannot be null or empty"))
                    .Bind(m => ApplyMacInternal(cmd, m))
            );
    }

    private static Result<CommandAPDU, SmartCardError> ApplyMacInternal(
        CommandAPDU plaintext,
        byte[] mac
    )
    {
        var plaintextData = Maybe<byte[]>.From(plaintext.Udc).GetValueOrDefault([]);

        // Append MAC to existing data
        var securedData = new byte[plaintextData.Length + mac.Length];

        if (plaintextData.Length > 0)
            Array.Copy(plaintextData, 0, securedData, 0, plaintextData.Length);
        Array.Copy(mac, 0, securedData, plaintextData.Length, mac.Length);

        // Preserve a case-3 command as case 3. WSCT's object initializer turns
        // Le=0 into an explicit trailing 00 even when the original APDU had no Le.
        // SCP03 1.1.2, 6.2.4 appends C-MAC to the command data; it does not add Le.
        // ISO/IEC 7816-4 command cases: a five-byte command with no data is
        // case 2 (Le present), while case 1 is four bytes and case 3 has Lc+data.
        bool hasLe =
            plaintextData.Length == 0
                ? plaintext.BinaryCommand.Length == 5
                : plaintext.BinaryCommand.Length > 5 + plaintextData.Length;
        if (!hasLe)
        {
            byte[] bytes =
            [
                (byte)(plaintext.Cla | 0x04),
                plaintext.Ins,
                plaintext.P1,
                plaintext.P2,
                (byte)securedData.Length,
                .. securedData,
            ];
            return Result.Success<CommandAPDU, SmartCardError>(new CommandAPDU(bytes));
        }

        var secured = new CommandAPDU
        {
            Cla = (byte)(plaintext.Cla | 0x04), // Set secure messaging bit
            Ins = plaintext.Ins,
            P1 = plaintext.P1,
            P2 = plaintext.P2,
            Udc = securedData,
            Le = plaintext.Le,
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
        int macSize = 8
    )
    {
        return Maybe<CommandAPDU>
            .From(secured)
            .ToResult(SmartCardError.InvalidArgument("Secured command cannot be null"))
            .Bind(cmd => RemoveMacInternal(cmd, macSize));
    }

    private static Result<CommandAPDU, SmartCardError> RemoveMacInternal(
        CommandAPDU secured,
        int macSize
    )
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
            Udc = plaintextData,
        };

        return Result.Success<CommandAPDU, SmartCardError>(plaintext);
    }
}
