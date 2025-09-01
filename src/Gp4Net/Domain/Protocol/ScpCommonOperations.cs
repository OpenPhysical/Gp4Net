using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Common operations shared between all SCP protocols.
/// All methods are pure static functions with no side effects.
/// </summary>
[PublicAPI]
public static class ScpCommonOperations
{
    /// <summary>
    /// Builds an APDU command from its components.
    /// </summary>
    /// <param name="cla">Class byte.</param>
    /// <param name="ins">Instruction byte.</param>
    /// <param name="p1">Parameter 1.</param>
    /// <param name="p2">Parameter 2.</param>
    /// <param name="data">Command data (optional).</param>
    /// <param name="le">Expected response length (optional).</param>
    /// <returns>The complete APDU command.</returns>
    public static Result<byte[], SmartCardError> BuildApdu(
        byte cla,
        byte ins,
        byte p1,
        byte p2,
        byte[] data = null,
        byte? le = null
    )
    {
        try
        {
            bool hasData = data is { Length: > 0 };
            bool hasLe = le.HasValue;

            // Calculate total length
            int length = 4; // CLA INS P1 P2
            if (hasData)
            {
                length += 1 + data!.Length; // Lc + data
            }
            if (hasLe)
            {
                length += 1; // Le
            }

            byte[] apdu = new byte[length];
            apdu[0] = cla;
            apdu[1] = ins;
            apdu[2] = p1;
            apdu[3] = p2;

            int offset = 4;
            if (hasData)
            {
                apdu[offset++] = (byte)data!.Length; // Lc
                Array.Copy(data, 0, apdu, offset, data.Length);
                offset += data.Length;
            }

            if (hasLe)
            {
                apdu[offset] = le!.Value;
            }

            return Result.Success<byte[], SmartCardError>(apdu);
        }
        catch (Exception ex)
        {
            return SmartCardError.UnexpectedError($"Failed to build APDU: {ex.Message}");
        }
    }

    /// <summary>
    /// Extracts the data section from a command APDU.
    /// </summary>
    /// <param name="command">The command APDU.</param>
    /// <returns>The data section or empty array if no data.</returns>
    public static Result<byte[], SmartCardError> ExtractCommandData(byte[] command)
    {
        if (command == null)
        {
            return SmartCardError.InvalidArgument("Command cannot be null");
        }

        if (command.Length < 5)
        {
            return Result.Success<byte[], SmartCardError>([]);
        }

        byte lc = command[4];
        if (lc == 0)
        {
            return Result.Success<byte[], SmartCardError>([]);
        }

        if (command.Length < 5 + lc)
        {
            return SmartCardError.InvalidData($"Command too short for declared data length {lc}");
        }

        byte[] data = new byte[lc];
        Array.Copy(command, 5, data, 0, lc);
        return Result.Success<byte[], SmartCardError>(data);
    }

    /// <summary>
    /// Extracts the status word from a response.
    /// </summary>
    /// <param name="response">The response including status word.</param>
    /// <returns>The status word.</returns>
    public static Result<ushort, SmartCardError> ExtractStatusWord(byte[] response)
    {
        if (response == null)
        {
            return SmartCardError.InvalidArgument("Response cannot be null");
        }

        if (response.Length < 2)
        {
            return SmartCardError.InvalidData("Response must contain at least status word");
        }

        ushort sw = (ushort)(response[^2] << 8 | response[^1]);
        return Result.Success<ushort, SmartCardError>(sw);
    }

    /// <summary>
    /// Builds MAC input by concatenating chaining value and data.
    /// </summary>
    /// <param name="chainingValue">The current MAC chaining value.</param>
    /// <param name="data">The data to MAC.</param>
    /// <returns>The concatenated MAC input.</returns>
    public static byte[] BuildMacInput(byte[] chainingValue, byte[] data)
    {
        byte[] macInput = new byte[chainingValue.Length + data.Length];
        Array.Copy(chainingValue, 0, macInput, 0, chainingValue.Length);
        Array.Copy(data, 0, macInput, chainingValue.Length, data.Length);
        return macInput;
    }

    /// <summary>
    /// Inserts MAC into a command APDU.
    /// </summary>
    /// <param name="command">The original command.</param>
    /// <param name="mac">The MAC to insert.</param>
    /// <param name="macSize">The size of the MAC.</param>
    /// <returns>The command with MAC appended.</returns>
    public static Result<byte[], SmartCardError> InsertMacInCommand(
        byte[] command,
        byte[] mac,
        int macSize
    )
    {
        if (command == null)
        {
            return SmartCardError.InvalidArgument("Command cannot be null");
        }

        if (mac == null)
        {
            return SmartCardError.InvalidArgument("MAC cannot be null");
        }

        if (mac.Length < macSize)
        {
            return SmartCardError.InvalidArgument($"MAC must be at least {macSize} bytes");
        }

        try
        {
            // Check if command has data
            bool hasData = command.Length > 5 && command[4] > 0;
            bool hasLe = hasData ? command.Length > 5 + command[4] : command.Length > 4;

            // Create new command with MAC
            int newLength = command.Length + macSize;
            byte[] newCommand = new byte[newLength];

            if (hasData)
            {
                // Copy CLA INS P1 P2
                Array.Copy(command, 0, newCommand, 0, 4);

                // Update CLA to include secure messaging bit
                newCommand[0] = SetSecureMessagingBit(command[0]);

                // Update Lc to include MAC
                byte originalLc = command[4];
                newCommand[4] = (byte)(originalLc + macSize);

                // Copy original data
                Array.Copy(command, 5, newCommand, 5, originalLc);

                // Append MAC
                Array.Copy(mac, 0, newCommand, 5 + originalLc, macSize);

                // Copy Le if present
                if (hasLe)
                {
                    newCommand[^1] = command[^1];
                }
            }
            else
            {
                // No data, just header + optional Le
                Array.Copy(command, 0, newCommand, 0, 4);
                newCommand[0] = SetSecureMessagingBit(command[0]);
                newCommand[4] = (byte)macSize; // Lc = MAC size
                Array.Copy(mac, 0, newCommand, 5, macSize);

                if (hasLe)
                {
                    newCommand[^1] = command[^1];
                }
            }

            return Result.Success<byte[], SmartCardError>(newCommand);
        }
        catch (Exception ex)
        {
            return SmartCardError.UnexpectedError($"Failed to insert MAC: {ex.Message}");
        }
    }

    /// <summary>
    /// Extracts MAC from a response before the status word.
    /// </summary>
    /// <param name="response">The response with MAC.</param>
    /// <param name="macSize">The expected MAC size.</param>
    /// <returns>The extracted MAC and response without MAC.</returns>
    public static Result<
        (byte[] mac, byte[] responseWithoutMac),
        SmartCardError
    > ExtractMacFromResponse(byte[] response, int macSize)
    {
        if (response == null)
        {
            return SmartCardError.InvalidArgument("Response cannot be null");
        }

        if (response.Length < 2 + macSize)
        {
            return SmartCardError.InvalidData(
                $"Response too short to contain {macSize}-byte MAC and status word"
            );
        }

        try
        {
            int macOffset = response.Length - 2 - macSize;
            byte[] mac = new byte[macSize];
            Array.Copy(response, macOffset, mac, 0, macSize);

            // Build response without MAC
            byte[] responseWithoutMac = new byte[response.Length - macSize];
            if (macOffset > 0)
            {
                Array.Copy(response, 0, responseWithoutMac, 0, macOffset); // Data before MAC
            }
            Array.Copy(
                response,
                response.Length - 2,
                responseWithoutMac,
                responseWithoutMac.Length - 2,
                2
            ); // Status word

            return Result.Success<(byte[], byte[]), SmartCardError>((mac, responseWithoutMac));
        }
        catch (Exception ex)
        {
            return SmartCardError.UnexpectedError($"Failed to extract MAC: {ex.Message}");
        }
    }

    /// <summary>
    /// Determines if response security should be applied based on status word.
    /// Per GlobalPlatform specification, only success and warning status words get R-MAC/R-ENC.
    /// </summary>
    /// <param name="statusWord">The response status word.</param>
    /// <returns>True if response security should be applied.</returns>
    public static bool ShouldApplyResponseSecurity(ushort statusWord)
    {
        // Apply response security for:
        // - Success (0x9000)
        // - Warnings (0x62xx, 0x63xx)
        return statusWord == 0x9000
            || (statusWord & 0xFF00) == 0x6200
            || (statusWord & 0xFF00) == 0x6300;
    }

    /// <summary>
    /// Checks if a response contains data (more than just status word).
    /// </summary>
    /// <param name="response">The response to check.</param>
    /// <returns>True if response has data.</returns>
    public static bool HasResponseData(byte[] response)
    {
        return response is { Length: > 2 };
    }

    /// <summary>
    /// Sets the secure messaging bit in the CLA byte.
    /// </summary>
    /// <param name="cla">The original CLA byte.</param>
    /// <returns>The CLA byte with secure messaging bit set.</returns>
    public static byte SetSecureMessagingBit(byte cla)
    {
        return (byte)(cla | 0x04);
    }

    /// <summary>
    /// Applies ISO 7816-4 padding to data.
    /// Appends 0x80 followed by zero bytes to reach the target block size.
    /// </summary>
    /// <param name="data">The data to pad.</param>
    /// <param name="blockSize">The block size (8 for 3DES, 16 for AES).</param>
    /// <returns>The padded data.</returns>
    public static Result<byte[], SmartCardError> ApplyIso7816Padding(byte[] data, int blockSize)
    {
        return CryptoService.Utils.ApplyIso7816Padding(data, blockSize);
    }

    /// <summary>
    /// Removes ISO 7816-4 padding from data.
    /// </summary>
    /// <param name="paddedData">The padded data.</param>
    /// <returns>The unpadded data.</returns>
    public static Result<byte[], SmartCardError> RemoveIso7816Padding(byte[] paddedData)
    {
        return CryptoService.Utils.RemoveIso7816Padding(paddedData);
    }

    /// <summary>
    /// Validates a host challenge.
    /// </summary>
    /// <param name="challenge">The host challenge to validate.</param>
    /// <returns>Success if valid, failure otherwise.</returns>
    public static Result ValidateHostChallenge(byte[] challenge)
    {
        if (challenge == null)
        {
            return Result.Failure("Host challenge cannot be null");
        }

        if (challenge.Length != 8)
        {
            return Result.Failure($"Host challenge must be 8 bytes, got {challenge.Length}");
        }

        return Result.Success();
    }

    /// <summary>
    /// Validates a card challenge.
    /// </summary>
    /// <param name="challenge">The card challenge to validate.</param>
    /// <param name="expectedLength">The expected length (6 for SCP02, 8 for SCP03).</param>
    /// <returns>Success if valid, failure otherwise.</returns>
    public static Result ValidateCardChallenge(byte[] challenge, int expectedLength)
    {
        if (challenge == null)
        {
            return Result.Failure("Card challenge cannot be null");
        }

        if (challenge.Length != expectedLength)
        {
            return Result.Failure(
                $"Card challenge must be {expectedLength} bytes, got {challenge.Length}"
            );
        }

        return Result.Success();
    }

    /// <summary>
    /// Validates a sequence counter.
    /// </summary>
    /// <param name="counter">The sequence counter to validate.</param>
    /// <param name="minLength">The minimum required length.</param>
    /// <returns>Success if valid, failure otherwise.</returns>
    public static Result ValidateSequenceCounter(byte[] counter, int minLength)
    {
        if (counter == null)
        {
            return Result.Failure("Sequence counter cannot be null");
        }

        if (counter.Length < minLength)
        {
            return Result.Failure(
                $"Sequence counter must be at least {minLength} bytes, got {counter.Length}"
            );
        }

        return Result.Success();
    }
}
