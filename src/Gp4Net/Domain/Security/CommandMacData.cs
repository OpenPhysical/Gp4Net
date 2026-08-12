using System;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using WSCT.ISO7816;
using static Gp4Net.Cryptography.CryptoService;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Immutable data structure representing the bytes needed for MAC calculation on a command APDU.
/// This type enforces that valid cryptographic keys and session state exist before MAC calculation can proceed.
/// </summary>
/// <remarks>
/// This type implements the "make invalid states unrepresentable" principle by requiring
/// proof of a valid secure channel session at construction time. You cannot create an instance
/// without having established a secure channel with MAC capabilities enabled.
/// </remarks>
[PublicAPI]
public sealed record CommandMacData
{
    /// <summary>
    /// The bytes to use for MAC calculation (CLA|INS|P1|P2|Lc|Data without MAC or Le).
    /// </summary>
    public ImmutableArray<byte> CalculationBytes { get; }

    /// <summary>
    /// The validated session keys from the secure channel establishment.
    /// Presence of this field proves that key derivation was successful.
    /// </summary>
    public SessionKeys ValidatedKeys { get; }

    /// <summary>
    /// The current MAC chaining state for continuous MAC calculation.
    /// </summary>
    public MacChainingState ChainState { get; }

    /// <summary>
    /// The protocol version for MAC calculation (SCP02 or SCP03).
    /// </summary>
    public ScpVersion ProtocolVersion { get; }

    /// <summary>
    /// Private constructor ensures validation through factory method.
    /// </summary>
    private CommandMacData(
        ImmutableArray<byte> calculationBytes,
        SessionKeys keys,
        MacChainingState chainState,
        ScpVersion protocolVersion
    )
    {
        CalculationBytes = calculationBytes;
        ValidatedKeys = keys;
        ChainState = chainState;
        ProtocolVersion = protocolVersion;
    }

    /// <summary>
    /// Creates CommandMacData from a command APDU and validated secure channel session.
    /// </summary>
    /// <param name="command">The command APDU to extract MAC calculation bytes from.</param>
    /// <param name="validSession">A valid secure channel session with C-MAC enabled.</param>
    /// <returns>Success with CommandMacData if session has C-MAC, failure otherwise.</returns>
    public static Result<CommandMacData, SmartCardError> Create(
        CommandAPDU command,
        SecureChannelState validSession
    )
    {
        return Maybe<CommandAPDU>
            .From(command)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Bind(_ =>
                Maybe<SecureChannelState>
                    .From(validSession)
                    .ToResult(SmartCardError.InvalidArgument("Session state cannot be null"))
            )
            .Bind(session =>
                session.SecurityLevel.HasCMac()
                    ? Result.Success<SecureChannelState, SmartCardError>(session)
                    : Result.Failure<SecureChannelState, SmartCardError>(
                        SmartCardError.SecurityError("C-MAC not enabled in current session")
                    )
            )
            .Bind(session => ExtractMacCalculationBytes(command, session))
            .Map(bytes => new CommandMacData(
                [.. bytes],
                validSession.SessionKeys,
                validSession.MacChaining,
                validSession.ProtocolVersion
            ));
    }

    /// <summary>
    /// Extracts the bytes needed for MAC calculation from a command APDU.
    /// </summary>
    private static Result<byte[], SmartCardError> ExtractMacCalculationBytes(
        CommandAPDU command,
        SecureChannelState session
    )
    {
        var binaryCommand = command.BinaryCommand;
        var isSecured = (command.Cla & 0x04) != 0;

        if (isSecured)
        {
            // For secured commands, we need to remove the MAC from Udc
            var udc = command.Udc ?? [];
            var macSize = session.ProtocolVersion == ScpVersion.Scp03 ? 8 : 8; // Both use 8-byte MACs

            if (udc.Length >= macSize)
            {
                // Extract data portion (Udc without MAC)
                var dataWithoutMac = new byte[udc.Length - macSize];
                if (dataWithoutMac.Length > 0)
                {
                    Array.Copy(udc, 0, dataWithoutMac, 0, dataWithoutMac.Length);
                }

                // If C-DECRYPTION is enabled (SCP02) or C-ENC (SCP03), decrypt data before MAC verification.
                var dataForMac = dataWithoutMac;
                if (
                    session.ProtocolVersion == ScpVersion.Scp02
                    && session.SecurityLevel.HasCDecryption()
                )
                {
                    var decryptResult = DecryptScp02CommandData(
                        binaryCommand,
                        dataWithoutMac,
                        macSize,
                        session
                    );

                    if (decryptResult.IsFailure)
                        return decryptResult.Error;

                    dataForMac = decryptResult.Value;
                }

                // Rebuild MAC input with plaintext data
                return RebuildMacInput(command, dataForMac, binaryCommand, macSize, session);
            }
        }

        // For unsecured commands, remove Le if present
        return RemoveLeFromCommand(command, binaryCommand);
    }

    private static Result<byte[], SmartCardError> RebuildMacInput(
        CommandAPDU command,
        byte[] plaintextData,
        byte[] binaryCommand,
        int macSize,
        SecureChannelState session
    )
    {
        var headerSize = 4; // CLA|INS|P1|P2
        var dataStartPos = headerSize;
        var usesExtendedLc = false;

        // Determine Lc encoding size
        if (binaryCommand.Length > headerSize)
        {
            var lcByte = binaryCommand[headerSize];
            if (lcByte == 0x00 && binaryCommand.Length > headerSize + 2)
            {
                usesExtendedLc = true;
                dataStartPos += 3; // Extended Lc: 00|XX|XX
            }
            else
            {
                dataStartPos += 1; // Short Lc
            }
        }

        // Build MAC input bytes
        var macInputSize = dataStartPos + plaintextData.Length;
        var macInputBytes = new byte[macInputSize];

        // Copy header and Lc
        Array.Copy(binaryCommand, 0, macInputBytes, 0, dataStartPos);

        // GP Card Specification v2.3.1, section E.4.4; SCP03 Amendment D
        // v1.1.2, section 6.2.4.
        bool isSecured = (command.Cla & 0x04) != 0;
        macInputBytes[0] = isSecured
            ? (byte)((command.Cla & 0xF0) | 0x04)
            : (byte)(command.Cla & 0xF0);

        // Lc must include MAC length per GP spec (E.4.3, note 5).
        var secureLc = plaintextData.Length + macSize;
        if (secureLc < macSize)
        {
            secureLc = macSize;
        }
        if (usesExtendedLc)
        {
            macInputBytes[headerSize] = 0x00;
            macInputBytes[headerSize + 1] = (byte)(secureLc >> 8);
            macInputBytes[headerSize + 2] = (byte)(secureLc & 0xFF);
        }
        else
        {
            macInputBytes[headerSize] = (byte)secureLc;
        }

        // Copy plaintext data
        if (plaintextData.Length > 0)
        {
            Array.Copy(plaintextData, 0, macInputBytes, dataStartPos, plaintextData.Length);
        }

        return Result.Success<byte[], SmartCardError>(macInputBytes);
    }

    private static Result<byte[], SmartCardError> DecryptScp02CommandData(
        byte[] originalCommand,
        byte[] dataWithoutMac,
        int macSize,
        SecureChannelState session
    )
    {
        var commandWithoutMac = BuildCommandWithoutMac(originalCommand, dataWithoutMac, macSize);

        return CryptoService
            .ScpOperations.Scp02.RemoveCommandEncryption(
                commandWithoutMac,
                session.SessionKeys.SEnc
            )
            .Bind(ExtractPlaintextDataSegment);
    }

    private static Result<byte[], SmartCardError> DecryptScp03CommandData(
        byte[] originalCommand,
        byte[] dataWithoutMac,
        int macSize,
        SecureChannelState session
    )
    {
        var commandWithoutMac = BuildCommandWithoutMac(originalCommand, dataWithoutMac, macSize);

        return CryptoService
            .ScpOperations.Scp03.RemoveCommandEncryption(
                commandWithoutMac,
                session.SessionKeys.SEnc,
                session.EncryptionCounter
            )
            .Bind(ExtractPlaintextDataSegment);
    }

    private static byte[] BuildCommandWithoutMac(
        byte[] originalCommand,
        byte[] dataWithoutMac,
        int macSize
    )
    {
        var commandLengthWithoutMac = originalCommand.Length - macSize;
        var result = new byte[commandLengthWithoutMac];

        const int headerSize = 4;
        Array.Copy(originalCommand, 0, result, 0, headerSize);

        bool usesExtendedLc =
            originalCommand.Length > headerSize
            && originalCommand[headerSize] == 0x00
            && originalCommand.Length > headerSize + 2;

        int lcSize = usesExtendedLc ? 3 : 1;

        if (usesExtendedLc)
        {
            int plaintextLength = dataWithoutMac.Length;
            result[headerSize] = 0x00;
            result[headerSize + 1] = (byte)(plaintextLength >> 8);
            result[headerSize + 2] = (byte)(plaintextLength & 0xFF);
        }
        else
        {
            result[headerSize] = (byte)dataWithoutMac.Length;
        }

        int dataStart = headerSize + lcSize;
        Array.Copy(dataWithoutMac, 0, result, dataStart, dataWithoutMac.Length);

        int leLength = commandLengthWithoutMac - (dataStart + dataWithoutMac.Length);
        if (leLength > 0)
        {
            Array.Copy(
                originalCommand,
                originalCommand.Length - leLength,
                result,
                dataStart + dataWithoutMac.Length,
                leLength
            );
        }

        return result;
    }

    private static Result<byte[], SmartCardError> ExtractPlaintextDataSegment(byte[] command)
    {
        const int headerSize = 4;
        if (command.Length <= headerSize)
            return Result.Success<byte[], SmartCardError>(Array.Empty<byte>());

        bool usesExtendedLc = command[headerSize] == 0x00 && command.Length > headerSize + 2;

        int lcSize = usesExtendedLc ? 3 : 1;
        int dataStart = headerSize + lcSize;
        int dataLength = usesExtendedLc
            ? (command[headerSize + 1] << 8) | command[headerSize + 2]
            : command[headerSize];

        if (dataLength < 0 || dataStart + dataLength > command.Length)
        {
            return SmartCardError.InvalidData("Invalid decrypted command structure");
        }

        byte[] plaintext = new byte[dataLength];
        Array.Copy(command, dataStart, plaintext, 0, dataLength);
        return Result.Success<byte[], SmartCardError>(plaintext);
    }

    private static Result<byte[], SmartCardError> RemoveLeFromCommand(
        CommandAPDU command,
        byte[] binaryCommand
    )
    {
        // For MAC calculation, we need CLA|INS|P1|P2|Lc|Data (no Le)
        var macInputBytes = binaryCommand;

        var leMaybe = Maybe<uint>.From(command.Le);
        if (leMaybe.HasValue)
        {
            var headerSize = 4;
            var udc = command.Udc ?? [];
            var dataSize = udc.Length;

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

        return Result.Success<byte[], SmartCardError>(macInputBytes);
    }
}
