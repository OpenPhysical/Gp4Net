using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using JetBrains.Annotations;
using WSCT.ISO7816;

namespace Gp4Net.Transport;

/// <summary>
/// Utility class for creating WSCT CommandAPDU instances.
/// Follows ISO 7816-4 APDU structure.
/// </summary>
[PublicAPI]
public static class ApduBuilder
{
    /// <summary>
    /// Creates a CommandAPDU from explicit parameters.
    /// </summary>
    /// <param name="cla">Class byte.</param>
    /// <param name="ins">Instruction byte.</param>
    /// <param name="p1">Parameter 1.</param>
    /// <param name="p2">Parameter 2.</param>
    /// <param name="data">Command data.</param>
    /// <param name="le">Expected response length.</param>
    /// <returns>A result containing the CommandAPDU or an error.</returns>
    public static Result<CommandAPDU, SmartCardError> CreateCommand(
        byte cla,
        byte ins,
        byte p1,
        byte p2,
        Maybe<byte[]> data = default,
        Maybe<int> le = default
    )
    {
        return BuildApduBytes(cla, ins, p1, p2, data, le).Map(bytes => new CommandAPDU(bytes));
    }

    /// <summary>
    /// Builds an APDU byte array with explicit parameters.
    /// </summary>
    internal static Result<byte[], SmartCardError> BuildApduBytes(
        byte cla,
        byte ins,
        byte p1,
        byte p2,
        Maybe<byte[]> data = default,
        Maybe<int> le = default
    )
    {
        var builder = ImmutableArray.CreateBuilder<byte>();
        builder.Add(cla);
        builder.Add(ins);
        builder.Add(p1);
        builder.Add(p2);

        byte[] commandData = data.GetValueOrDefault([]);
        bool hasData = commandData.Length > 0;
        bool hasExpectedLength = le.HasValue;

        if (hasData)
        {
            var dataResult = AppendDataBytes(builder, commandData, le);
            if (dataResult.IsFailure)
                return dataResult;
        }

        if (hasExpectedLength)
        {
            return le.Match(
                expectedLength => AppendLengthBytes(builder, commandData, expectedLength),
                () => Result.Success<byte[], SmartCardError>(builder.ToArray())
            );
        }

        return Result.Success<byte[], SmartCardError>(builder.ToArray());
    }

    private static Result<byte[], SmartCardError> AppendDataBytes(
        ImmutableArray<byte>.Builder builder,
        byte[] commandData,
        Maybe<int> le
    )
    {
        // Security check: Validate data length against APDU limits
        int dataLength = commandData.Length;
        if (dataLength > Apdu.Formats.MAX_APDU_DATA_LENGTH)
        {
            return SmartCardError.InvalidArgument(
                $"Data length ({dataLength}) exceeds maximum APDU data length ({Apdu.Formats.MAX_APDU_DATA_LENGTH})"
            );
        }

        bool isExtendedLength =
            dataLength > 255 || le.Map(len => len > 255).GetValueOrDefault(false);

        // Add Lc (data length)
        if (isExtendedLength && dataLength > 255)
        {
            // Security check: Ensure length fits in 16 bits for extended format
            if (dataLength > 65535)
            {
                return SmartCardError.InvalidArgument(
                    $"Extended APDU data length ({dataLength}) exceeds 16-bit limit (65535)"
                );
            }

            // Extended length format
            builder.Add(0x00);
            builder.Add((byte)(dataLength >> 8));
            builder.Add((byte)(dataLength & 0xFF));
        }
        else
        {
            // Security check: Ensure length fits in byte for short format
            if (dataLength > 255)
            {
                return SmartCardError.InvalidArgument(
                    $"Short APDU data length ({dataLength}) exceeds byte limit (255)"
                );
            }

            // Short length format
            builder.Add((byte)dataLength);
        }

        // Add data
        builder.AddRange(commandData);

        return Result.Success<byte[], SmartCardError>(builder.ToArray());
    }

    private static Result<byte[], SmartCardError> AppendLengthBytes(
        ImmutableArray<byte>.Builder builder,
        byte[] commandData,
        int expectedLength
    )
    {
        bool isExtendedLength = commandData.Length > 255 || expectedLength > 256;
        bool hasData = commandData.Length > 0;

        // Security check: Validate expected response length
        if (expectedLength > Apdu.Formats.MAX_EXTENDED_LENGTH)
        {
            return SmartCardError.InvalidArgument(
                $"Expected response length ({expectedLength}) exceeds maximum ({Apdu.Formats.MAX_EXTENDED_LENGTH})"
            );
        }

        if (isExtendedLength && expectedLength > 255)
        {
            // Security check: Ensure length fits in 16 bits for extended format
            if (expectedLength > 65535)
            {
                return SmartCardError.InvalidArgument(
                    $"Extended APDU expected length ({expectedLength}) exceeds 16-bit limit (65535)"
                );
            }

            // Extended length format
            if (!hasData)
            {
                // Need to add 00 prefix for extended length when no data
                builder.Add(0x00);
            }

            builder.Add((byte)(expectedLength >> 8));
            builder.Add((byte)(expectedLength & 0xFF));
        }
        else
        {
            // Security check: Ensure length fits in short format
            if (expectedLength > 256)
            {
                return SmartCardError.InvalidArgument(
                    $"Short APDU expected length ({expectedLength}) exceeds limit (256)"
                );
            }

            // Short length format
            // 0 means maximum response (256 bytes)
            builder.Add(expectedLength is 0 or 256 ? (byte)0x00 : (byte)expectedLength);
        }

        return Result.Success<byte[], SmartCardError>(builder.ToArray());
    }

    /// <summary>
    /// Builds APDU bytes from an IApduCommand.
    /// </summary>
    /// <param name="command">The command to build APDU bytes from.</param>
    /// <returns>A result containing the APDU bytes or an error.</returns>
    public static Result<byte[], SmartCardError> BuildApdu(Maybe<IApduCommand> command)
    {
        return command
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Map(cmd => cmd.ToApdu().ToBytes());
    }
}
