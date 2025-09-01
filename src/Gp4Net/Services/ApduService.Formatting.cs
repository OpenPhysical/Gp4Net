using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Transport;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Services;

public static partial class ApduService
{
    /// <summary>
    /// APDU formatting operations consolidating ApduBuilder + Extension Methods.
    /// All methods are functionally pure and return Result&lt;T, SmartCardError&gt;.
    /// </summary>
    public static class Formatting
    {
        /// <summary>
        /// Converts an IApduCommand to byte array following ISO 7816-4 format.
        /// Consolidates ApduBuilder.BuildApdu + extension method logic.
        /// </summary>
        /// <param name="command">The command to convert to APDU bytes.</param>
        /// <returns>APDU byte array or error.</returns>
        public static Result<byte[], SmartCardError> ToBytes(IApduCommand command)
        {
            // Validate command is not missing
            return ValidateCommand(command)
                .Bind(cmd => FormatCommandToBytes(cmd));
        }

        /// <summary>
        /// Creates a complete APDU command from individual components.
        /// Replaces multiple builder patterns with single unified method.
        /// </summary>
        /// <param name="cla">Class byte.</param>
        /// <param name="ins">Instruction byte.</param>
        /// <param name="p1">Parameter 1 byte.</param>
        /// <param name="p2">Parameter 2 byte.</param>
        /// <param name="data">Command data (can be empty).</param>
        /// <param name="expectedResponseLength">Expected response length (optional).</param>
        /// <returns>Formatted APDU bytes or error.</returns>
        public static Result<byte[], SmartCardError> CreateApdu(
            byte cla,
            byte ins,
            byte p1,
            byte p2,
            byte[] data,
            Maybe<int> expectedResponseLength = default)
        {
            var command = new UnifiedApduCommand(cla, ins, p1, p2, data, expectedResponseLength);
            return FormatCommandToBytes(command);
        }

        /// <summary>
        /// Adds MAC to existing command for SCP security.
        /// Used in secure channel processing.
        /// </summary>
        /// <param name="originalCommand">Original unsecured command bytes.</param>
        /// <param name="mac">8-byte MAC to append.</param>
        /// <returns>Secured command with MAC appended or error.</returns>
        public static Result<byte[], SmartCardError> AddMac(byte[] originalCommand, byte[] mac)
        {
            if (mac.Length != 8)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("MAC must be exactly 8 bytes"));
            }

            if (originalCommand.Length < 4)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidData("Original command too short"));
            }

            return Result.Try(
                () => originalCommand.Concat(mac).ToArray(),
                ex => SmartCardError.UnexpectedError($"MAC append failed: {ex.Message}")
            );
        }

        /// <summary>
        /// Converts CLA byte to secured class for SCP channels.
        /// Per GP specification, sets bits to indicate secure messaging.
        /// </summary>
        /// <param name="originalCla">Original class byte.</param>
        /// <param name="securityLevel">Security level for CLA modification.</param>
        /// <returns>Modified CLA byte for secure channel.</returns>
        public static byte ConvertToSecuredCla(byte originalCla, SecurityLevel securityLevel)
        {
            // Set secure messaging bits based on security level
            byte securedCla = originalCla;
            
            if (securityLevel.HasCMac())
            {
                securedCla |= 0x04; // Set bit 2 for C-MAC
            }
            
            if ((securityLevel & SecurityLevel.CEncryption) != 0)
            {
                securedCla |= 0x0C; // Set bits 2&3 for C-ENC + C-MAC
            }

            return securedCla;
        }

        /// <summary>
        /// Converts unsecured command to secured command with modified CLA.
        /// Consolidates ApduFactory.ConvertToSecuredCla functionality.
        /// </summary>
        /// <param name="command">Original unsecured command.</param>
        /// <returns>Command with secured CLA byte or error.</returns>
        public static Result<IApduCommand, SmartCardError> ConvertCommandToSecuredCla(IApduCommand command)
        {
            byte securedCla = command.Cla switch
            {
                Apdu.Classes.Standard => GlobalPlatform.Cla.GpStandard,
                GlobalPlatform.Cla.GpStandard => GlobalPlatform.Cla.GpStandard,
                _ => GlobalPlatform.Cla.GpStandard
            };

            return Result.Success<IApduCommand, SmartCardError>(
                new UnifiedApduCommand(
                    securedCla,
                    command.Ins,
                    command.P1,
                    command.P2,
                    command.Data,
                    command.ExpectedResponseLength));
        }

        /// <summary>
        /// Determines if command should use extended length encoding.
        /// Based on ISO 7816-4 extended length rules.
        /// </summary>
        /// <param name="dataLength">Length of command data.</param>
        /// <param name="expectedResponseLength">Expected response length.</param>
        /// <returns>True if extended length should be used.</returns>
        public static bool ShouldUseExtendedLength(int dataLength, Maybe<int> expectedResponseLength)
        {
            return dataLength > 255 || expectedResponseLength.Match(len => len > 255, () => false);
        }

        private static Result<IApduCommand, SmartCardError> ValidateCommand(IApduCommand command)
        {
            if (command.Data.Length > Apdu.Formats.MaxApduDataLength)
            {
                return Result.Failure<IApduCommand, SmartCardError>(
                    SmartCardError.InvalidArgument(
                        $"Data length ({command.Data.Length}) exceeds maximum APDU data length ({Apdu.Formats.MaxApduDataLength})"));
            }

            return Result.Success<IApduCommand, SmartCardError>(command);
        }

        private static Result<byte[], SmartCardError> FormatCommandToBytes(IApduCommand command)
        {
            return Result.Try(() =>
            {
                // If command provides complete APDU bytes, use them directly
                if (command is ICompleteApduCommand completeCommand)
                {
                    return completeCommand.GetCompleteApdu();
                }

                var builder = ImmutableArray.CreateBuilder<byte>();
                builder.Add(command.Cla);
                builder.Add(command.Ins);
                builder.Add(command.P1);
                builder.Add(command.P2);

                bool hasData = command.Data.Length > 0;
                bool hasExpectedLength = command.ExpectedResponseLength.HasValue;

                if (hasData)
                {
                    FormatDataField(builder, command);
                }

                if (hasExpectedLength && !hasData)
                {
                    command.ExpectedResponseLength.Match(
                        expectedLength => FormatExpectedLengthOnly(builder, expectedLength),
                        () => { /* No expected length to format */ }
                    );
                }
                else if (hasExpectedLength && hasData)
                {
                    FormatExpectedLengthWithData(builder, command);
                }

                return builder.ToImmutable().ToArray();
            }, ex => SmartCardError.UnexpectedError($"APDU formatting failed: {ex.Message}"));
        }

        private static void FormatDataField(ImmutableArray<byte>.Builder builder, IApduCommand command)
        {
            int dataLength = command.Data.Length;

            if (command.IsExtendedLength && dataLength > 255)
            {
                // Extended length format: 00 + length high byte + length low byte + data
                builder.Add(0x00);
                builder.Add((byte)(dataLength >> 8));
                builder.Add((byte)(dataLength & 0xFF));
            }
            else
            {
                // Short length format: length + data
                builder.Add((byte)dataLength);
            }

            builder.AddRange(command.Data);
        }

        private static void FormatExpectedLengthOnly(ImmutableArray<byte>.Builder builder, int expectedLength)
        {
            if (expectedLength > 255)
            {
                // Extended format: 00 + length high byte + length low byte
                builder.Add(0x00);
                builder.Add((byte)(expectedLength >> 8));
                builder.Add((byte)(expectedLength & 0xFF));
            }
            else
            {
                // Short format: length byte (0x00 means 256)
                builder.Add(expectedLength == 256 ? (byte)0x00 : (byte)expectedLength);
            }
        }

        private static void FormatExpectedLengthWithData(ImmutableArray<byte>.Builder builder, IApduCommand command)
        {
            command.ExpectedResponseLength.Match(
                expectedLength =>
                {
                    if (command.IsExtendedLength)
                    {
                        // Extended format: length high byte + length low byte
                        builder.Add((byte)(expectedLength >> 8));
                        builder.Add((byte)(expectedLength & 0xFF));
                    }
                    else
                    {
                        // Short format: length byte
                        builder.Add(expectedLength == 256 ? (byte)0x00 : (byte)expectedLength);
                    }
                },
                () => { /* No expected length to format */ }
            );
        }
    }
}