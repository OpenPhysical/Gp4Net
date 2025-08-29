using System;
using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using JetBrains.Annotations;

namespace Gp4Net.Transport;

/// <summary>
/// Utility class for building APDU byte arrays from IApduCommand instances.
/// Follows ISO 7816-4 APDU structure.
/// </summary>
[PublicAPI]
public static class ApduBuilder
{
    /// <summary>
    /// Builds an APDU byte array from an IApduCommand instance.
    /// </summary>
    /// <param name="command">The command to convert to APDU bytes.</param>
    /// <returns>The APDU byte array.</returns>
    public static byte[] BuildApdu(IApduCommand command)
    {
        // If the command provides complete APDU bytes, use them directly
        if (command is ICompleteApduCommand completeCommand)
        {
            return completeCommand.GetCompleteApdu();
        }

        List<byte> apduBytes = [command.Cla, command.Ins, command.P1, command.P2];

        bool hasData = command.Data.Length > 0;
        bool hasExpectedLength = command.ExpectedResponseLength.HasValue;

        if (hasData)
        {
            // Security check: Validate data length against APDU limits
            int dataLength = command.Data.Length;
            if (dataLength > ApduConstants.MaxApduDataLength)
            {
                throw new ArgumentException(
                    $"Data length ({dataLength}) exceeds maximum APDU data length ({ApduConstants.MaxApduDataLength})",
                    nameof(command));
            }

            // Add Lc (data length)
            if (command.IsExtendedLength && dataLength > 255)
            {
                // Security check: Ensure length fits in 16 bits for extended format
                if (dataLength > 65535)
                {
                    throw new ArgumentException(
                        $"Extended APDU data length ({dataLength}) exceeds 16-bit limit (65535)",
                        nameof(command));
                }

                // Extended length format
                apduBytes.Add(0x00);
                apduBytes.Add((byte)(dataLength >> 8));
                apduBytes.Add((byte)(dataLength & 0xFF));
            }
            else
            {
                // Security check: Ensure length fits in byte for short format
                if (dataLength > 255)
                {
                    throw new ArgumentException(
                        $"Short APDU data length ({dataLength}) exceeds byte limit (255)",
                        nameof(command));
                }

                // Short length format
                apduBytes.Add((byte)dataLength);
            }

            // Add data
            apduBytes.AddRange(command.Data);
        }

        if (hasExpectedLength)
        {
            int expectedLength = command.ExpectedResponseLength.Value;

            // Security check: Validate expected response length
            if (expectedLength > ApduConstants.MaxExtendedLength)
            {
                throw new ArgumentException(
                    $"Expected response length ({expectedLength}) exceeds maximum ({ApduConstants.MaxExtendedLength})",
                    nameof(command));
            }

            if (command.IsExtendedLength && expectedLength > 255)
            {
                // Security check: Ensure length fits in 16 bits for extended format
                if (expectedLength > 65535)
                {
                    throw new ArgumentException(
                        $"Extended APDU expected length ({expectedLength}) exceeds 16-bit limit (65535)",
                        nameof(command));
                }

                // Extended length format
                if (!hasData)
                {
                    // Need to add 00 prefix for extended length when no data
                    apduBytes.Add(0x00);
                }

                apduBytes.Add((byte)(expectedLength >> 8));
                apduBytes.Add((byte)(expectedLength & 0xFF));
            }
            else
            {
                // Security check: Ensure length fits in short format
                if (expectedLength > 256)
                {
                    throw new ArgumentException(
                        $"Short APDU expected length ({expectedLength}) exceeds limit (256)",
                        nameof(command));
                }

                // Short length format
                // 0 means maximum response (256 bytes)
                apduBytes.Add(expectedLength is 0 or 256 ? (byte)0x00 : (byte)expectedLength);
            }
        }

        return apduBytes.ToArray();
    }

    /// <summary>
    /// Builds an APDU byte array with explicit parameters.
    /// </summary>
    /// <param name="cla">Class byte.</param>
    /// <param name="ins">Instruction byte.</param>
    /// <param name="p1">Parameter 1.</param>
    /// <param name="p2">Parameter 2.</param>
    /// <param name="data">Command data.</param>
    /// <param name="le">Expected response length.</param>
    /// <returns>The APDU byte array.</returns>
    public static byte[] BuildApdu(byte cla, byte ins, byte p1, byte p2, byte[] data = null, Maybe<int> le = default)
    {
        SimpleApduCommand command = new SimpleApduCommand(cla, ins, p1, p2, data, le);
        return BuildApdu(command);
    }

    /// <summary>
    /// Simple implementation of IApduCommand for building APDUs.
    /// </summary>
    private sealed class SimpleApduCommand : IApduCommand
    {
        public byte Cla { get; }
        public byte Ins { get; }
        public byte P1 { get; }
        public byte P2 { get; }
        public byte[] Data { get; }
        public Maybe<int> ExpectedResponseLength { get; }
        public bool IsExtendedLength
        {
            get
            {
                return Data.Length > 255 || ExpectedResponseLength.Map(len => len > 255).GetValueOrDefault(false);
            }
        }

        public SimpleApduCommand(byte cla, byte ins, byte p1, byte p2, byte[] data, Maybe<int> le)
        {
            Cla = cla;
            Ins = ins;
            P1 = p1;
            P2 = p2;
            Data = data ?? [];
            ExpectedResponseLength = le;
        }
    }
}