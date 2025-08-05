using System;
using System.Collections.Generic;
using CSharpFunctionalExtensions;
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
    /// <exception cref="ArgumentNullException">Thrown when command is null.</exception>
    public static byte[] BuildApdu(IApduCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);

        var apduBytes = new List<byte> { command.Cla, command.Ins, command.P1, command.P2 };

        var hasData = command.Data is { Length: > 0 };
        var hasExpectedLength = command.ExpectedResponseLength.HasValue;

        if (hasData)
        {
            // Add Lc (data length)
            if (command.IsExtendedLength && command.Data!.Length > 255)
            {
                // Extended length format
                apduBytes.Add(0x00);
                apduBytes.Add((byte)(command.Data.Length >> 8));
                apduBytes.Add((byte)(command.Data.Length & 0xFF));
            }
            else
            {
                // Short length format
                apduBytes.Add((byte)command.Data!.Length);
            }
            
            // Add data
            apduBytes.AddRange(command.Data);
        }

        if (hasExpectedLength)
        {
            var expectedLength = command.ExpectedResponseLength.Value;
            
            if (command.IsExtendedLength && expectedLength > 255)
            {
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
                // Short length format
                // 0 means maximum response (256 bytes)
                apduBytes.Add(expectedLength == 0 || expectedLength == 256 ? (byte)0x00 : (byte)expectedLength);
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
    /// <param name="data">Optional data.</param>
    /// <param name="le">Optional expected response length.</param>
    /// <returns>The APDU byte array.</returns>
    public static byte[] BuildApdu(byte cla, byte ins, byte p1, byte p2, byte[] data = null, Maybe<int> le = default)
    {
        var command = new SimpleApduCommand(cla, ins, p1, p2, data, le);
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
                return Data is { Length: > 255 } || ExpectedResponseLength.Map(len => len > 255).GetValueOrDefault(false);
            }
        }

        public SimpleApduCommand(byte cla, byte ins, byte p1, byte p2, byte[] data, Maybe<int> le)
        {
            Cla = cla;
            Ins = ins;
            P1 = p1;
            P2 = p2;
            Data = data ?? Array.Empty<byte>();
            ExpectedResponseLength = le;
        }
    }
}