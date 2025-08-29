using System.Collections.Generic;
using JetBrains.Annotations;

namespace Gp4Net.Transport;

/// <summary>
/// Extension methods for APDU commands.
/// </summary>
[PublicAPI]
public static class ApduCommandExtensions
{
    /// <summary>
    /// Converts an APDU command to a byte array.
    /// </summary>
    /// <param name="command">The command to convert.</param>
    /// <returns>The APDU as a byte array.</returns>
    public static byte[] ToApdu(this IApduCommand command)
    {
        List<byte> apdu = [command.Cla, command.Ins, command.P1, command.P2];

        byte[] data = command.Data;
        bool hasData = data is { Length: > 0 };
        bool expectsResponse = command.ExpectedResponseLength.HasValue;

        if (command.IsExtendedLength)
        {
            // Extended length encoding
            if (hasData)
            {
                apdu.Add(0x00); // Extended length indicator
                apdu.Add((byte)(data!.Length >> 8));
                apdu.Add((byte)(data.Length & 0xFF));
                apdu.AddRange(data);
            }

            if (expectsResponse)
            {
                if (!hasData)
                {
                    apdu.Add(0x00); // Extended length indicator
                }

                int le = command.ExpectedResponseLength!.Value;
                if (le == 0)
                {
                    // Maximum length
                    apdu.Add(0x00);
                    apdu.Add(0x00);
                }
                else
                {
                    apdu.Add((byte)(le >> 8));
                    apdu.Add((byte)(le & 0xFF));
                }
            }
        }
        else
        {
            // Short length encoding
            if (hasData)
            {
                apdu.Add((byte)data!.Length);
                apdu.AddRange(data);
            }

            if (expectsResponse)
            {
                int le = command.ExpectedResponseLength!.Value;
                if (le == 0)
                {
                    // Maximum length (256 bytes)
                    apdu.Add(0x00);
                }
                else
                {
                    apdu.Add((byte)le);
                }
            }
        }

        return apdu.ToArray();
    }

    /// <summary>
    /// Converts an APDU command to a byte array (alias for ToApdu).
    /// </summary>
    /// <param name="command">The command to convert.</param>
    /// <returns>The APDU as a byte array.</returns>
    public static byte[] ToByteArray(this IApduCommand command)
        => command.ToApdu();
}