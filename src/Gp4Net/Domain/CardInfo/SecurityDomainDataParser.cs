using System;
using System.Collections.Generic;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Parses security domain data from A5 proprietary tag format.
/// </summary>
public static class SecurityDomainDataParser
{
    /// <summary>
    /// Decodes security domain data from A5 proprietary tag format.
    /// </summary>
    /// <param name="data">The raw security domain data.</param>
    /// <returns>Parsed security domain information as a formatted string.</returns>
    public static string Decode(byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return string.Empty;
        }

        List<string> result = [];

        // Parse A5 tag (proprietary data)
        if (data.Length >= 2 && data[0] == 0xA5)
        {
            int offset = 2; // Skip A5 and length

            while (offset < data.Length)
            {
                if (data[offset] == 0x9F && offset + 1 < data.Length)
                {
                    int tag = (data[offset] << 8) | data[offset + 1];
                    if (offset + 2 < data.Length)
                    {
                        byte length = data[offset + 2];
                        if (offset + 3 + length <= data.Length)
                        {
                            byte[] value = data[(offset + 3)..(offset + 3 + length)];

                            switch (tag)
                            {
                                case 0x9F65: // Maximum APDU size
                                    if (length >= 2)
                                    {
                                        int maxApdu = (value[0] << 8) | value[1];
                                        result.Add($"Max APDU: {maxApdu} bytes");
                                    }
                                    break;
                                case 0x9F6E: // Application production lifecycle data
                                    if (length >= 1)
                                    {
                                        string lifecycle = ParseLifecycleState(value[0]);
                                        result.Add($"Lifecycle: {lifecycle}");
                                    }
                                    break;
                                default:
                                    result.Add($"Tag {tag:X4}: {Convert.ToHexString(value)}");
                                    break;
                            }
                        }
                        offset += 3 + length;
                    }
                    else
                    {
                        break;
                    }
                }
                else
                {
                    offset++;
                }
            }
        }

        return result.Count > 0 ? string.Join(", ", result) : Convert.ToHexString(data);
    }

    private static string ParseLifecycleState(byte state)
    {
        return state switch
        {
            0x01 => "Loaded",
            0x03 => "Installed",
            0x07 => "Selectable",
            0x0F => "Personalized",
            0x83 => "Blocked",
            0x87 => "Locked",
            _ => $"0x{state:X2}"
        };
    }
}