using System.Collections.Generic;
using System.Linq;
using Gp4Net.Core.Tlv;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Parses SCP (Secure Channel Protocol) capabilities from card capability data.
/// </summary>
public static class ScpCapabilitiesParser
{
    /// <summary>
    /// Parses SCP capabilities from TLV-encoded card capability data.
    /// </summary>
    /// <param name="data">The raw capability data.</param>
    /// <returns>Comma-separated list of supported SCP protocols.</returns>
    public static string Parse(byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return string.Empty;
        }

        var result = new List<string>();

        try
        {
            // Use TlvParser to properly parse TLV structure
            foreach (var element in TlvParser.ParseAll(data))
            {
                switch (element.TagNumber)
                {
                    case 0x81: // Secure messaging support
                        foreach (var protocolByte in element.Value)
                        {
                            // Check for specific SCP protocol support indicators
                            if (protocolByte == 0x01 || protocolByte == 0x02)
                            {
                                result.Add("SCP02");
                            }

                            if (protocolByte == 0x06 || protocolByte == 0x07)
                            {
                                result.Add("SCP03");
                            }

                            if (protocolByte == 0x10)
                            {
                                result.Add("SCP10");
                            }
                        }
                        break;

                    case 0x82: // Secure channel protocol data
                        // Sometimes contains direct protocol indicators
                        foreach (var valueByte in element.Value)
                        {
                            // Look for SCP protocol version bytes
                            if (valueByte == 0x02)
                            {
                                result.Add("SCP02");
                            }

                            if (valueByte == 0x03)
                            {
                                result.Add("SCP03");
                            }
                        }
                        break;

                    case 0x83: // Additional security capabilities
                        // Look for AES support (indicator of SCP03)
                        if (element.Value.Length > 0)
                        {
                            var capabilities = element.Value[0];
                            if ((capabilities & 0x01) != 0)
                            {
                                result.Add("SCP02");
                            }

                            if ((capabilities & 0x02) != 0)
                            {
                                result.Add("SCP03");
                            }
                        }
                        break;
                }
            }
        }
        catch
        {
            // If TLV parsing fails, return empty string
            return string.Empty;
        }

        // Remove duplicates and sort
        return string.Join(" ", result.Distinct().OrderBy(x => x));
    }
}