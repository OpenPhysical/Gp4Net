using System;
using System.Collections.Generic;
using System.Linq;

namespace Gp4Net.Domain.CardInfo
{
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

            // GlobalPlatform Card Capabilities format analysis
            // Look for various SCP indicators in the TLV structure
            int offset = 0;

            while (offset < data.Length - 1)
            {
                var tag = data[offset];

                if (offset + 1 >= data.Length)
                {
                    break;
                }

                var length = data[offset + 1];

                if (offset + 2 + length > data.Length)
                {
                    break;
                }

                switch (tag)
                {
                    case 0x81: // Secure messaging support
                        for (int i = 0; i < length; i++)
                        {
                            var protocol = data[offset + 2 + i];
                            // Check for specific SCP protocol support indicators
                            if (protocol == 0x01 || protocol == 0x02)
                            {
                                result.Add("SCP02");
                            }

                            if (protocol == 0x06 || protocol == 0x07)
                            {
                                result.Add("SCP03");
                            }

                            if (protocol == 0x10)
                            {
                                result.Add("SCP10");
                            }
                        }
                        break;

                    case 0x82: // Secure channel protocol data
                        // Sometimes contains direct protocol indicators
                        for (int i = 0; i < length; i++)
                        {
                            var value = data[offset + 2 + i];
                            // Look for SCP protocol version bytes
                            if (value == 0x02)
                            {
                                result.Add("SCP02");
                            }

                            if (value == 0x03)
                            {
                                result.Add("SCP03");
                            }
                        }
                        break;

                    case 0x83: // Additional security capabilities
                        // Look for AES support (indicator of SCP03)
                        if (length > 0)
                        {
                            var capabilities = data[offset + 2];
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

                offset += 2 + length;
            }

            // Remove duplicates and sort
            return string.Join(", ", result.Distinct().OrderBy(x => x));
        }
    }
}