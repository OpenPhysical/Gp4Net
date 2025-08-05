using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.Core.Tlv;
using Gp4Net.Domain.Protocol;

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
        var info = ParseDetailed(data);
        return info.ToFormattedString(multiLine: false);
    }
    
    /// <summary>
    /// Parses SCP capabilities and returns detailed information.
    /// </summary>
    /// <param name="data">The raw capability data.</param>
    /// <returns>Structured SCP information.</returns>
    public static ScpInformation ParseDetailed(byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return new ScpInformation(new List<ScpProtocolInfo>());
        }

        var protocols = new Dictionary<byte, List<ScpImplementation>>();

        try
        {
            // Use TlvParser to properly parse TLV structure
            ParseElements(TlvParser.ParseAll(data), protocols);
        }
        catch
        {
            // If TLV parsing fails, return empty information
            return new ScpInformation(new List<ScpProtocolInfo>());
        }

        // Convert to structured information
        var protocolList = protocols
            .Select(kvp => new ScpProtocolInfo(kvp.Key, kvp.Value.Distinct().ToList()))
            .OrderBy(p => p.Version)
            .ToList();
            
        return new ScpInformation(protocolList);
    }

    /// <summary>
    /// Recursively parses TLV elements to extract SCP information.
    /// </summary>
    private static void ParseElements(IEnumerable<TlvObject> elements, Dictionary<byte, List<ScpImplementation>> protocols)
    {
        foreach (var element in elements)
        {
            switch (element.TagNumber)
            {
                case 0xA0: // Constructed tag containing SCP information
                    // Per GP Card Spec, A0 tag in capabilities contains nested TLV
                    if (element.Value != null && element.Value.Length > 0)
                    {
                        try
                        {
                            // Parse inner TLV structure
                            var innerElements = TlvParser.ParseAll(element.Value);
                            ParseA0Contents(innerElements, protocols);
                        }
                        catch
                        {
                            // If parsing inner structure fails, continue
                        }
                    }
                    break;

                // Tags 80-87 outside A0 context are not SCP related per GP Card Spec Table H-5
                case 0x80: // Outside A0 context - not SCP related
                case 0x81: // Outside A0 context - privileges  
                case 0x82: // Outside A0 context - privileges
                case 0x83: // Outside A0 context - privileges  
                case 0x84: // Outside A0 context - privileges
                case 0x85: // Outside A0 context - privileges  
                case 0x86: // Outside A0 context - privileges
                case 0x87: // Outside A0 context - privileges
                    // These tags outside A0 are privilege/capability indicators, not SCP
                    break;
                    
                default:
                    break;
            }
        }
    }
    
    /// <summary>
    /// Parses A0 tag contents to extract SCP information per GP Card Spec Table H-5.
    /// </summary>
    private static void ParseA0Contents(IEnumerable<TlvObject> elements, Dictionary<byte, List<ScpImplementation>> protocols)
    {
        byte? currentScpType = null;
        
        foreach (var element in elements)
        {
            switch (element.TagNumber)
            {
                case 0x80: // SCP type ('02', '03', '10', '11', '80', '81')
                    if (element.Value != null && element.Value.Length > 0)
                    {
                        var scpVersion = element.Value[0];
                        // Valid SCP versions per GP specification
                        if (scpVersion == 0x02 || scpVersion == 0x03 || 
                            scpVersion == 0x10 || scpVersion == 0x11 ||
                            scpVersion == 0x80 || scpVersion == 0x81)
                        {
                            currentScpType = scpVersion;
                            if (!protocols.ContainsKey(scpVersion))
                            {
                                protocols[scpVersion] = new List<ScpImplementation>();
                            }
                        }
                    }
                    break;
                    
                case 0x81: // List of supported options for that protocol
                    if (element.Value != null && element.Value.Length > 0 && currentScpType.HasValue)
                    {
                        foreach (var optionByte in element.Value)
                        {
                            // Each byte is an implementation option
                            if (Enum.IsDefined(typeof(ScpImplementation), optionByte))
                            {
                                var impl = (ScpImplementation)optionByte;
                                if (currentScpType.Value == 0x02 && impl.IsScp02())
                                {
                                    protocols[currentScpType.Value].Add(impl);
                                }
                                else if (currentScpType.Value == 0x03 && impl.IsScp03())
                                {
                                    protocols[currentScpType.Value].Add(impl);
                                }
                                else if (currentScpType.Value == 0x10)
                                {
                                    // SCP10 implementation options
                                    protocols[currentScpType.Value].Add(impl);
                                }
                            }
                        }
                    }
                    break;
                    
                case 0x82: // Supported keys for SCP03
                case 0x83: // Supported TLS cipher suites for SCP81
                case 0x84: // Maximum length of Pre Shared Key
                    // These are additional SCP-specific options, not parsed for now
                    break;
            }
        }
    }
}