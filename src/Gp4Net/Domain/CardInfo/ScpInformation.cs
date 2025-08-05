using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.Domain.Protocol;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Represents SCP (Secure Channel Protocol) information for a smart card.
/// </summary>
public record ScpInformation
{
    /// <summary>
    /// Gets the list of supported SCP protocols with their implementation options.
    /// </summary>
    public IReadOnlyList<ScpProtocolInfo> Protocols { get; }

    /// <summary>
    /// Initializes a new instance of ScpInformation.
    /// </summary>
    public ScpInformation(IReadOnlyList<ScpProtocolInfo> protocols)
    {
        Protocols = protocols ?? Array.Empty<ScpProtocolInfo>();
    }
    
    /// <summary>
    /// Gets a formatted string representation of the SCP support.
    /// </summary>
    public string ToFormattedString(bool multiLine = false)
    {
        if (Protocols.Count == 0)
        {
            return string.Empty;
        }

        if (!multiLine)
        {
            return string.Join(" ", Protocols.Select(p => p.ToShortString()));
        }

        return string.Join("\n", Protocols.Select(p => p.ToDetailedString()));
    }
}

/// <summary>
/// Represents information about a single SCP protocol with its implementation options.
/// </summary>
public record ScpProtocolInfo
{
    /// <summary>
    /// Gets the SCP protocol version (e.g., 2 for SCP02, 3 for SCP03).
    /// </summary>
    public byte Version { get; }
    
    /// <summary>
    /// Gets the implementation options for this protocol.
    /// </summary>
    public IReadOnlyList<ScpImplementation> ImplementationOptions { get; }
    
    /// <summary>
    /// Initializes a new instance of ScpProtocolInfo.
    /// </summary>
    public ScpProtocolInfo(byte version, IReadOnlyList<ScpImplementation> implementationOptions)
    {
        Version = version;
        ImplementationOptions = implementationOptions ?? Array.Empty<ScpImplementation>();
    }
    
    /// <summary>
    /// Gets a short string representation suitable for single-line display.
    /// </summary>
    public string ToShortString()
    {
        if (ImplementationOptions.Count == 0)
        {
            return FormatScpVersion(Version);
        }
        
        var options = string.Join(" ", ImplementationOptions.OrderBy(opt => (byte)opt).Select(opt => $"i={(byte)opt:X2}"));
        return $"{FormatScpVersion(Version)} ({options})";
    }
    
    /// <summary>
    /// Gets a detailed string representation with descriptions.
    /// </summary>
    public string ToDetailedString()
    {
        if (ImplementationOptions.Count == 0)
        {
            return FormatScpVersion(Version);
        }
        
        var lines = new List<string> { $"{FormatScpVersion(Version)}:" };
        
        foreach (var option in ImplementationOptions.OrderBy(opt => (byte)opt))
        {
            var description = GetImplementationDescription(option);
            lines.Add($"  - i={(byte)option:X2}: {description}");
        }
        
        return string.Join("\n", lines);
    }
    
    /// <summary>
    /// Gets a human-readable description for an SCP implementation option.
    /// </summary>
    private static string GetImplementationDescription(ScpImplementation implementation)
    {
        return implementation switch
        {
            ScpImplementation.Scp02NoDerivation => "3 Secure Channel Keys (no derivation)",
            ScpImplementation.Scp02OneKey => "1 Secure Channel base key",
            ScpImplementation.Scp02ThreeKeys => "3 Secure Channel base keys",
            ScpImplementation.Scp02OneKeyStaticMac => "1 base key with static MAC",
            ScpImplementation.Scp02StaticMac => "3 keys with static MAC",
            ScpImplementation.Scp02AesKeys => "3 keys with AES encryption",
            ScpImplementation.Scp02ThreeKeysRMac => "3 keys with R-MAC support",
            ScpImplementation.Scp02PseudoRandom => "Pseudo-random card challenge",
            ScpImplementation.Scp02PseudoRandomRMac => "Pseudo-random with R-MAC support",
            ScpImplementation.Scp03Aes128 => "AES-128",
            ScpImplementation.Scp03Aes192 => "AES-192", 
            ScpImplementation.Scp03Aes256 => "AES-256",
            ScpImplementation.Scp03NoResponseMac => "AES-128 (no R-MAC)",
            ScpImplementation.Scp03RandomChallenge => "Random card challenge",
            ScpImplementation.Scp03PseudoRandom => "Pseudo-random card challenge",
            _ => GetDetailedImplementationFeatures(implementation)
        };
    }
    
    /// <summary>
    /// Gets detailed features for an implementation option based on its bits.
    /// </summary>
    private static string GetDetailedImplementationFeatures(ScpImplementation implementation)
    {
        var features = new List<string>();
        var value = (byte)implementation;
        
        if (implementation.IsScp02())
        {
            // Decode SCP02 bitmap per GP Card Spec Table E-1
            features.Add((value & 0x01) != 0 ? "3 keys" : "1 base key");
            features.Add((value & 0x02) != 0 ? "C-MAC on unmodified APDU" : "C-MAC on modified APDU");
            features.Add((value & 0x04) != 0 ? "Explicit init" : "Implicit init");
            features.Add((value & 0x08) != 0 ? "ICV=MAC(AID)" : "ICV=0");
            features.Add((value & 0x10) != 0 ? "ICV encryption" : "No ICV encryption");
            if ((value & 0x20) != 0) features.Add("R-MAC support");
            if ((value & 0x40) != 0) features.Add("Pseudo-random");
            
            return string.Join(", ", features);
        }
        
        return $"Unknown implementation 0x{value:X2}";
    }
    
    /// <summary>
    /// Formats SCP version number for display.
    /// </summary>
    private static string FormatScpVersion(byte version)
    {
        // For SCP versions 10 and above, use hex format
        return version >= 0x10 ? $"SCP{version:X2}" : $"SCP{version:D2}";
    }
}