using System.Collections.Generic;
using System.Linq;
using Gp4Net.Constants;

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
        Protocols = protocols ?? [];
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
        ImplementationOptions = implementationOptions ?? [];
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

        string options = string.Join(
            " ",
            ImplementationOptions.OrderBy(opt => (byte)opt).Select(opt => $"i={(byte)opt:X2}")
        );
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

        var header = $"{FormatScpVersion(Version)}:";
        var options = ImplementationOptions
            .OrderBy(opt => (byte)opt)
            .Select(option =>
                $"  - i={(byte)option:X2}: {GetImplementationDescription(Version, option)}"
            );

        return string.Join("\n", new[] { header }.Concat(options));
    }

    /// <summary>
    /// Gets a human-readable description for an SCP implementation option.
    /// </summary>
    private static string GetImplementationDescription(
        byte scpVersion,
        ScpImplementation implementation
    )
    {
        if (scpVersion == 0x02)
            return implementation.GetDescription();
        return scpVersion == 0x03
            ? implementation.GetScp03Description()
            : $"Unknown implementation 0x{(byte)implementation:X2}";
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
