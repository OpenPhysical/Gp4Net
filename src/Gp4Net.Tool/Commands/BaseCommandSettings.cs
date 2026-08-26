using System.ComponentModel;
using JetBrains.Annotations;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands;

/// <summary>
/// Base settings for secure commands with keyset management.
/// Functional approach to command configuration.
/// </summary>
[PublicAPI]
public abstract class BaseCommandSettings : SecureCommandSettings
{
    /// <summary>
    /// Gets or sets the encryption key.
    /// </summary>
    [CommandOption("--key-enc")]
    [Description("Encryption key (hex)")]
    public string KeyEnc { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the MAC key.
    /// </summary>
    [CommandOption("--key-mac")]
    [Description("MAC key (hex)")]
    public string KeyMac { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the DEK key.
    /// </summary>
    [CommandOption("--key-dek")]
    [Description("DEK key (hex)")]
    public string KeyDek { get; set; } = string.Empty;

    /// <summary>
    /// Gets whether this command requires a secure channel.
    /// </summary>
    public abstract bool RequiresSecureChannel { get; }
}
