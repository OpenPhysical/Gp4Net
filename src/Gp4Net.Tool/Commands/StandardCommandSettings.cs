using System.ComponentModel;
using JetBrains.Annotations;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands;

/// <summary>
/// Standard settings for commands that don't require card operations.
/// </summary>
[PublicAPI]
public class StandardCommandSettings : CommandSettings
{
    /// <summary>
    /// Gets or sets a value indicating whether to use verbose output.
    /// </summary>
    [CommandOption("-v|--verbose")]
    [Description("Enable verbose output")]
    public bool Verbose { get; set; }
}

/// <summary>
/// Settings for commands that require card connection but not secure channel.
/// </summary>
[PublicAPI]
public class CardCommandSettings : BaseCommandSettings
{
    /// <inheritdoc />
    public override bool RequiresSecureChannel
    {
        get
        {
            return false;
        }
    }
}

/// <summary>
/// Settings for commands that require both card connection and secure channel.
/// </summary>
[PublicAPI]
public class SecureCommandSettings : BaseCommandSettings
{
    /// <inheritdoc />
    public override bool RequiresSecureChannel
    {
        get
        {
            return true;
        }
    }
}