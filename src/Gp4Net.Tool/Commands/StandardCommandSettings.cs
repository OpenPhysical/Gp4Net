using System.ComponentModel;
using CSharpFunctionalExtensions;
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
public class CardCommandSettings : CommandSettings
{
    /// <summary>
    /// Gets or sets the reader name to use for card operations.
    /// </summary>
    [CommandOption("-r|--reader")]
    [Description("Smart card reader name")]
    public string ReaderName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether to use verbose output.
    /// </summary>
    [CommandOption("-v|--verbose")]
    [Description("Enable verbose output")]
    public bool Verbose { get; set; }

    /// <summary>
    /// Gets the reader name as Maybe type.
    /// </summary>
    public Maybe<string> GetReaderName() => 
        string.IsNullOrWhiteSpace(ReaderName) ? Maybe<string>.None : Maybe<string>.From(ReaderName);
}

/// <summary>
/// Settings for commands that require both card connection and secure channel.
/// </summary>
[PublicAPI]
public class SecureCommandSettings : CommandSettings
{
    /// <summary>
    /// Gets or sets the reader name to use for card operations.
    /// </summary>
    [CommandOption("-r|--reader")]
    [Description("Smart card reader name")]
    public string ReaderName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the keyset specification for secure channel establishment.
    /// </summary>
    [CommandOption("-k|--keyset")]
    [Description("Keyset specification for secure channel")]
    public string Keyset { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether to use verbose output.
    /// </summary>
    [CommandOption("-v|--verbose")]
    [Description("Enable verbose output")]
    public bool Verbose { get; set; }

    /// <summary>
    /// Gets the reader name as Maybe type.
    /// </summary>
    public Maybe<string> GetReaderName() => 
        string.IsNullOrWhiteSpace(ReaderName) ? Maybe<string>.None : Maybe<string>.From(ReaderName);

    /// <summary>
    /// Gets the keyset as Maybe type.
    /// </summary>
    public Maybe<string> GetKeyset() => 
        string.IsNullOrWhiteSpace(Keyset) ? Maybe<string>.None : Maybe<string>.From(Keyset);
}