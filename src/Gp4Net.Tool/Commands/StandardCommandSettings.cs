using System.ComponentModel;
using CSharpFunctionalExtensions;
using Gp4Net.Pipeline;
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

    /// <summary>
    /// Gets or sets a value indicating whether to enable debug output.
    /// </summary>
    [CommandOption("-d|--debug")]
    [Description("Enable debug output")]
    public bool Debug { get; set; }

    /// <summary>
    /// Creates CommandOptions from the settings.
    /// </summary>
    public CommandOptions GetCommandOptions() =>
        new(
            UseSecureChannel: false,
            CaptureMetrics: true,
            EnableLogging: true,
            VerboseLogging: Verbose,
            DebugLogging: Debug
        );
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
    [Description("Smart card reader name or virtual:profile.json")]
    public string ReaderName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the file path to save virtual card state.
    /// </summary>
    [CommandOption("--save-file")]
    [Description("Save virtual card state to file")]
    public string SaveFile { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether to use verbose output.
    /// </summary>
    [CommandOption("-v|--verbose")]
    [Description("Enable verbose output")]
    public bool Verbose { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to enable debug output.
    /// </summary>
    [CommandOption("-d|--debug")]
    [Description("Enable debug output")]
    public bool Debug { get; set; }

    /// <summary>
    /// Gets the reader name as Maybe type.
    /// </summary>
    public Maybe<string> GetReaderName() =>
        string.IsNullOrWhiteSpace(ReaderName) ? Maybe<string>.None : Maybe<string>.From(ReaderName);

    /// <summary>
    /// Gets the save file path as Maybe type.
    /// </summary>
    public Maybe<string> GetSaveFile() =>
        string.IsNullOrWhiteSpace(SaveFile) ? Maybe<string>.None : Maybe<string>.From(SaveFile);

    /// <summary>
    /// Creates CommandOptions from the settings.
    /// </summary>
    public CommandOptions GetCommandOptions(bool useSecureChannel = false) =>
        new(
            UseSecureChannel: useSecureChannel,
            CaptureMetrics: true,
            EnableLogging: true,
            VerboseLogging: Verbose,
            DebugLogging: Debug
        );
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
    [Description("Smart card reader name or virtual:profile.json")]
    public string ReaderName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the keyset specification for secure channel establishment.
    /// </summary>
    [CommandOption("-k|--keyset")]
    [Description("Keyset specification for secure channel")]
    public string Keyset { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the explicit key version number. When omitted, the card's key
    /// information template and GP default key selection are used for autodetection.
    /// </summary>
    [CommandOption("--key-version")]
    [Description("Explicit key version number; omit to autodetect")]
    public string KeyVersion { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the file path to save virtual card state.
    /// </summary>
    [CommandOption("--save-file")]
    [Description("Save virtual card state to file")]
    public string SaveFile { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether to use verbose output.
    /// </summary>
    [CommandOption("-v|--verbose")]
    [Description("Enable verbose output")]
    public bool Verbose { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to enable debug output.
    /// </summary>
    [CommandOption("-d|--debug")]
    [Description("Enable debug output")]
    public bool Debug { get; set; }

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

    /// <summary>
    /// Gets the save file path as Maybe type.
    /// </summary>
    public Maybe<string> GetSaveFile() =>
        string.IsNullOrWhiteSpace(SaveFile) ? Maybe<string>.None : Maybe<string>.From(SaveFile);

    /// <summary>
    /// Creates CommandOptions from the settings.
    /// </summary>
    public CommandOptions GetCommandOptions(bool useSecureChannel = true) =>
        new(
            UseSecureChannel: useSecureChannel,
            CaptureMetrics: true,
            EnableLogging: true,
            VerboseLogging: Verbose,
            DebugLogging: Debug
        );
}
