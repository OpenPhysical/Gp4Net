namespace Gp4Net.Tool.Infrastructure;

/// <summary>
/// Marker interface for CLI commands to enable Scrutor scanning.
/// </summary>
public interface ICliCommand
{
    /// <summary>
    /// Gets the command metadata.
    /// </summary>
    static abstract CliCommandMetadata Metadata { get; }
}

/// <summary>
/// Metadata for CLI commands.
/// </summary>
public record CliCommandMetadata(
    string Name,
    string Description,
    string? ParentCommand = null);