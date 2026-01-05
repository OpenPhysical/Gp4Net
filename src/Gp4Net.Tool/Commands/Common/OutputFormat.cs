namespace Gp4Net.Tool.Commands.Common;

/// <summary>
/// Represents the output format for CLI commands.
/// </summary>
public enum OutputFormat
{
    /// <summary>
    /// Human-readable table format using Spectre.Console.
    /// </summary>
    Table,

    /// <summary>
    /// Machine-parseable JSON format.
    /// </summary>
    Json
}
