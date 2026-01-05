namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Represents the severity level of a validation message.
/// </summary>
public enum ValidationSeverity
{
    /// <summary>
    /// Blocking error that prevents operation.
    /// </summary>
    Error,

    /// <summary>
    /// Non-blocking warning that should be reviewed.
    /// </summary>
    Warning,

    /// <summary>
    /// Informational message for awareness.
    /// </summary>
    Info
}
