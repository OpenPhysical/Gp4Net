using CSharpFunctionalExtensions;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Represents an individual validation message with severity and context.
/// Immutable record following functional programming principles.
/// </summary>
public sealed record ValidationMessage
{
    /// <summary>
    /// Gets the severity level of this message.
    /// </summary>
    public ValidationSeverity Severity { get; init; }

    /// <summary>
    /// Gets the validation code (e.g., "CAP-001", "MANIFEST-MISSING").
    /// </summary>
    public string Code { get; init; }

    /// <summary>
    /// Gets the human-readable description.
    /// </summary>
    public string Message { get; init; }

    /// <summary>
    /// Gets optional additional context (file path, line number, component name).
    /// </summary>
    public Maybe<string> Context { get; init; }

    /// <summary>
    /// Gets optional suggested remediation action.
    /// </summary>
    public Maybe<string> Suggestion { get; init; }

    private ValidationMessage(
        ValidationSeverity severity,
        string code,
        string message,
        Maybe<string> context,
        Maybe<string> suggestion
    )
    {
        Severity = severity;
        Code = code;
        Message = message;
        Context = context;
        Suggestion = suggestion;
    }

    /// <summary>
    /// Creates a new validation message.
    /// </summary>
    public static ValidationMessage Create(
        ValidationSeverity severity,
        string code,
        string message,
        Maybe<string> context = default,
        Maybe<string> suggestion = default
    )
    {
        return new ValidationMessage(severity, code, message, context, suggestion);
    }

    /// <summary>
    /// Creates an error message.
    /// </summary>
    public static ValidationMessage Error(
        string code,
        string message,
        Maybe<string> context = default,
        Maybe<string> suggestion = default
    )
    {
        return Create(ValidationSeverity.Error, code, message, context, suggestion);
    }

    /// <summary>
    /// Creates a warning message.
    /// </summary>
    public static ValidationMessage Warning(
        string code,
        string message,
        Maybe<string> context = default,
        Maybe<string> suggestion = default
    )
    {
        return Create(ValidationSeverity.Warning, code, message, context, suggestion);
    }

    /// <summary>
    /// Creates an info message.
    /// </summary>
    public static ValidationMessage Info(
        string code,
        string message,
        Maybe<string> context = default,
        Maybe<string> suggestion = default
    )
    {
        return Create(ValidationSeverity.Info, code, message, context, suggestion);
    }
}
