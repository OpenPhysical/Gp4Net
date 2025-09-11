using CSharpFunctionalExtensions;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Functional logging service that encapsulates Maybe&lt;ILogger&gt; handling.
/// Provides clean API for logging operations while maintaining functional programming principles.
/// </summary>
[PublicAPI]
public record LoggingService(Maybe<ILogger> Logger)
{
    /// <summary>
    /// Logs a debug message if logger is available.
    /// </summary>
    public void LogDebug(string message) => Logger.Match(l => l.LogDebug(message), () => { });

    /// <summary>
    /// Logs a debug message with parameters if logger is available.
    /// </summary>
    public void LogDebug(string message, params object[] args) =>
        Logger.Match(l => l.LogDebug(message, args), () => { });

    /// <summary>
    /// Logs an information message if logger is available.
    /// </summary>
    public void LogInformation(string message) =>
        Logger.Match(l => l.LogInformation(message), () => { });

    /// <summary>
    /// Logs an information message with parameters if logger is available.
    /// </summary>
    public void LogInformation(string message, params object[] args) =>
        Logger.Match(l => l.LogInformation(message, args), () => { });

    /// <summary>
    /// Logs a warning message if logger is available.
    /// </summary>
    public void LogWarning(string message) => Logger.Match(l => l.LogWarning(message), () => { });

    /// <summary>
    /// Logs a warning message with parameters if logger is available.
    /// </summary>
    public void LogWarning(string message, params object[] args) =>
        Logger.Match(l => l.LogWarning(message, args), () => { });

    /// <summary>
    /// Logs an error message if logger is available.
    /// </summary>
    public void LogError(string message) => Logger.Match(l => l.LogError(message), () => { });

    /// <summary>
    /// Logs an error message with parameters if logger is available.
    /// </summary>
    public void LogError(string message, params object[] args) =>
        Logger.Match(l => l.LogError(message, args), () => { });

    /// <summary>
    /// Logs a trace message if logger is available.
    /// </summary>
    public void LogTrace(string message) => Logger.Match(l => l.LogTrace(message), () => { });

    /// <summary>
    /// Logs a trace message with parameters if logger is available.
    /// </summary>
    public void LogTrace(string message, params object[] args) =>
        Logger.Match(l => l.LogTrace(message, args), () => { });

    /// <summary>
    /// Creates a LoggingService from a non-null ILogger.
    /// </summary>
    public static LoggingService From(ILogger logger) => new(Maybe<ILogger>.From(logger));

    /// <summary>
    /// Creates a LoggingService with no logger (silent operation).
    /// </summary>
    public static LoggingService None => new(Maybe<ILogger>.None);
}
