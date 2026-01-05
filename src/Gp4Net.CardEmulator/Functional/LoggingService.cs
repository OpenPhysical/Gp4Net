using CSharpFunctionalExtensions;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Represents a unit value for methods that have side effects but return a value to indicate completion.
/// </summary>
public readonly struct Unit
{
    public static readonly Unit Instance = default;
}

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
    public Unit LogDebug(string message) =>
        Logger.Match(
            l =>
            {
                l.LogDebug(message);
                return Unit.Instance;
            },
            () => Unit.Instance
        );

    /// <summary>
    /// Logs a debug message with parameters if logger is available.
    /// </summary>
    public Unit LogDebug(string message, params object[] args) =>
        Logger.Match(
            l =>
            {
                l.LogDebug(message, args);
                return Unit.Instance;
            },
            () => Unit.Instance
        );

    /// <summary>
    /// Logs an information message if logger is available.
    /// </summary>
    public Unit LogInformation(string message) =>
        Logger.Match(
            l =>
            {
                l.LogInformation(message);
                return Unit.Instance;
            },
            () => Unit.Instance
        );

    /// <summary>
    /// Logs an information message with parameters if logger is available.
    /// </summary>
    public Unit LogInformation(string message, params object[] args) =>
        Logger.Match(
            l =>
            {
                l.LogInformation(message, args);
                return Unit.Instance;
            },
            () => Unit.Instance
        );

    /// <summary>
    /// Logs a warning message if logger is available.
    /// </summary>
    public Unit LogWarning(string message) =>
        Logger.Match(
            l =>
            {
                l.LogWarning(message);
                return Unit.Instance;
            },
            () => Unit.Instance
        );

    /// <summary>
    /// Logs a warning message with parameters if logger is available.
    /// </summary>
    public Unit LogWarning(string message, params object[] args) =>
        Logger.Match(
            l =>
            {
                l.LogWarning(message, args);
                return Unit.Instance;
            },
            () => Unit.Instance
        );

    /// <summary>
    /// Logs an error message if logger is available.
    /// </summary>
    public Unit LogError(string message) =>
        Logger.Match(
            l =>
            {
                l.LogError(message);
                return Unit.Instance;
            },
            () => Unit.Instance
        );

    /// <summary>
    /// Logs an error message with parameters if logger is available.
    /// </summary>
    public Unit LogError(string message, params object[] args) =>
        Logger.Match(
            l =>
            {
                l.LogError(message, args);
                return Unit.Instance;
            },
            () => Unit.Instance
        );

    /// <summary>
    /// Logs a trace message if logger is available.
    /// </summary>
    public Unit LogTrace(string message) =>
        Logger.Match(
            l =>
            {
                l.LogTrace(message);
                return Unit.Instance;
            },
            () => Unit.Instance
        );

    /// <summary>
    /// Logs a trace message with parameters if logger is available.
    /// </summary>
    public Unit LogTrace(string message, params object[] args) =>
        Logger.Match(
            l =>
            {
                l.LogTrace(message, args);
                return Unit.Instance;
            },
            () => Unit.Instance
        );

    /// <summary>
    /// Creates a LoggingService from a non-null ILogger.
    /// </summary>
    public static LoggingService From(ILogger logger) => new(Maybe<ILogger>.From(logger));

    /// <summary>
    /// Creates a LoggingService with no logger (silent operation).
    /// </summary>
    public static LoggingService None => new(Maybe<ILogger>.None);
}
