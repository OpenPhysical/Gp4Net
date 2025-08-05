using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Transport;

namespace Gp4Net.Services;

/// <summary>
/// Functional interface for smart card communication using pipeline architecture.
/// </summary>
public interface ISmartCardService : IDisposable
{
    /// <summary>
    /// Executes a command through the card communication pipeline.
    /// </summary>
    /// <param name="command">The APDU command to execute.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The result of the command execution.</returns>
    Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        IApduCommand command,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Executes a command with additional options.
    /// </summary>
    /// <param name="command">The APDU command to execute.</param>
    /// <param name="options">Command execution options.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The result of the command execution.</returns>
    Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        IApduCommand command,
        CommandOptions options,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the current command context containing state information.
    /// </summary>
    IPipelineContext Context { get; }

    /// <summary>
    /// Creates a new service instance with an updated context.
    /// </summary>
    /// <param name="context">The new context.</param>
    /// <returns>A new service instance with the updated context.</returns>
    ISmartCardService WithContext(IPipelineContext context);

    /// <summary>
    /// Creates a new service instance with a context value added.
    /// </summary>
    /// <typeparam name="T">The type of the value.</typeparam>
    /// <param name="key">The context key.</param>
    /// <param name="value">The context value.</param>
    /// <returns>A new service instance with the updated context.</returns>
    ISmartCardService WithContextValue<T>(string key, T value);
}

/// <summary>
/// Factory for creating smart card service instances.
/// </summary>
public interface ISmartCardServiceFactory
{
    /// <summary>
    /// Creates a smart card service for the specified reader.
    /// </summary>
    /// <param name="readerName">The reader name.</param>
    /// <param name="options">Service configuration options.</param>
    /// <returns>A smart card service instance.</returns>
    Task<Result<ISmartCardService, SmartCardError>> CreateAsync(
        string readerName,
        SmartCardServiceOptions options);

    /// <summary>
    /// Lists available smart card readers.
    /// </summary>
    /// <returns>The list of available readers.</returns>
    Task<Result<string[], SmartCardError>> ListReadersAsync();
}

/// <summary>
/// Options for smart card service configuration.
/// </summary>
public record SmartCardServiceOptions
{
    /// <summary>
    /// The card protocol to use (T0, T1, etc.).
    /// </summary>
    public CardProtocol Protocol { get; init; } = CardProtocol.Any;

    /// <summary>
    /// Whether to enable command logging.
    /// </summary>
    public bool EnableLogging { get; init; } = true;

    /// <summary>
    /// Whether to enable state capturing.
    /// </summary>
    public bool EnableStateCapture { get; init; } = true;

    /// <summary>
    /// Custom middleware to add to the pipeline.
    /// </summary>
    public ICommandMiddleware[] CustomMiddleware { get; init; } = Array.Empty<ICommandMiddleware>();

    /// <summary>
    /// Initial context values.
    /// </summary>
    public IPipelineContext InitialContext { get; init; }
}

/// <summary>
/// Card communication protocols.
/// </summary>
public enum CardProtocol
{
    /// <summary>
    /// Any available protocol.
    /// </summary>
    Any = 0,

    /// <summary>
    /// T=0 protocol.
    /// </summary>
    T0 = 1,

    /// <summary>
    /// T=1 protocol.
    /// </summary>
    T1 = 2,

    /// <summary>
    /// T=CL (contactless) protocol.
    /// </summary>
    Tcl = 3
}