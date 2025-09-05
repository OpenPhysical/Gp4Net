using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using WSCT.ISO7816;

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
        CommandAPDU command,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Executes a command with additional options.
    /// </summary>
    /// <param name="command">The APDU command to execute.</param>
    /// <param name="options">Command execution options.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The result of the command execution.</returns>
    Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        CommandOptions options,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Gets the current command context containing state information.
    /// </summary>
    IPipelineContext Context { get; }

    /// <summary>
    /// Creates a new service instance with an updated context.
    /// </summary>
    /// <param name="context">The new context.</param>
    /// <returns>A Result containing a new service instance with the updated context, or an error if the context is null.</returns>
    Result<ISmartCardService, SmartCardError> WithContext(IPipelineContext context);

    /// <summary>
    /// Creates a new service instance with a context value added.
    /// </summary>
    /// <typeparam name="T">The type of the value.</typeparam>
    /// <param name="key">The context key.</param>
    /// <param name="value">The context value.</param>
    /// <returns>A Result containing a new service instance with the updated context, or an error if the context is invalid.</returns>
    Result<ISmartCardService, SmartCardError> WithContextValue<T>(string key, T value);

    /// <summary>
    /// Checks if the service is connected to a smart card.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if connected, false otherwise.</returns>
    Task<Result<bool, SmartCardError>> IsConnectedAsync(
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Gets the Answer To Reset (ATR) from the connected card.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The ATR bytes if available.</returns>
    Task<Result<byte[], SmartCardError>> GetAtrAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the list of available card readers.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of reader names.</returns>
    Task<Result<string[], SmartCardError>> GetReadersAsync(
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Checks if a secure channel is currently established.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if secure channel is established, false otherwise.</returns>
    Task<Result<bool, SmartCardError>> IsSecureChannelEstablishedAsync(
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Sends a raw APDU command to the card.
    /// </summary>
    /// <param name="command">The APDU command bytes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The response from the card.</returns>
    Task<Result<CommandResponse, SmartCardError>> SendCommandAsync(
        byte[] command,
        CancellationToken cancellationToken = default
    );
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

    // CustomMiddleware removed - using functional composition instead

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
    Tcl = 3,
}
