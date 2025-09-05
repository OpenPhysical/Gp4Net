using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Services;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Provides context and services for CLI command execution.
/// This is separate from the core pipeline's IPipelineContext.
/// </summary>
public interface ICliExecutionContext
{
    /// <summary>
    /// Gets the display service for console output.
    /// </summary>
    IDisplayService Display { get; }

    /// <summary>
    /// Gets the smart card service for functional card operations.
    /// </summary>
    ISmartCardService CardService { get; }

    /// <summary>
    /// Gets the keyset resolver for resolving keysets by name or parameters.
    /// </summary>
    IKeysetResolver KeysetResolver { get; }


    /// <summary>
    /// Gets a pure function for establishing secure channels from user requests.
    /// Eliminates imperative keyset resolution patterns in commands.
    /// </summary>
    Func<
        SecureChannelRequest,
        CancellationToken,
        Task<Result<SecureChannelExecutionContext, SmartCardError>>
    > EstablishSecureChannelAsync { get; }

    /// <summary>
    /// Ensures a card connection is established with the specified reader.
    /// </summary>
    Task<Result<ICliExecutionContext, SmartCardError>> RequireCardConnection(
        Maybe<string> readerName = default
    );

    /// <summary>
    /// Ensures a secure channel is established with the specified security level.
    /// </summary>
    Task<Result<ICliExecutionContext, SmartCardError>> RequireSecureChannel(
        byte securityLevel = 1,
        Maybe<string> keyset = default
    );

    /// <summary>
    /// Executes the command logic with the current context.
    /// </summary>
    Task<int> ExecuteAsync(Func<ICliExecutionContext, Task<int>> commandLogic);

    /// <summary>
    /// Executes the command logic with the current context synchronously.
    /// </summary>
    Task<int> ExecuteAsync(Func<ICliExecutionContext, int> commandLogic);
}
