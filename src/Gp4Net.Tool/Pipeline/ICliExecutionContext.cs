using System;
using System.Threading.Tasks;
using Gp4Net.Tool.Services;
using Spectre.Console;
using WSCT.Core;

namespace Gp4Net.Tool.Pipeline
{
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
        /// Gets the card service for smart card operations.
        /// </summary>
        ICardService CardService { get; }

        /// <summary>
        /// Gets the GlobalPlatform service for GP operations.
        /// Creates the service on demand with proper pipeline context.
        /// </summary>
        Gp4Net.Services.IGlobalPlatformService GetGlobalPlatformService();

        /// <summary>
        /// Gets the keyset resolver for key management.
        /// </summary>
        IKeysetResolver KeysetResolver { get; }

        /// <summary>
        /// Ensures a card connection is established with the specified reader.
        /// </summary>
        Task<ICliExecutionContext> RequireCardConnection(string? readerName = null);

        /// <summary>
        /// Ensures a secure channel is established with the specified security level.
        /// </summary>
        Task<ICliExecutionContext> RequireSecureChannel(byte securityLevel = 1, string? keyset = null);

        /// <summary>
        /// Executes the command logic with the current context.
        /// </summary>
        Task<int> ExecuteAsync(Func<ICliExecutionContext, Task<int>> commandLogic);

        /// <summary>
        /// Executes the command logic with the current context synchronously.
        /// </summary>
        Task<int> ExecuteAsync(Func<ICliExecutionContext, int> commandLogic);
    }
}
