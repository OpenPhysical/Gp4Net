using System;
using System.Threading.Tasks;
using Gp4Net.Tool.Services;
using Spectre.Console;
using WSCT.Core;

namespace Gp4Net.Tool.Pipeline
{
    /// <summary>
    /// Provides context and services for command execution.
    /// </summary>
    public interface ICommandContext
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
        /// </summary>
        IGlobalPlatformService GlobalPlatformService { get; }

        /// <summary>
        /// Gets the keyset resolver for key management.
        /// </summary>
        IKeysetResolver KeysetResolver { get; }

        /// <summary>
        /// Ensures a card connection is established with the specified reader.
        /// </summary>
        Task<ICommandContext> RequireCardConnection(string? readerName = null);

        /// <summary>
        /// Ensures a secure channel is established with the specified security level.
        /// </summary>
        Task<ICommandContext> RequireSecureChannel(byte securityLevel = 1, string? keyset = null);

        /// <summary>
        /// Executes the command logic with the current context.
        /// </summary>
        Task<int> ExecuteAsync(Func<ICommandContext, Task<int>> commandLogic);

        /// <summary>
        /// Executes the command logic with the current context synchronously.
        /// </summary>
        Task<int> ExecuteAsync(Func<ICommandContext, int> commandLogic);
    }
}
