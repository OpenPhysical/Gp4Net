using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;

namespace Gp4Net.Pipeline
{
    /// <summary>
    /// Represents a pipeline for executing APDU commands with middleware processing.
    /// </summary>
    public interface ICommandPipeline
    {
        /// <summary>
        /// Executes a command through the pipeline.
        /// </summary>
        /// <param name="command">The APDU command to execute.</param>
        /// <param name="context">The command context.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The result of the command execution.</returns>
        Task<Result<CommandResponse, SmartCardError>> ExecuteAsync(
            IApduCommand command,
            IPipelineContext context,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Executes a command request through the pipeline.
        /// </summary>
        /// <param name="request">The command request.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The result of the command execution.</returns>
        Task<Result<CommandResponse, SmartCardError>> ExecuteAsync(
            CommandRequest request,
            CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Builder interface for constructing command pipelines.
    /// </summary>
    public interface ICommandPipelineBuilder
    {
        /// <summary>
        /// Adds a middleware to the pipeline.
        /// </summary>
        /// <typeparam name="TMiddleware">The type of middleware to add.</typeparam>
        /// <returns>The builder for chaining.</returns>
        ICommandPipelineBuilder Use<TMiddleware>() where TMiddleware : ICommandMiddleware, new();

        /// <summary>
        /// Adds a middleware instance to the pipeline.
        /// </summary>
        /// <param name="middleware">The middleware instance.</param>
        /// <returns>The builder for chaining.</returns>
        ICommandPipelineBuilder Use(ICommandMiddleware middleware);

        /// <summary>
        /// Adds a middleware delegate to the pipeline.
        /// </summary>
        /// <param name="middleware">The middleware delegate.</param>
        /// <returns>The builder for chaining.</returns>
        ICommandPipelineBuilder Use(MiddlewareDelegate middleware);

        /// <summary>
        /// Builds the pipeline.
        /// </summary>
        /// <returns>The constructed pipeline.</returns>
        ICommandPipeline Build();
    }

    /// <summary>
    /// Delegate for inline middleware definitions.
    /// </summary>
    public delegate Task<Result<CommandResponse, SmartCardError>> MiddlewareDelegate(
        CommandRequest request,
        CommandDelegate next,
        CancellationToken cancellationToken);
}