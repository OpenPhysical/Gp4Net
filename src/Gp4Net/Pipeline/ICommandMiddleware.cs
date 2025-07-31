using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Pipeline
{
    /// <summary>
    /// Represents a middleware component in the command pipeline.
    /// </summary>
    public interface ICommandMiddleware
    {
        /// <summary>
        /// Processes a command request, potentially modifying it before passing to the next middleware.
        /// </summary>
        /// <param name="request">The command request to process.</param>
        /// <param name="next">The next middleware in the pipeline.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The result of the command execution.</returns>
        Task<Result<CommandResponse, SmartCardError>> InvokeAsync(
            CommandRequest request,
            CommandDelegate next,
            CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Delegate representing the next middleware in the pipeline.
    /// </summary>
    public delegate Task<Result<CommandResponse, SmartCardError>> CommandDelegate(
        CommandRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Base class for middleware that provides common functionality.
    /// </summary>
    public abstract class CommandMiddlewareBase : ICommandMiddleware
    {
        /// <inheritdoc/>
        public abstract Task<Result<CommandResponse, SmartCardError>> InvokeAsync(
            CommandRequest request,
            CommandDelegate next,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Helper method to update the context in a response.
        /// </summary>
        protected static Result<CommandResponse, SmartCardError> UpdateContext(
            Result<CommandResponse, SmartCardError> result,
            IPipelineContext newContext) =>
            result.Map(response => response.WithContext(newContext));

        /// <summary>
        /// Helper method to add metadata to a response.
        /// </summary>
        protected static Result<CommandResponse, SmartCardError> AddMetadata(
            Result<CommandResponse, SmartCardError> result,
            string key,
            object value) =>
            result.Map(response => response.WithMetadata(key, value));
    }
}