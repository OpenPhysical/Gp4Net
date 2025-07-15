using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Gp4Net.Core;
using Gp4Net.Services;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Pipeline
{
    /// <summary>
    /// Default implementation of the command pipeline.
    /// </summary>
    public class CommandPipeline : ICommandPipeline
    {
        private readonly CommandDelegate _pipeline;
        private readonly ILogger<CommandPipeline>? _logger;

        /// <summary>
        /// Initializes a new instance of CommandPipeline.
        /// </summary>
        public CommandPipeline(CommandDelegate pipeline, ILogger<CommandPipeline>? logger = null)
        {
            _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
            _logger = logger;
        }

        /// <inheritdoc/>
        public Task<Result<CommandResponse, SmartCardError>> ExecuteAsync(
            IApduCommand command,
            ICommandContext context,
            CancellationToken cancellationToken = default)
        {
            var request = new CommandRequest(command, context);
            return ExecuteAsync(request, cancellationToken);
        }

        /// <inheritdoc/>
        public async Task<Result<CommandResponse, SmartCardError>> ExecuteAsync(
            CommandRequest request,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(request);

            try
            {
                _logger?.LogTrace("Executing command {CommandType} through pipeline", 
                    request.Command.GetType().Name);

                var result = await _pipeline(request, cancellationToken).ConfigureAwait(false);

                if (result.IsSuccess && _logger?.IsEnabled(LogLevel.Trace) == true)
                {
                    result.Match<Core.Unit>(
                        success => { _logger.LogTrace("Command succeeded with SW={SW:X4}", success.StatusWord); return Core.Unit.Value; },
                        failure => { _logger.LogTrace("Command failed: {Error}", failure.Message); return Core.Unit.Value; });
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Pipeline execution failed");
                return Result<CommandResponse, SmartCardError>.Fail(
                    SmartCardError.CommunicationError("Pipeline execution failed", ex));
            }
        }
    }

    /// <summary>
    /// Builder for constructing command pipelines.
    /// </summary>
    public class CommandPipelineBuilder : ICommandPipelineBuilder
    {
        private readonly List<Func<CommandDelegate, CommandDelegate>> _components = new();
        private readonly IServiceProvider? _serviceProvider;
        private readonly ILogger<CommandPipeline>? _logger;

        /// <summary>
        /// Initializes a new instance of CommandPipelineBuilder.
        /// </summary>
        public CommandPipelineBuilder(IServiceProvider? serviceProvider = null)
        {
            _serviceProvider = serviceProvider;
            _logger = serviceProvider?.GetService(typeof(ILogger<CommandPipeline>)) as ILogger<CommandPipeline>;
        }

        /// <inheritdoc/>
        public ICommandPipelineBuilder Use<TMiddleware>() where TMiddleware : ICommandMiddleware, new()
        {
            var middleware = new TMiddleware();
            return Use(middleware);
        }

        /// <inheritdoc/>
        public ICommandPipelineBuilder Use(ICommandMiddleware middleware)
        {
            ArgumentNullException.ThrowIfNull(middleware);

            _components.Add(next => 
                (request, ct) => middleware.InvokeAsync(request, next, ct));
            
            return this;
        }

        /// <inheritdoc/>
        public ICommandPipelineBuilder Use(MiddlewareDelegate middleware)
        {
            ArgumentNullException.ThrowIfNull(middleware);

            _components.Add(next => 
                (request, ct) => middleware(request, next, ct));
            
            return this;
        }

        /// <inheritdoc/>
        public ICommandPipeline Build()
        {
            CommandDelegate pipeline = (request, ct) =>
            {
                // Terminal middleware - should never be reached if pipeline is properly constructed
                var error = SmartCardError.CommunicationError(
                    "Pipeline terminated without handling the command. Ensure a terminal middleware (like TransportMiddleware) is registered.");
                return Task.FromResult(Result<CommandResponse, SmartCardError>.Fail(error));
            };

            // Build pipeline in reverse order
            foreach (var component in _components.AsEnumerable().Reverse())
            {
                pipeline = component(pipeline);
            }

            return new CommandPipeline(pipeline, _logger);
        }

        /// <summary>
        /// Creates a new pipeline builder.
        /// </summary>
        public static ICommandPipelineBuilder Create(IServiceProvider? serviceProvider = null) =>
            new CommandPipelineBuilder(serviceProvider);
    }

    /// <summary>
    /// Extension methods for pipeline building.
    /// </summary>
    public static class PipelineBuilderExtensions
    {
        /// <summary>
        /// Adds a conditional middleware to the pipeline.
        /// </summary>
        public static ICommandPipelineBuilder UseWhen(
            this ICommandPipelineBuilder builder,
            Func<CommandRequest, bool> condition,
            ICommandMiddleware middleware)
        {
            return builder.Use(async (request, next, ct) =>
            {
                if (condition(request))
                {
                    return await middleware.InvokeAsync(request, next, ct);
                }
                return await next(request, ct);
            });
        }

        /// <summary>
        /// Adds an inline middleware using a lambda.
        /// </summary>
        public static ICommandPipelineBuilder Use(
            this ICommandPipelineBuilder builder,
            Func<CommandRequest, CommandDelegate, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> middleware)
        {
            return builder.Use(new MiddlewareDelegate(middleware));
        }

        /// <summary>
        /// Branches the pipeline based on a condition.
        /// </summary>
        public static ICommandPipelineBuilder Branch(
            this ICommandPipelineBuilder builder,
            Func<CommandRequest, bool> condition,
            Action<ICommandPipelineBuilder> configureBranch)
        {
            var branchBuilder = new CommandPipelineBuilder();
            configureBranch(branchBuilder);
            var branchPipeline = branchBuilder.Build();

            return builder.Use(async (request, next, ct) =>
            {
                if (condition(request))
                {
                    return await branchPipeline.ExecuteAsync(request, ct);
                }
                return await next(request, ct);
            });
        }
    }
}