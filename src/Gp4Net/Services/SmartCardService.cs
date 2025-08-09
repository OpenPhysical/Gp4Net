using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Security;
using Gp4Net.Pipeline;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging;
using static Gp4Net.Pipeline.CommandProcessing;
using Microsoft.Extensions.Logging.Abstractions;

namespace Gp4Net.Services;

/// <summary>
/// Smart card service implementation using functional command processing.
/// </summary>
public class SmartCardService : ISmartCardService
{
    private readonly CommandEnvironment _environment;
    private readonly CommandProcessor _processor;
    private readonly ILogger<SmartCardService> _logger;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of SmartCardService.
    /// </summary>
    public SmartCardService(
        CommandEnvironment environment,
        CommandProcessor processor,
        ILogger<SmartCardService> logger)
    {
        _environment = environment;
        _processor = processor;
        _logger = logger;
    }

    /// <inheritdoc/>
    public IPipelineContext Context
    {
        get
        {
            // Build context from environment for backward compatibility
            var context = ImmutablePipelineContext.Empty
                .With<ICardChannel>("CardChannel", _environment.Channel)
                .With<IApduTransport>("ApduTransport", _environment.Transport);
                
            if (_environment.SecureChannel.HasValue)
            {
                context = context.With("SecureChannelSession", _environment.SecureChannel.Value);
            }
                
            return context;
        }
    }

    /// <inheritdoc/>
    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        IApduCommand command,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteCommandAsync(command, CommandOptions.Default, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        IApduCommand command,
        CommandOptions options,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        
        // Create environment with options
        var environmentWithOptions = _environment with { Options = options };
        
        try
        {
            // Execute command through functional processor
            var result = await _processor(command, environmentWithOptions, cancellationToken);
            
            // Convert CommandResult to CommandResponse for backward compatibility
            return result.Map(cmdResult => new CommandResponse(
                cmdResult.Data,
                cmdResult.StatusWord,
                Context, // Use the Context property which builds from environment
                new System.Collections.Generic.Dictionary<string, object>
                {
                    [ResponseMetadata.ExecutionTime] = cmdResult.Metadata?.ExecutionTime ?? TimeSpan.Zero,
                    [ResponseMetadata.TransmittedBytes] = cmdResult.Metadata?.TransmittedBytes ?? Array.Empty<byte>(),
                    [ResponseMetadata.ReceivedBytes] = cmdResult.Metadata?.ReceivedBytes ?? Array.Empty<byte>(),
                    [ResponseMetadata.SecureChannelWrapped] = cmdResult.Metadata?.SecureChannelWrapped ?? false,
                    [ResponseMetadata.RetryCount] = cmdResult.Metadata?.RetryCount ?? 0
                }));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Unexpected error executing command");
            return Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError("Unexpected error executing command", Maybe<Exception>.From(ex)));
        }
    }

    /// <inheritdoc/>
    public Result<ISmartCardService, SmartCardError> WithContext(IPipelineContext context)
    {
        // Extract values from context to build new environment
        var channel = context.Get<ICardChannel>("CardChannel");
        var transport = context.Get<IApduTransport>("ApduTransport");
        var secureChannel = context.Get<SecureChannelState>("SecureChannelSession");
        
        if (!channel.HasValue || !transport.HasValue)
        {
            return Result.Failure<ISmartCardService, SmartCardError>(
                SmartCardError.InvalidArgument("Context must contain CardChannel and ApduTransport"));
        }
        
        var newEnvironment = new CommandEnvironment(
            channel.Value,
            transport.Value,
            secureChannel,
            _logger,
            _environment.Options);
            
        return Result.Success<ISmartCardService, SmartCardError>(
            new SmartCardService(newEnvironment, _processor, _logger));
    }

    /// <inheritdoc/>
    public Result<ISmartCardService, SmartCardError> WithContextValue<T>(string key, T value)
    {
        // Special handling for known context values
        if (key == "SecureChannelSession" && value is SecureChannelState secureChannel)
        {
            var newEnvironment = _environment.WithSecureChannel(secureChannel);
            return Result.Success<ISmartCardService, SmartCardError>(
                new SmartCardService(newEnvironment, _processor, _logger));
        }
        
        // For other values, use the context-based approach
        var newContext = Context.With(key, value);
        return WithContext(newContext);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _logger.LogDebug("Smart card service disposed");
    }
}

/// <summary>
/// Extension methods for smart card service.
/// </summary>
public static class SmartCardServiceExtensions
{
    /// <summary>
    /// Executes multiple commands in sequence, threading context through.
    /// </summary>
    public static async Task<Result<CommandResponse[], SmartCardError>> ExecuteCommandsAsync(
        this ISmartCardService service,
        IApduCommand[] commands,
        CancellationToken cancellationToken = default)
    {
        var responses = new CommandResponse[commands.Length];
        var currentService = service;

        for (var i = 0; i < commands.Length; i++)
        {
            var result = await currentService.ExecuteCommandAsync(commands[i], cancellationToken);
                
            if (result.IsFailure)
            {
                return Result.Failure<CommandResponse[], SmartCardError>(result.Error);
            }

            var response = result.Value;
            responses[i] = response;

            // Update service with new context for next command
            if (!ReferenceEquals(response.UpdatedContext, currentService.Context))
            {
                var contextResult = currentService.WithContext(response.UpdatedContext);
                if (contextResult.IsFailure)
                {
                    return Result.Failure<CommandResponse[], SmartCardError>(contextResult.Error);
                }
                currentService = contextResult.Value;
            }
        }

        return Result.Success<CommandResponse[], SmartCardError>(responses);
    }

    /// <summary>
    /// Executes a command and maps the successful response.
    /// </summary>
    public static async Task<Result<T, SmartCardError>> ExecuteAndMapAsync<T>(
        this ISmartCardService service,
        IApduCommand command,
        Func<CommandResponse, T> mapper,
        CancellationToken cancellationToken = default)
    {
        var result = await service.ExecuteCommandAsync(command, cancellationToken);
        return result.Map(mapper);
    }
}