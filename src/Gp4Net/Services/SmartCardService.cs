using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Services;

/// <summary>
/// Smart card service implementation using pipeline architecture.
/// </summary>
public class SmartCardService : ISmartCardService
{
    private readonly ICommandPipeline _pipeline;
    private readonly IPipelineContext _context;
    private readonly IApduTransport _transport;
    private readonly ILogger<SmartCardService> _logger;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of SmartCardService.
    /// </summary>
    public SmartCardService(
        ICommandPipeline pipeline,
        IPipelineContext context,
        IApduTransport transport,
        ILogger<SmartCardService> logger = null)
    {
        _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        _logger = logger;
    }

    /// <inheritdoc/>
    public IPipelineContext Context
    {
        get
        {
            return _context;
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
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(options);

        try
        {
            var request = new CommandRequest(command, _context, options);
            var result = await _pipeline.ExecuteAsync(request, cancellationToken);

            // Update context if command succeeded and context changed
            if (result.IsSuccess)
            {
                return result.Map(response =>
                {
                    // Store the updated context for future commands
                    if (!ReferenceEquals(response.UpdatedContext, _context))
                    {
                        // Note: This is a side effect, but necessary for maintaining state
                        // In a purely functional approach, we'd return a new service instance
                        _logger?.LogTrace("Context updated after command execution");
                    }
                    return response;
                });
            }

            return result;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger?.LogError(ex, "Unexpected error executing command");
            return Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError("Unexpected error executing command", ex));
        }
    }

    /// <inheritdoc/>
    public ISmartCardService WithContext(IPipelineContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return new SmartCardService(_pipeline, context, _transport, _logger);
    }

    /// <inheritdoc/>
    public ISmartCardService WithContextValue<T>(string key, T value)
    {
        var newContext = _context.With(key, value);
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
        // IApduTransport doesn't implement IDisposable
        // Transport lifecycle should be managed by DI container
        // _transport?.Dispose();
        _logger?.LogDebug("Smart card service disposed");
    }
}

/// <summary>
/// Factory implementation for creating smart card services.
/// </summary>
public class SmartCardServiceFactory : ISmartCardServiceFactory
{
    private readonly ILoggerFactory _loggerFactory;
    private readonly IServiceProvider _serviceProvider;

    /// <summary>
    /// Initializes a new instance of SmartCardServiceFactory.
    /// </summary>
    public SmartCardServiceFactory(
        ILoggerFactory loggerFactory = null,
        IServiceProvider serviceProvider = null)
    {
        _loggerFactory = loggerFactory;
        _serviceProvider = serviceProvider;
    }

    /// <inheritdoc/>
    public async Task<Result<ISmartCardService, SmartCardError>> CreateAsync(
        string readerName,
        SmartCardServiceOptions options = null)
    {
        options ??= new SmartCardServiceOptions();

        try
        {
            // Create card context
            var contextResult = await CreateCardContextAsync();
            if (contextResult.IsFailure)
            {
                return Result.Failure<ISmartCardService, SmartCardError>(contextResult.Error);
            }

            var cardContext = contextResult.Value;

            // Connect to card
            var connectResult = await ConnectToCardAsync(cardContext, readerName, options.Protocol);
            if (connectResult.IsFailure)
            {
                cardContext.Dispose();
                return Result.Failure<ISmartCardService, SmartCardError>(connectResult.Error);
            }

            var (cardChannel, protocol) = connectResult.Value;

            // Create transport
            var transport = CreateTransport(cardChannel, protocol);

            // Build pipeline
            var pipeline = BuildPipeline(transport, options);

            // Create initial context
            var context = options.InitialContext ?? new ImmutablePipelineContext();

            // Create service
            var logger = _loggerFactory?.CreateLogger<SmartCardService>();
            var service = new SmartCardService(pipeline, context, transport, logger);

            return Result.Success<ISmartCardService, SmartCardError>(service);
        }
        catch (Exception ex)
        {
            return Result.Failure<ISmartCardService, SmartCardError>(
                SmartCardError.CommunicationError($"Failed to create smart card service: {ex.Message}", ex));
        }
    }

    /// <inheritdoc/>
    public async Task<Result<string[], SmartCardError>> ListReadersAsync()
    {
        try
        {
            var contextResult = await CreateCardContextAsync();
            if (contextResult.IsFailure)
            {
                return Result.Failure<string[], SmartCardError>(contextResult.Error);
            }

            using var cardContext = contextResult.Value;
            var readers = cardContext.GetReaders();
                
            return Result.Success<string[], SmartCardError>(readers);
        }
        catch (Exception ex)
        {
            return Result.Failure<string[], SmartCardError>(
                SmartCardError.CommunicationError($"Failed to list readers: {ex.Message}", ex));
        }
    }

    private static async Task<Result<ICardContext, SmartCardError>> CreateCardContextAsync()
    {
        // The card context should be provided by the tool layer through dependency injection
        // This service should not know about specific implementations like WSCT
        return await Task.FromResult(Result.Failure<ICardContext, SmartCardError>(
            SmartCardError.CommunicationError("Card context must be injected from tool layer")));
    }

    private async Task<Result<(ICardChannel, CardProtocol), SmartCardError>> ConnectToCardAsync(
        ICardContext context,
        string readerName,
        CardProtocol requestedProtocol)
    {
        // Execute synchronous operation on thread pool to avoid blocking
        // This is acceptable as we're bridging legacy synchronous API
        return await Task.Run(() => ConnectToCardSync(context, readerName, requestedProtocol));
    }

    private Result<(ICardChannel, CardProtocol), SmartCardError> ConnectToCardSync(
        ICardContext context,
        string readerName,
        CardProtocol requestedProtocol)
    {
        try
        {
            var channel = context.Connect(readerName, ConvertProtocol(requestedProtocol));
            var actualProtocol = DetectProtocol(channel);
            return Result.Success<(ICardChannel, CardProtocol), SmartCardError>((channel, actualProtocol));
        }
        catch (Exception ex)
        {
            return Result.Failure<(ICardChannel, CardProtocol), SmartCardError>(
                SmartCardError.CommunicationError($"Failed to connect to card: {ex.Message}", ex));
        }
    }

    private static IApduTransport CreateTransport(ICardChannel channel, CardProtocol protocol)
    {
        // Transport creation should be handled by dependency injection
        // For now, create with null loggers as this needs architectural fix
        return protocol switch
        {
            CardProtocol.T0 => new T0ApduTransport(Microsoft.Extensions.Logging.Abstractions.NullLogger<T0ApduTransport>.Instance),
            CardProtocol.T1 => new T1ApduTransport(Microsoft.Extensions.Logging.Abstractions.NullLogger<T1ApduTransport>.Instance),
            CardProtocol.Tcl => new ClApduTransport(
                Microsoft.Extensions.Logging.Abstractions.NullLogger<ClApduTransport>.Instance,
                Microsoft.Extensions.Logging.Abstractions.NullLogger<T1ApduTransport>.Instance),
            _ => new T0ApduTransport(Microsoft.Extensions.Logging.Abstractions.NullLogger<T0ApduTransport>.Instance) // Default to T0
        };
    }

    private ICommandPipeline BuildPipeline(IApduTransport transport, SmartCardServiceOptions options)
    {
        var builder = CommandPipelineBuilder.Create(_serviceProvider);

        // Add logging middleware
        if (options.EnableLogging)
        {
            var logger = _loggerFactory?.CreateLogger<Pipeline.Middleware.LoggingMiddleware>();
            if (logger != null)
            {
                builder.Use(new Pipeline.Middleware.LoggingMiddleware(logger));
            }
        }

        // Add secure channel middleware
        var scLogger = _loggerFactory?.CreateLogger<Pipeline.Middleware.SecureChannelMiddleware>();
        builder.Use(new Pipeline.Middleware.SecureChannelMiddleware(scLogger));

        // Add state capturing middleware
        if (options.EnableStateCapture)
        {
            var stateLogger = _loggerFactory?.CreateLogger<Pipeline.Middleware.StateCapturingMiddleware>();
            builder.Use(new Pipeline.Middleware.StateCapturingMiddleware(stateLogger));
        }

        // Add custom middleware
        if (options.CustomMiddleware != null)
        {
            foreach (var middleware in options.CustomMiddleware)
            {
                builder.Use(middleware);
            }
        }

        // Add transport middleware (terminal)
        var transportLogger = _loggerFactory?.CreateLogger<Pipeline.Middleware.TransportMiddleware>();
        builder.Use(new Pipeline.Middleware.TransportMiddleware(transport, transportLogger));

        return builder.Build();
    }

    private static ShareMode ConvertProtocol(CardProtocol protocol) => protocol switch
    {
        CardProtocol.T0 => ShareMode.Direct,
        CardProtocol.T1 => ShareMode.Direct,
        CardProtocol.Tcl => ShareMode.Direct,
        _ => ShareMode.Shared
    };

    private static CardProtocol DetectProtocol(ICardChannel channel)
    {
        // Map transport protocol to card protocol
        return channel.Protocol switch
        {
            TransportProtocol.T0 => CardProtocol.T0,
            TransportProtocol.T1 => CardProtocol.T1,
            TransportProtocol.Tcl => CardProtocol.Tcl,
            _ => CardProtocol.T0
        };
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
                currentService = currentService.WithContext(response.UpdatedContext);
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