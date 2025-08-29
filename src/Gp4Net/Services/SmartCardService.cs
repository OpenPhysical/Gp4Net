using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Security;
using Gp4Net.Pipeline;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging;
using static Gp4Net.Pipeline.CommandProcessing;

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
            IPipelineContext context = ImmutablePipelineContext.Empty
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
        CommandEnvironment environmentWithOptions = _environment with { Options = options };

        try
        {
            // Execute command through functional processor
            Result<CommandResult, SmartCardError> result = await _processor(command, environmentWithOptions, cancellationToken);

            // Convert CommandResult to CommandResponse for backward compatibility
            return result.Map(cmdResult => new CommandResponse(
                cmdResult.Data,
                cmdResult.StatusWord,
                Context, // Use the Context property which builds from environment
                new System.Collections.Generic.Dictionary<string, object>
                {
                    [ResponseMetadata.ExecutionTime] = cmdResult.Metadata?.ExecutionTime ?? TimeSpan.Zero,
                    [ResponseMetadata.TransmittedBytes] = cmdResult.Metadata?.TransmittedBytes ?? [],
                    [ResponseMetadata.ReceivedBytes] = cmdResult.Metadata?.ReceivedBytes ?? [],
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
        // Extract values from context to build new environment using functional composition
        Result<ICardChannel, SmartCardError> channelResult = context.Get<ICardChannel>("CardChannel")
            .ToResult(SmartCardError.InvalidArgument("Context must contain CardChannel"));
        Result<IApduTransport, SmartCardError> transportResult = context.Get<IApduTransport>("ApduTransport")
            .ToResult(SmartCardError.InvalidArgument("Context must contain ApduTransport"));
        Maybe<SecureChannelState> secureChannel = context.Get<Domain.SecureChannelState>("SecureChannelSession");

        return channelResult
            .Bind(channel => transportResult
                .Map(transport => new CommandEnvironment(
                    channel,
                    transport,
                    secureChannel,
                    _environment.SecureChannelService,
                    _logger,
                    _environment.Options)))
            .Map(newEnvironment => (ISmartCardService)new SmartCardService(newEnvironment, _processor, _logger));
    }

    /// <inheritdoc/>
    public Result<ISmartCardService, SmartCardError> WithContextValue<T>(string key, T value)
    {
        // Special handling for known context values
        if (key == "SecureChannelSession" && value is Domain.SecureChannelState secureChannel)
        {
            CommandEnvironment newEnvironment = _environment.WithSecureChannel(secureChannel);
            return Result.Success<ISmartCardService, SmartCardError>(
                new SmartCardService(newEnvironment, _processor, _logger));
        }

        // For other values, use the context-based approach
        IPipelineContext newContext = Context.With(key, value);
        return WithContext(newContext);
    }

    /// <inheritdoc/>
    public async Task<Result<bool, SmartCardError>> IsConnectedAsync(CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(
            Maybe<ICardChannel>.From(_environment.Channel)
                .Bind(_ => Maybe<IApduTransport>.From(_environment.Transport))
                .Match(
                    _ => Result.Success<bool, SmartCardError>(true),
                    () => Result.Success<bool, SmartCardError>(false)));
    }

    /// <inheritdoc/>
    public Task<Result<byte[], SmartCardError>> GetAtrAsync(CancellationToken cancellationToken = default)
    {
        // ATR is not directly available from ICardChannel interface
        // Would need to be stored during connection establishment
        return Task.FromResult(
            Result.Failure<byte[], SmartCardError>(
                SmartCardError.CommunicationError("ATR not available from current channel interface")));
    }

    /// <inheritdoc/>
    public async Task<Result<string[], SmartCardError>> GetReadersAsync(CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(
            Result.Success<string[], SmartCardError>(["Default Reader"]));
    }

    /// <inheritdoc/>
    public async Task<Result<bool, SmartCardError>> IsSecureChannelEstablishedAsync(CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(
            Result.Success<bool, SmartCardError>(_environment.SecureChannel.HasValue));
    }

    /// <inheritdoc/>
    public async Task<Result<CommandResponse, SmartCardError>> SendCommandAsync(
        byte[] command,
        CancellationToken cancellationToken = default)
    {
        Result<IApduCommand, SmartCardError> parseResult = ParseApduCommand(command);
        if (parseResult.IsFailure)
        {
            return Result.Failure<CommandResponse, SmartCardError>(parseResult.Error);
        }
        
        return await ExecuteCommandAsync(parseResult.Value, cancellationToken);
    }
    
    private static Result<IApduCommand, SmartCardError> ParseApduCommand(byte[] command)
    {
        return command.Length switch
        {
            4 => Result.Success<IApduCommand, SmartCardError>(
                new SimpleApduCommand(command[0], command[1], command[2], command[3], [], Maybe<int>.None)),
            5 => Result.Success<IApduCommand, SmartCardError>(
                new SimpleApduCommand(command[0], command[1], command[2], command[3], [], 
                    Maybe<int>.From(command[4] == 0 ? 256 : command[4]))),
            _ when command.Length > 5 => ParseApduWithData(command),
            _ => Result.Failure<IApduCommand, SmartCardError>(
                SmartCardError.InvalidArgument("Invalid APDU command length"))
        };
    }
    
    private static Result<IApduCommand, SmartCardError> ParseApduWithData(byte[] command)
    {
        byte cla = command[0];
        byte ins = command[1];
        byte p1 = command[2];
        byte p2 = command[3];
        byte lc = command[4];
        
        if (command.Length == 5 + lc)
        {
            // Case 3: command with data, no response expected
            byte[] data = new byte[lc];
            Array.Copy(command, 5, data, 0, lc);
            return Result.Success<IApduCommand, SmartCardError>(
                new SimpleApduCommand(cla, ins, p1, p2, data, Maybe<int>.None));
        }
        else if (command.Length == 5 + lc + 1)
        {
            // Case 4: command with data and expected response
            byte[] data = new byte[lc];
            Array.Copy(command, 5, data, 0, lc);
            byte le = command[5 + lc];
            int expectedLength = le == 0 ? 256 : le;
            return Result.Success<IApduCommand, SmartCardError>(
                new SimpleApduCommand(cla, ins, p1, p2, data, Maybe<int>.From(expectedLength)));
        }
        
        return Result.Failure<IApduCommand, SmartCardError>(
            SmartCardError.InvalidArgument("Invalid APDU command format"));
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
        CommandResponse[] responses = new CommandResponse[commands.Length];
        ISmartCardService currentService = service;

        for (int i = 0; i < commands.Length; i++)
        {
            Result<CommandResponse, SmartCardError> result = await currentService.ExecuteCommandAsync(commands[i], cancellationToken);

            if (result.IsFailure)
            {
                return Result.Failure<CommandResponse[], SmartCardError>(result.Error);
            }

            CommandResponse response = result.Value;
            responses[i] = response;

            // Update service with new context for next command
            if (!ReferenceEquals(response.UpdatedContext, currentService.Context))
            {
                Result<ISmartCardService, SmartCardError> contextResult = currentService.WithContext(response.UpdatedContext);
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
        Result<CommandResponse, SmartCardError> result = await service.ExecuteCommandAsync(command, cancellationToken);
        return result.Map(mapper);
    }
}

/// <summary>
/// Simple APDU command implementation for raw command execution.
/// </summary>
internal class SimpleApduCommand : IApduCommand
{
    /// <inheritdoc/>
    public byte Cla { get; }

    /// <inheritdoc/>
    public byte Ins { get; }

    /// <inheritdoc/>
    public byte P1 { get; }

    /// <inheritdoc/>
    public byte P2 { get; }

    /// <inheritdoc/>
    public byte[] Data { get; }

    /// <inheritdoc/>
    public Maybe<int> ExpectedResponseLength { get; }

    /// <inheritdoc/>
    public bool IsExtendedLength => 
        Data.Length > 255 || ExpectedResponseLength.GetValueOrDefault(0) > 256;

    /// <summary>
    /// Initializes a new instance of SimpleApduCommand.
    /// </summary>
    public SimpleApduCommand(
        byte cla, 
        byte ins, 
        byte p1, 
        byte p2, 
        byte[] data, 
        Maybe<int> expectedResponseLength)
    {
        Cla = cla;
        Ins = ins;
        P1 = p1;
        P2 = p2;
        Data = data ?? [];
        ExpectedResponseLength = expectedResponseLength;
    }
}