using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Pipeline;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging;
using WSCT.ISO7816;
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
        ILogger<SmartCardService> logger
    )
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
            var context = ImmutablePipelineContext
                .Empty.With("CardChannel", _environment.Channel)
                .With("ApduTransport", _environment.Transport);

            if (_environment.SecureChannel.HasValue)
            {
                context = context.With("SecureChannelSession", _environment.SecureChannel.Value);
            }

            return context;
        }
    }

    /// <inheritdoc/>
    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        CancellationToken cancellationToken = default
    )
    {
        // No secure channel by default - explicit choice required
        return await ExecuteCommandAsync(
            command,
            new CommandOptions(UseSecureChannel: false),
            cancellationToken
        );
    }

    /// <inheritdoc/>
    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        bool useSecureChannel,
        CancellationToken cancellationToken = default
    )
    {
        return await ExecuteCommandAsync(
            command,
            new CommandOptions(UseSecureChannel: useSecureChannel),
            cancellationToken
        );
    }

    /// <inheritdoc/>
    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        CommandOptions options,
        CancellationToken cancellationToken = default
    )
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Create environment with options
        var environmentWithOptions = _environment with
        {
            Options = options,
        };

        // Execute command through functional processor using direct CommandAPDU extension
        var result = await _processor(
            command.AsApduCommand(),
            environmentWithOptions,
            cancellationToken
        );

        // Convert CommandResult to CommandResponse for backward compatibility
        return result.Map(cmdResult => new CommandResponse(
            cmdResult.Data,
            cmdResult.StatusWord,
            Context, // Use the Context property which builds from environment
            new Dictionary<string, object>
            {
                [ResponseMetadata.EXECUTION_TIME] =
                    cmdResult.Metadata?.ExecutionTime.GetValueOrDefault(TimeSpan.Zero)
                    ?? TimeSpan.Zero,
                [ResponseMetadata.TRANSMITTED_BYTES] =
                    cmdResult.Metadata?.TransmittedBytes.GetValueOrDefault([]) ?? [],
                [ResponseMetadata.RECEIVED_BYTES] =
                    cmdResult.Metadata?.ReceivedBytes.GetValueOrDefault([]) ?? [],
                [ResponseMetadata.SECURE_CHANNEL_WRAPPED] =
                    cmdResult.Metadata?.SecureChannelWrapped ?? false,
            }
        ));
    }

    /// <inheritdoc/>
    public Result<ISmartCardService, SmartCardError> WithContext(IPipelineContext context)
    {
        // Extract values from context to build new environment using functional composition
        var channelResult = context
            .Get<ICardChannel>("CardChannel")
            .ToResult(SmartCardError.InvalidArgument("Context must contain CardChannel"));
        var transportResult = context
            .Get<IApduTransport>("ApduTransport")
            .ToResult(SmartCardError.InvalidArgument("Context must contain ApduTransport"));
        var secureChannel = context.Get<SecureChannelState>("SecureChannelSession");

        return channelResult
            .Bind(channel =>
                transportResult.Map(transport => new CommandEnvironment(
                    channel,
                    transport,
                    secureChannel,
                    _logger,
                    _environment.Options
                ))
            )
            .Map(newEnvironment =>
                (ISmartCardService)new SmartCardService(newEnvironment, _processor, _logger)
            );
    }

    /// <inheritdoc/>
    public Result<ISmartCardService, SmartCardError> WithContextValue<T>(string key, T value)
    {
        // Special handling for known context values
        if (key == "SecureChannelSession" && value is SecureChannelState secureChannel)
        {
            var newEnvironment = _environment.WithSecureChannel(secureChannel);
            return Result.Success<ISmartCardService, SmartCardError>(
                new SmartCardService(newEnvironment, _processor, _logger)
            );
        }

        // For other values, use the context-based approach
        var newContext = Context.With(key, value);
        return WithContext(newContext);
    }

    /// <inheritdoc/>
    public async Task<Result<bool, SmartCardError>> IsConnectedAsync(
        CancellationToken cancellationToken = default
    )
    {
        return await Task.FromResult(
            Maybe<ICardChannel>
                .From(_environment.Channel)
                .Bind(_ => Maybe<IApduTransport>.From(_environment.Transport))
                .Match(
                    _ => Result.Success<bool, SmartCardError>(true),
                    () => Result.Success<bool, SmartCardError>(false)
                )
        );
    }

    /// <inheritdoc/>
    public Task<Result<byte[], SmartCardError>> GetAtrAsync(
        CancellationToken cancellationToken = default
    )
    {
        // ATR is not directly available from ICardChannel interface
        // Would need to be stored during connection establishment
        return Task.FromResult(
            Result.Failure<byte[], SmartCardError>(
                SmartCardError.CommunicationError(
                    "ATR not available from current channel interface"
                )
            )
        );
    }

    /// <inheritdoc/>
    public async Task<Result<string[], SmartCardError>> GetReadersAsync(
        CancellationToken cancellationToken = default
    )
    {
        return await Task.FromResult(Result.Success<string[], SmartCardError>(["Default Reader"]));
    }

    /// <inheritdoc/>
    public async Task<Result<bool, SmartCardError>> IsSecureChannelEstablishedAsync(
        CancellationToken cancellationToken = default
    )
    {
        return await Task.FromResult(
            Result.Success<bool, SmartCardError>(_environment.SecureChannel.HasValue)
        );
    }

    /// <inheritdoc/>
    public async Task<Result<CommandResponse, SmartCardError>> SendCommandAsync(
        byte[] command,
        CancellationToken cancellationToken = default
    )
    {
        var parseResult = ParseApduCommand(command);
        if (parseResult.IsFailure)
        {
            return Result.Failure<CommandResponse, SmartCardError>(parseResult.Error);
        }

        return await ExecuteCommandAsync(parseResult.Value, cancellationToken);
    }

    private static Result<CommandAPDU, SmartCardError> ParseApduCommand(byte[] command)
    {
        return command.Length switch
        {
            4
                => Result.Success<CommandAPDU, SmartCardError>(
                    new CommandAPDU(command[0], command[1], command[2], command[3])
                ),
            5
                => Result.Success<CommandAPDU, SmartCardError>(
                    new CommandAPDU(
                        command[0],
                        command[1],
                        command[2],
                        command[3],
                        (uint)(command[4] == 0 ? 256 : command[4])
                    )
                ),
            > 5 => ParseApduWithData(command),
            _
                => Result.Failure<CommandAPDU, SmartCardError>(
                    SmartCardError.InvalidArgument("Invalid APDU command length")
                ),
        };
    }

    private static Result<CommandAPDU, SmartCardError> ParseApduWithData(byte[] command)
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
            return Result.Success<CommandAPDU, SmartCardError>(
                new CommandAPDU(cla, ins, p1, p2, (uint)data.Length, data)
            );
        }
        if (command.Length == 5 + lc + 1)
        {
            // Case 4: command with data and expected response
            byte[] data = new byte[lc];
            Array.Copy(command, 5, data, 0, lc);
            byte le = command[5 + lc];
            int expectedLength = le == 0 ? 256 : le;
            return Result.Success<CommandAPDU, SmartCardError>(
                new CommandAPDU(cla, ins, p1, p2, (uint)data.Length, data, (uint)expectedLength)
            );
        }

        return Result.Failure<CommandAPDU, SmartCardError>(
            SmartCardError.InvalidArgument("Invalid APDU command format")
        );
    }

    /// <inheritdoc/>
    public async Task<
        Result<CardTransportCapabilities, SmartCardError>
    > GetCardTransportCapabilitiesAsync(CancellationToken cancellationToken = default)
    {
        // Create detector and probe capabilities
        var detector = new CardCapabilityDetector(
            new Microsoft.Extensions.Logging.Abstractions.NullLogger<CardCapabilityDetector>()
        );

        var result = await detector.DetectCapabilitiesAsync(this, cancellationToken);

        // Log the result if successful
        result.Match(
            capabilities =>
            {
                _logger.LogInformation(
                    "Card transport capabilities detected - Extended APDU: {ExtendedSupport}, Block size: {BlockSize}",
                    capabilities.SupportsExtendedApdu,
                    capabilities.OptimalBlockSize
                );
            },
            error =>
                _logger.LogWarning("Failed to detect card transport capabilities: {Error}", error)
        );

        return result;
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
        CommandAPDU[] commands,
        CancellationToken cancellationToken = default
    )
    {
        var responses = new CommandResponse[commands.Length];
        var currentService = service;

        for (int i = 0; i < commands.Length; i++)
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
        CommandAPDU command,
        Func<CommandResponse, T> mapper,
        CancellationToken cancellationToken = default
    )
    {
        var result = await service.ExecuteCommandAsync(command, cancellationToken);
        return result.Map(mapper);
    }
}
