using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Tests.TestHelpers;

/// <summary>
/// Test implementation of ISmartCardService that wraps VirtualCardService.
/// Eliminates adapter casting issues by implementing the current ISmartCardService directly.
/// Preserves all original functionality while adapting to new async Result-based interface.
/// </summary>
[PublicAPI]
public class TestCardService : ISmartCardService
{
    private readonly VirtualCardService _virtualCardService;
    private readonly IPipelineContext _context;
    private readonly Maybe<string> _connectedReaderName;
    private readonly bool _secureChannelEstablished;

    public TestCardService(VirtualCardService virtualCardService)
    {
        _virtualCardService = virtualCardService;
        _context = ImmutablePipelineContext.Empty;
        _connectedReaderName = Maybe<string>.None;
        _secureChannelEstablished = false;

        // Ensure connection to first reader for tests - preserve original functionality
        VirtualReaderManager readerManager = _virtualCardService.GetReaderManager();
        IReadOnlyList<string> readerNames = readerManager.GetReaderNames();
        if (readerNames.Count > 0)
        {
            string firstReader = readerNames[0];
            _ = _virtualCardService.Connect(firstReader);
        }
    }

    private TestCardService(
        VirtualCardService virtualCardService,
        IPipelineContext context,
        Maybe<string> connectedReaderName,
        bool secureChannelEstablished)
    {
        _virtualCardService = virtualCardService;
        _context = context;
        _connectedReaderName = connectedReaderName;
        _secureChannelEstablished = secureChannelEstablished;
    }

    public IPipelineContext Context => _context;

    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        IApduCommand command,
        CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(
            ConvertIApduCommandToBytes(command)
                .Bind(commandBytes => SendCommandAsyncInternal(commandBytes)));
    }

    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        IApduCommand command,
        CommandOptions options,
        CancellationToken cancellationToken = default)
    {
        // Preserve original functionality by ignoring options for test scenarios
        return await ExecuteCommandAsync(command, cancellationToken);
    }

    public Result<ISmartCardService, SmartCardError> WithContext(IPipelineContext context)
    {
        return Maybe<IPipelineContext>.From(context)
            .ToResult(SmartCardError.InvalidArgument("Context cannot be null"))
            .Map(validContext => (ISmartCardService)new TestCardService(_virtualCardService, validContext, _connectedReaderName, _secureChannelEstablished));
    }

    public Result<ISmartCardService, SmartCardError> WithContextValue<T>(string key, T value)
    {
        IPipelineContext? newContext = _context.With(key, value);
        return Result.Success<ISmartCardService, SmartCardError>(
            new TestCardService(_virtualCardService, newContext, _connectedReaderName, _secureChannelEstablished));
    }

    public async Task<Result<bool, SmartCardError>> IsConnectedAsync(CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(
            _connectedReaderName.Match(
                readerName => Result.Success<bool, SmartCardError>(true),
                () => Result.Success<bool, SmartCardError>(false)));
    }

    public async Task<Result<byte[], SmartCardError>> GetAtrAsync(CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(
            _connectedReaderName
                .ToResult(SmartCardError.CommunicationError("No reader connected"))
                .Bind(readerName =>
                {
                    VirtualReaderManager readerManager = _virtualCardService.GetReaderManager();
                    return Maybe<VirtualCardReader>.From(readerManager.GetReader(readerName))
                        .ToResult(SmartCardError.CommunicationError($"Reader {readerName} not found"))
                        .Map(reader => Maybe<byte[]>.From(reader.GetAtr()).GetValueOrDefault([]));
                }));
    }

    public async Task<Result<string[], SmartCardError>> GetReadersAsync(CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(
            Result.Success<string[], SmartCardError>(
                _virtualCardService.GetReaderManager().GetReaderNames().ToArray()));
    }

    public async Task<Result<bool, SmartCardError>> IsSecureChannelEstablishedAsync(CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(
            Result.Success<bool, SmartCardError>(_secureChannelEstablished));
    }

    public async Task<Result<CommandResponse, SmartCardError>> SendCommandAsync(
        byte[] command,
        CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(SendCommandAsyncInternal(command));
    }

    private Result<CommandResponse, SmartCardError> SendCommandAsyncInternal(byte[] command)
    {
        VirtualCommandResponse virtualResponse = _virtualCardService.SendCommand(command);

        return virtualResponse.IsSuccessful
            ? Result.Success<CommandResponse, SmartCardError>(
                CommandResponse.Success(virtualResponse.Data, _context))
            : virtualResponse.Error
                .ToResult(SmartCardError.CommunicationError("Unknown error"))
                .Bind<SmartCardError>(error =>
                    Result.Failure<CommandResponse, SmartCardError>(error));
    }

    private static Result<byte[], SmartCardError> ConvertIApduCommandToBytes(IApduCommand command)
    {
        return Maybe<IApduCommand>.From(command)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Bind(validCommand => ConstructApduBytes(validCommand));
    }

    private static Result<byte[], SmartCardError> ConstructApduBytes(IApduCommand command)
    {
        // Convert IApduCommand to byte array following ISO 7816-4 format using functional composition
        ImmutableArray<byte> headerBytes = [command.Cla, command.Ins, command.P1, command.P2];

        return command.Data.Length switch
        {
            0 => Result.Success<byte[], SmartCardError>(headerBytes.ToArray()),
            <= 255 => Result.Success<byte[], SmartCardError>(headerBytes
                .Add((byte)command.Data.Length)
                .AddRange(command.Data)
                .ToArray()),
            _ when command.IsExtendedLength => Result.Success<byte[], SmartCardError>(headerBytes
                .AddRange(new byte[] { 0x00, (byte)(command.Data.Length >> 8), (byte)(command.Data.Length & 0xFF) })
                .AddRange(command.Data)
                .ToArray()),
            _ => Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument($"Data length {command.Data.Length} exceeds short format limit"))
        };
    }

    public void Dispose() => _virtualCardService.Dispose();
}
