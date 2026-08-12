using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using WSCT.ISO7816;

namespace Gp4Net.Tests.Infrastructure;

/// <summary>
/// Test implementation of ICardSessionCommands that adapts VirtualCardOperations for testing.
/// Provides a bridge between the emulator's VirtualCardOperations and the ICardSessionCommands interface.
/// </summary>
public sealed class TestCardService : ICardSessionCommands
{
    private readonly Maybe<VirtualCardOperations> _virtualCardService;
    private readonly ImmutablePipelineContext _context;
    private bool _disposed;

    /// <summary>
    /// Creates a TestCardService with the specified VirtualCardOperations.
    /// </summary>
    /// <param name="virtualCardService">The virtual card service to adapt.</param>
    /// <returns>A Result containing the TestCardService or an error.</returns>
    public static Result<TestCardService, SmartCardError> Create(
        VirtualCardOperations virtualCardService
    )
    {
        return Maybe
            .From(virtualCardService)
            .ToResult(SmartCardError.InvalidArgument("VirtualCardOperations cannot be null"))
            .Map(service => new TestCardService(service, ImmutablePipelineContext.Empty));
    }

    private TestCardService(
        VirtualCardOperations virtualCardService,
        ImmutablePipelineContext context
    )
    {
        _virtualCardService = Maybe.From(virtualCardService);
        _context = context;
    }

    /// <inheritdoc />
    public ImmutablePipelineContext Context => _context;

    /// <inheritdoc />
    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        CancellationToken cancellationToken = default
    )
    {
        return await Task.FromResult(
            Result.Success<CommandResponse, SmartCardError>(
                CommandResponse.Success([0x90, 0x00], _context)
            )
        );
    }

    /// <inheritdoc />
    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        bool useSecureChannel,
        CancellationToken cancellationToken = default
    )
    {
        return await ExecuteCommandAsync(command, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        CommandOptions options,
        CancellationToken cancellationToken = default
    )
    {
        return await ExecuteCommandAsync(command, cancellationToken);
    }

    /// <inheritdoc />
    public Result<ICardSessionCommands, SmartCardError> WithContext(
        ImmutablePipelineContext context
    )
    {
        return Maybe<ImmutablePipelineContext>
            .From(context)
            .ToResult(SmartCardError.InvalidArgument("Context cannot be null"))
            .Bind(validContext =>
                _virtualCardService
                    .ToResult(
                        SmartCardError.CommunicationError("Virtual card service not available")
                    )
                    .Map(service =>
                        (ICardSessionCommands)new TestCardService(service, validContext)
                    )
            );
    }

    /// <inheritdoc />
    public Result<ICardSessionCommands, SmartCardError> WithContextValue<T>(string key, T value)
    {
        var newContext = _context.With(key, value);
        return _virtualCardService
            .ToResult(SmartCardError.CommunicationError("Virtual card service not available"))
            .Map(service => (ICardSessionCommands)new TestCardService(service, newContext));
    }

    /// <inheritdoc />
    public async Task<Result<bool, SmartCardError>> IsConnectedAsync(
        CancellationToken cancellationToken = default
    )
    {
        return await Task.FromResult(Result.Success<bool, SmartCardError>(true));
    }

    /// <inheritdoc />
    public async Task<Result<byte[], SmartCardError>> GetAtrAsync(
        CancellationToken cancellationToken = default
    )
    {
        // Return a generic ATR for testing
        return await Task.FromResult(
            Result.Success<byte[], SmartCardError>([0x3B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        );
    }

    /// <inheritdoc />
    public async Task<Result<string[], SmartCardError>> GetReadersAsync(
        CancellationToken cancellationToken = default
    )
    {
        return await Task.FromResult(
            Result.Success<string[], SmartCardError>(["Virtual P71 Reader 00 00"])
        );
    }

    /// <inheritdoc />
    public async Task<Result<bool, SmartCardError>> IsSecureChannelEstablishedAsync(
        CancellationToken cancellationToken = default
    )
    {
        return await Task.FromResult(Result.Success<bool, SmartCardError>(true));
    }

    /// <inheritdoc />
    public async Task<Result<CommandResponse, SmartCardError>> SendCommandAsync(
        byte[] command,
        CancellationToken cancellationToken = default
    )
    {
        return await Task.FromResult(
            Result.Success<CommandResponse, SmartCardError>(
                CommandResponse.Success([0x90, 0x00], _context)
            )
        );
    }

    /// <inheritdoc />
    public async Task<
        Result<CardTransportCapabilities, SmartCardError>
    > GetCardTransportCapabilitiesAsync(CancellationToken cancellationToken = default)
    {
        // Return default capabilities for testing
        return await Task.FromResult(
            Result.Success<CardTransportCapabilities, SmartCardError>(
                new CardTransportCapabilities(false, 245)
            )
        );
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
            return;

        _virtualCardService.Execute(service => service.Dispose());
        _disposed = true;
    }
}
