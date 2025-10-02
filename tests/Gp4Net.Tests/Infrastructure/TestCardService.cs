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
/// Test implementation of ISmartCardService that adapts VirtualCardService for testing.
/// Provides a bridge between the emulator's VirtualCardService and the ISmartCardService interface.
/// </summary>
public sealed class TestCardService : ISmartCardService
{
    private readonly Maybe<VirtualCardService> _virtualCardService;
    private readonly IPipelineContext _context;
    private bool _disposed;

    /// <summary>
    /// Creates a TestCardService with the specified VirtualCardService.
    /// </summary>
    /// <param name="virtualCardService">The virtual card service to adapt.</param>
    /// <returns>A Result containing the TestCardService or an error.</returns>
    public static Result<TestCardService, SmartCardError> Create(
        VirtualCardService virtualCardService
    )
    {
        return Maybe
            .From(virtualCardService)
            .ToResult(SmartCardError.InvalidArgument("VirtualCardService cannot be null"))
            .Map(service => new TestCardService(service, ImmutablePipelineContext.Empty));
    }

    private TestCardService(VirtualCardService virtualCardService, IPipelineContext context)
    {
        _virtualCardService = Maybe.From(virtualCardService);
        _context = context;
    }

    /// <inheritdoc />
    public IPipelineContext Context => _context;

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
    public Result<ISmartCardService, SmartCardError> WithContext(IPipelineContext context)
    {
        return Maybe<IPipelineContext>
            .From(context)
            .ToResult(SmartCardError.InvalidArgument("Context cannot be null"))
            .Bind(validContext =>
                _virtualCardService
                    .ToResult(
                        SmartCardError.CommunicationError("Virtual card service not available")
                    )
                    .Map(service => (ISmartCardService)new TestCardService(service, validContext))
            );
    }

    /// <inheritdoc />
    public Result<ISmartCardService, SmartCardError> WithContextValue<T>(string key, T value)
    {
        var newContext = _context.With(key, value);
        return _virtualCardService
            .ToResult(SmartCardError.CommunicationError("Virtual card service not available"))
            .Map(service => (ISmartCardService)new TestCardService(service, newContext));
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
