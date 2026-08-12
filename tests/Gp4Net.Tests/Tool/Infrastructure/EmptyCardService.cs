using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using WSCT.ISO7816;

namespace Gp4Net.Tests.Tool.Infrastructure;

/// <summary>
/// Empty card service for testing error conditions.
/// Preserves all original functionality while implementing ICardSessionCommands.
/// </summary>
public class EmptyCardService : ICardSessionCommands
{
    private readonly ImmutablePipelineContext _context;

    public EmptyCardService()
    {
        _context = ImmutablePipelineContext.Empty;
    }

    private EmptyCardService(ImmutablePipelineContext context)
    {
        _context = context;
    }

    public ImmutablePipelineContext Context => _context;

    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        CancellationToken cancellationToken = default
    )
    {
        return await Task.FromResult(
            Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError("Empty card service - no operation supported")
            )
        );
    }

    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        bool useSecureChannel,
        CancellationToken cancellationToken = default
    )
    {
        return await ExecuteCommandAsync(command, cancellationToken);
    }

    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        CommandOptions options,
        CancellationToken cancellationToken = default
    )
    {
        return await ExecuteCommandAsync(command, cancellationToken);
    }

    public Result<ICardSessionCommands, SmartCardError> WithContext(
        ImmutablePipelineContext context
    )
    {
        return Maybe<ImmutablePipelineContext>
            .From(context)
            .ToResult(SmartCardError.InvalidArgument("Context cannot be null"))
            .Map(validContext => (ICardSessionCommands)new EmptyCardService(validContext));
    }

    public Result<ICardSessionCommands, SmartCardError> WithContextValue<T>(string key, T value)
    {
        var newContext = _context.With(key, value);
        return Result.Success<ICardSessionCommands, SmartCardError>(
            new EmptyCardService(newContext)
        );
    }

    public async Task<Result<bool, SmartCardError>> IsConnectedAsync(
        CancellationToken cancellationToken = default
    )
    {
        return await Task.FromResult(Result.Success<bool, SmartCardError>(false));
    }

    public async Task<Result<byte[], SmartCardError>> GetAtrAsync(
        CancellationToken cancellationToken = default
    )
    {
        return await Task.FromResult(
            Result.Failure<byte[], SmartCardError>(
                SmartCardError.CommunicationError("Empty card service - no ATR available")
            )
        );
    }

    public async Task<Result<string[], SmartCardError>> GetReadersAsync(
        CancellationToken cancellationToken = default
    )
    {
        return await Task.FromResult(Result.Success<string[], SmartCardError>([]));
    }

    public async Task<Result<bool, SmartCardError>> IsSecureChannelEstablishedAsync(
        CancellationToken cancellationToken = default
    )
    {
        return await Task.FromResult(Result.Success<bool, SmartCardError>(false));
    }

    public async Task<Result<CommandResponse, SmartCardError>> SendCommandAsync(
        byte[] command,
        CancellationToken cancellationToken = default
    )
    {
        return await Task.FromResult(
            Result.Success<CommandResponse, SmartCardError>(
                CommandResponse.Failure(0x6F00, _context)
            )
        ); // Generic error response
    }

    public async Task<
        Result<CardTransportCapabilities, SmartCardError>
    > GetCardTransportCapabilitiesAsync(CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(
            Result.Success<CardTransportCapabilities, SmartCardError>(
                new CardTransportCapabilities(false, 245)
            )
        );
    }

    public void Dispose()
    {
        // Empty card service has no resources to dispose
    }
}
