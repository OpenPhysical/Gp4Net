using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Transport;

namespace Gp4Net.Tests.Tool.Infrastructure;

/// <summary>
/// Empty card service for testing error conditions.
/// Preserves all original functionality while implementing ISmartCardService.
/// </summary>
public class EmptyCardService : ISmartCardService
{
    private readonly IPipelineContext _context;

    public EmptyCardService()
    {
        _context = ImmutablePipelineContext.Empty;
    }

    private EmptyCardService(IPipelineContext context)
    {
        _context = context;
    }

    public IPipelineContext Context => _context;

    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        IApduCommand command, 
        CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(
            Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError("Empty card service - no operation supported")));
    }

    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        IApduCommand command, 
        CommandOptions options, 
        CancellationToken cancellationToken = default)
    {
        return await ExecuteCommandAsync(command, cancellationToken);
    }

    public Result<ISmartCardService, SmartCardError> WithContext(IPipelineContext context)
    {
        return Maybe<IPipelineContext>.From(context)
            .ToResult(SmartCardError.InvalidArgument("Context cannot be null"))
            .Map(validContext => (ISmartCardService)new EmptyCardService(validContext));
    }

    public Result<ISmartCardService, SmartCardError> WithContextValue<T>(string key, T value)
    {
        IPipelineContext? newContext = _context.With(key, value);
        return Result.Success<ISmartCardService, SmartCardError>(new EmptyCardService(newContext));
    }

    public async Task<Result<bool, SmartCardError>> IsConnectedAsync(CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(Result.Success<bool, SmartCardError>(false));
    }

    public async Task<Result<byte[], SmartCardError>> GetAtrAsync(CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(
            Result.Failure<byte[], SmartCardError>(
                SmartCardError.CommunicationError("Empty card service - no ATR available")));
    }

    public async Task<Result<string[], SmartCardError>> GetReadersAsync(CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(Result.Success<string[], SmartCardError>([]));
    }

    public async Task<Result<bool, SmartCardError>> IsSecureChannelEstablishedAsync(CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(Result.Success<bool, SmartCardError>(false));
    }

    public async Task<Result<CommandResponse, SmartCardError>> SendCommandAsync(
        byte[] command, 
        CancellationToken cancellationToken = default)
    {
        return await Task.FromResult(
            Result.Success<CommandResponse, SmartCardError>(
                CommandResponse.Failure(0x6F00, _context))); // Generic error response
    }

    public void Dispose()
    {
        // Empty card service has no resources to dispose
    }
}