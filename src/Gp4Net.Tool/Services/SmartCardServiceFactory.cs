using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using WSCT.ISO7816;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Factory for creating SmartCardService instances for different purposes.
/// Provides services for enumeration (no connection) and connected operations.
/// </summary>
[PublicAPI]
public interface ISmartCardServiceFactory
{
    /// <summary>
    /// Creates a SmartCardService for reader enumeration.
    /// This service can list readers but is not connected to any specific card.
    /// </summary>
    /// <returns>SmartCardService configured for enumeration</returns>
    ISmartCardService CreateForEnumeration();

    /// <summary>
    /// Creates a connected SmartCardService for the specified reader.
    /// Supports both physical and virtual readers.
    /// </summary>
    /// <param name="readerSpec">Reader specification (physical name or virtual:profile.json)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Connected SmartCardService or error</returns>
    Task<Result<ISmartCardService, SmartCardError>> CreateConnectedAsync(
        string readerSpec,
        CancellationToken cancellationToken = default
    );
}

/// <summary>
/// Implementation of SmartCardServiceFactory.
/// </summary>
[PublicAPI]
public class SmartCardServiceFactory : ISmartCardServiceFactory
{
    private readonly ILoggerFactory _loggerFactory;

    public SmartCardServiceFactory(ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory;
    }

    /// <inheritdoc/>
    public ISmartCardService CreateForEnumeration()
    {
        // Create a wrapper service that implements reader enumeration
        return new EnumerationSmartCardService();
    }

    /// <inheritdoc/>
    public async Task<Result<ISmartCardService, SmartCardError>> CreateConnectedAsync(
        string readerSpec,
        CancellationToken cancellationToken = default
    )
    {
        var logger = _loggerFactory.CreateLogger<SmartCardService>();
        return await ConnectionFactory.CreateConnectionAsync(readerSpec, logger, cancellationToken);
    }
}

/// <summary>
/// SmartCardService implementation for reader enumeration only.
/// Cannot perform card operations but can list available readers.
/// </summary>
internal class EnumerationSmartCardService : ISmartCardService
{
    /// <inheritdoc/>
    public IPipelineContext Context => ImmutablePipelineContext.Empty;

    /// <inheritdoc/>
    public async Task<Result<string[], SmartCardError>> GetReadersAsync(
        CancellationToken cancellationToken = default
    )
    {
        // Use ReaderEnumerationService to get physical readers
        return await ReaderEnumerationService.EnumeratePhysicalReadersAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        IApduCommand command,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError(
                    "No card connection established. This service is for enumeration only."
                )
            )
        );
    }

    /// <inheritdoc/>
    public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        IApduCommand command,
        CommandOptions options,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError(
                    "No card connection established. This service is for enumeration only."
                )
            )
        );
    }

    /// <inheritdoc/>
    public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError(
                    "No card connection established. This service is for enumeration only."
                )
            )
        );
    }

    /// <inheritdoc/>
    public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        bool useSecureChannel,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError(
                    "No card connection established. This service is for enumeration only."
                )
            )
        );
    }

    /// <inheritdoc/>
    public Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        CommandAPDU command,
        CommandOptions options,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError(
                    "No card connection established. This service is for enumeration only."
                )
            )
        );
    }

    /// <inheritdoc/>
    public Result<ISmartCardService, SmartCardError> WithContext(IPipelineContext context)
    {
        return Result.Success<ISmartCardService, SmartCardError>(this);
    }

    /// <inheritdoc/>
    public Result<ISmartCardService, SmartCardError> WithContextValue<T>(string key, T value)
    {
        return Result.Success<ISmartCardService, SmartCardError>(this);
    }

    /// <inheritdoc/>
    public Task<Result<bool, SmartCardError>> IsConnectedAsync(
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(Result.Success<bool, SmartCardError>(false));
    }

    /// <inheritdoc/>
    public Task<Result<byte[], SmartCardError>> GetAtrAsync(
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<byte[], SmartCardError>(
                SmartCardError.CommunicationError("No card connection established.")
            )
        );
    }

    /// <inheritdoc/>
    public Task<Result<bool, SmartCardError>> IsSecureChannelEstablishedAsync(
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(Result.Success<bool, SmartCardError>(false));
    }

    /// <inheritdoc/>
    public Task<Result<CommandResponse, SmartCardError>> SendCommandAsync(
        byte[] command,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.CommunicationError(
                    "No card connection established. This service is for enumeration only."
                )
            )
        );
    }

    /// <inheritdoc/>
    public Task<
        Result<CardTransportCapabilities, SmartCardError>
    > GetCardTransportCapabilitiesAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(
            Result.Failure<CardTransportCapabilities, SmartCardError>(
                SmartCardError.CommunicationError(
                    "No card connection established. This service is for enumeration only."
                )
            )
        );
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        // Nothing to dispose in enumeration service
    }
}
