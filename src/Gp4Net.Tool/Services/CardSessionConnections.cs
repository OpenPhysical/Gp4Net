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
/// Factory for creating CardSessionCommands instances for different purposes.
/// Provides services for enumeration (no connection) and connected operations.
/// </summary>
/// <summary>
/// Implementation of CardSessionConnections.
/// </summary>
[PublicAPI]
public class CardSessionConnections
{
    private readonly ILoggerFactory _loggerFactory;

    public CardSessionConnections(ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory;
    }

    /// <inheritdoc/>
    public ICardSessionCommands CreateForEnumeration()
    {
        // Create a wrapper service that implements reader enumeration
        return new CardEnumerationCommands();
    }

    /// <inheritdoc/>
    public async Task<Result<ICardSessionCommands, SmartCardError>> CreateConnectedAsync(
        string readerSpec,
        CancellationToken cancellationToken = default
    )
    {
        var logger = _loggerFactory.CreateLogger<CardSessionCommands>();
        return await CardConnections.CreateConnectionAsync(readerSpec, logger, cancellationToken);
    }
}

/// <summary>
/// CardSessionCommands implementation for reader enumeration only.
/// Cannot perform card operations but can list available readers.
/// </summary>
internal class CardEnumerationCommands : ICardSessionCommands
{
    /// <inheritdoc/>
    public ImmutablePipelineContext Context => ImmutablePipelineContext.Empty;

    /// <inheritdoc/>
    public async Task<Result<string[], SmartCardError>> GetReadersAsync(
        CancellationToken cancellationToken = default
    )
    {
        // Use ReaderEnumeration to get physical readers
        return await ReaderEnumeration.EnumeratePhysicalReadersAsync(cancellationToken);
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
    public Result<ICardSessionCommands, SmartCardError> WithContext(
        ImmutablePipelineContext context
    )
    {
        return Result.Success<ICardSessionCommands, SmartCardError>(this);
    }

    /// <inheritdoc/>
    public Result<ICardSessionCommands, SmartCardError> WithContextValue<T>(string key, T value)
    {
        return Result.Success<ICardSessionCommands, SmartCardError>(this);
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
