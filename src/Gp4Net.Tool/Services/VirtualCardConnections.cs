using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.CardEmulator.Persistence;
using Gp4Net.CardEmulator.Profiles;
using Gp4Net.CardEmulator.Transport;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using static Gp4Net.Pipeline.CommandProcessing;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Service for creating CardSessionCommands instances connected to virtual cards.
/// Handles loading card profiles and managing virtual card state persistence.
/// </summary>
[PublicAPI]
public static class VirtualCardConnections
{
    /// <summary>
    /// Creates a CardSessionCommands connected to a virtual card specified by the reader string.
    /// </summary>
    /// <param name="virtualReaderSpec">Virtual reader specification in format "virtual:profile.json"</param>
    /// <param name="logger">Logger for the CardSessionCommands</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>A CardSessionCommands connected to the virtual card, or an error</returns>
    public static Task<Result<ICardSessionCommands, SmartCardError>> CreateServiceAsync(
        string virtualReaderSpec,
        ILogger<CardSessionCommands> logger,
        CancellationToken cancellationToken = default
    )
    {
        return ParseVirtualReaderSpec(virtualReaderSpec)
            .Bind(profilePath => LoadOrCreateVirtualCard(profilePath, cancellationToken))
            .Bind(virtualCard => Task.FromResult(CreateSmartCardService(virtualCard, logger)));
    }

    /// <summary>
    /// Parses the virtual reader specification to extract the profile path.
    /// </summary>
    private static Result<string, SmartCardError> ParseVirtualReaderSpec(string spec)
    {
        const string prefix = "virtual:";

        return Maybe<string>
            .From(spec)
            .Where(s => s.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            .Map(s => s[prefix.Length..])
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .ToResult(
                SmartCardError.InvalidArgument($"Invalid virtual reader specification: {spec}")
            );
    }

    /// <summary>
    /// Loads a virtual card from a profile file.
    /// </summary>
    private static async Task<Result<VirtualCard, SmartCardError>> LoadOrCreateVirtualCard(
        string profilePath,
        CancellationToken cancellationToken
    )
    {
        if (File.Exists(profilePath))
        {
            return await LoadCardFromProfile(profilePath, cancellationToken);
        }

        return Result.Failure<VirtualCard, SmartCardError>(
            SmartCardError.InvalidArgument($"Virtual card profile not found: {profilePath}")
        );
    }

    /// <summary>
    /// Loads a virtual card configuration from a JSON profile file.
    /// </summary>
    private static Task<Result<VirtualCard, SmartCardError>> LoadCardFromProfile(
        string profilePath,
        CancellationToken cancellationToken
    )
    {
        return Task.FromResult(
            CardProfileLoader.LoadFromFile(profilePath).Bind(config => LoadPersistentCard(config))
        );
    }

    private static Result<VirtualCard, SmartCardError> LoadPersistentCard(
        CardConfiguration configuration
    ) =>
        GetPersistenceSettings()
            .Bind(settings =>
                settings.Match(
                    configured =>
                        File.Exists(configured.Path)
                            ? VirtualCardStateStore
                                .Load(configured.Path, configuration, configured.RootKey)
                                .Bind(state =>
                                    VirtualCard.Restore(
                                        configuration,
                                        Gp4Net.Cryptography.CryptoOperations.Rng.CreateSecureContext(),
                                        state
                                    )
                                )
                            : CreateAndPersist(configuration, configured),
                    () =>
                        Result.Success<VirtualCard, SmartCardError>(
                            VirtualCardTestBuilder.CreateWithSecureRng(configuration)
                        )
                )
            );

    private static Result<VirtualCard, SmartCardError> CreateAndPersist(
        CardConfiguration configuration,
        PersistenceSettings settings
    )
    {
        VirtualCard card = VirtualCardTestBuilder.CreateWithSecureRng(configuration);
        return VirtualCardStateStore.Save(card, settings.Path, settings.RootKey).Map(() => card);
    }

    /// <summary>
    /// Creates a CardSessionCommands with a virtual card backend.
    /// </summary>
    private static Result<ICardSessionCommands, SmartCardError> CreateSmartCardService(
        VirtualCard virtualCard,
        ILogger<CardSessionCommands> logger
    )
    {
        return GetPersistenceSettings()
            .Bind(settings =>
            {
                Maybe<Func<IVirtualCard, UnitResult<SmartCardError>>> persistence = settings.Map(
                    configured =>
                        (Func<IVirtualCard, UnitResult<SmartCardError>>)(
                            card =>
                                card is VirtualCard concrete
                                    ? VirtualCardStateStore.Save(
                                        concrete,
                                        configured.Path,
                                        configured.RootKey
                                    )
                                    : UnitResult.Failure(
                                        SmartCardError.InvalidArgument(
                                            "Unsupported virtual-card implementation"
                                        )
                                    )
                        )
                );

                return VirtualCardChannel
                    .Create(virtualCard, persistence)
                    .Bind(channel =>
                        VirtualCardTransport
                            .Create(virtualCard)
                            .Map(transport => (channel, transport))
                    )
                    .Map(tuple =>
                    {
                        var (channel, transport) = tuple;

                        var environment = new CommandEnvironment(
                            Channel: channel,
                            Transport: transport,
                            SecureChannel: Maybe<SecureChannelState>.None,
                            Logger: logger,
                            Options: new CommandOptions(
                                UseSecureChannel: false,
                                CaptureMetrics: true,
                                EnableLogging: true, // Enable logging infrastructure
                                VerboseLogging: false, // CLI will override if --verbose
                                DebugLogging: false // CLI will override if --debug
                            )
                        );

                        var processor = Gp4Net.Pipeline.CommandProcessors.CreatePipeline(
                            enableLogging: true,
                            enableSecureChannel: true
                        );

                        return (ICardSessionCommands)
                            new CardSessionCommands(environment, processor, logger);
                    });
            });
    }

    /// <summary>
    /// Saves the current state of a virtual card to a file.
    /// Serializes both configuration and runtime state.
    /// </summary>
    /// <param name="virtualCard">The virtual card to save</param>
    /// <param name="statePath">Path to save the state</param>
    /// <param name="rootKey">32-byte state-encryption root key.</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Success or error result</returns>
    public static Task<UnitResult<SmartCardError>> SaveCardStateAsync(
        VirtualCard virtualCard,
        string statePath,
        byte[] rootKey,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(VirtualCardStateStore.Save(virtualCard, statePath, rootKey));
    }

    private static Result<Maybe<PersistenceSettings>, SmartCardError> GetPersistenceSettings()
    {
        Maybe<string> path = Maybe<string>
            .From(Environment.GetEnvironmentVariable("GP4NET_VIRTUAL_STATE"))
            .Where(value => !string.IsNullOrWhiteSpace(value));
        if (path.HasNoValue)
            return Result.Success<Maybe<PersistenceSettings>, SmartCardError>(
                Maybe<PersistenceSettings>.None
            );

        return Maybe<string>
            .From(Environment.GetEnvironmentVariable("GP4NET_VIRTUAL_STATE_KEY"))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToResult(
                SmartCardError.InvalidArgument(
                    "GP4NET_VIRTUAL_STATE_KEY is required when GP4NET_VIRTUAL_STATE is set"
                )
            )
            .Ensure(
                value => value.Length == 64,
                SmartCardError.InvalidArgument(
                    "GP4NET_VIRTUAL_STATE_KEY must be exactly 32 hexadecimal bytes"
                )
            )
            .Bind(value =>
                Result.Try(
                    () => Convert.FromHexString(value),
                    _ =>
                        SmartCardError.InvalidArgument(
                            "GP4NET_VIRTUAL_STATE_KEY must contain hexadecimal characters"
                        )
                )
            )
            .Map(rootKey =>
                Maybe<PersistenceSettings>.From(new PersistenceSettings(path.Value, rootKey))
            );
    }

    private sealed record PersistenceSettings(string Path, byte[] RootKey);
}
