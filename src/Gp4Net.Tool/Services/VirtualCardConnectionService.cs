using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
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
/// Service for creating SmartCardService instances connected to virtual cards.
/// Handles loading card profiles and managing virtual card state persistence.
/// </summary>
[PublicAPI]
public static class VirtualCardConnectionService
{
    /// <summary>
    /// Creates a SmartCardService connected to a virtual card specified by the reader string.
    /// </summary>
    /// <param name="virtualReaderSpec">Virtual reader specification in format "virtual:profile.json"</param>
    /// <param name="logger">Logger for the SmartCardService</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>A SmartCardService connected to the virtual card, or an error</returns>
    public static Task<Result<ISmartCardService, SmartCardError>> CreateServiceAsync(
        string virtualReaderSpec,
        ILogger<SmartCardService> logger,
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
        // Use the existing CardProfileLoader which handles all the JSON parsing
        return Task.FromResult(
            CardProfileLoader
                .LoadFromFile(profilePath)
                .Map(config => VirtualCardTestBuilder.CreateWithSecureRng(config))
        );
    }

    /// <summary>
    /// Creates a SmartCardService with a virtual card backend.
    /// </summary>
    private static Result<ISmartCardService, SmartCardError> CreateSmartCardService(
        VirtualCard virtualCard,
        ILogger<SmartCardService> logger
    )
    {
        return VirtualCardChannel
            .Create(virtualCard)
            .Bind(channel =>
                VirtualCardTransport.Create(virtualCard).Map(transport => (channel, transport))
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

                return (ISmartCardService)new SmartCardService(environment, processor, logger);
            });
    }

    /// <summary>
    /// Saves the current state of a virtual card to a file.
    /// Serializes both configuration and runtime state.
    /// </summary>
    /// <param name="virtualCard">The virtual card to save</param>
    /// <param name="statePath">Path to save the state</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Success or error result</returns>
    public static Task<UnitResult<SmartCardError>> SaveCardStateAsync(
        VirtualCard virtualCard,
        string statePath,
        CancellationToken cancellationToken = default
    )
    {
        return SerializeCardState(virtualCard)
            .Bind(json => WriteStateToFile(json, statePath, cancellationToken));
    }

    /// <summary>
    /// Serializes virtual card state to JSON.
    /// </summary>
    private static Result<string, SmartCardError> SerializeCardState(VirtualCard virtualCard)
    {
        var cardState = new { CardType = "VirtualCard", Timestamp = DateTime.UtcNow };

        string json = JsonSerializer.Serialize(
            cardState,
            new JsonSerializerOptions { WriteIndented = true }
        );

        return Result.Success<string, SmartCardError>(json);
    }

    /// <summary>
    /// Writes state JSON to file.
    /// </summary>
    private static async Task<UnitResult<SmartCardError>> WriteStateToFile(
        string json,
        string statePath,
        CancellationToken cancellationToken
    )
    {
        await File.WriteAllTextAsync(statePath, json, cancellationToken);
        return UnitResult.Success<SmartCardError>();
    }
}
