using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Services.GlobalPlatform;

/// <summary>
/// Provides pure functional composition for retrieving complete card content.
/// Implements the full GlobalPlatform applet listing flow with auto-detection.
/// </summary>
[PublicAPI]
public class CardContentRetriever
{
    private readonly ISmartCardService _cardService;
    private readonly ILogger<CardContentRetriever> _logger;

    /// <summary>
    /// Initializes a new instance of the CardContentRetriever class.
    /// </summary>
    /// <param name="cardService">The smart card service for command execution.</param>
    /// <param name="logger">The logger for diagnostic output.</param>
    public CardContentRetriever(ISmartCardService cardService, ILogger<CardContentRetriever> logger)
    {
        _cardService = cardService;
        _logger = logger;
    }

    /// <summary>
    /// Retrieves complete card content using functional composition.
    /// Performs ISD selection, secure channel establishment, and comprehensive GET STATUS queries.
    /// </summary>
    /// <param name="keySet">The key set to use (defaults to GP test keys if not provided).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Complete card content or error.</returns>
    public async Task<Result<CardContent, SmartCardError>> RetrieveCardContentAsync(
        Maybe<IKeySet> keySet = default,
        CancellationToken cancellationToken = default
    )
    {
        // Select ISD, establish secure channel, and retrieve complete card content
        return await Discovery
            .DetectAndSelectIsdAsync(
                async (cmd, ct) => await _cardService.ExecuteCommandAsync(cmd, ct),
                cancellationToken
            )
            .Bind(async _ => await EstablishSecureChannelWithAutoDetection(keySet))
            .Bind(async _ =>
                await Applications.RetrieveCompleteCardContentAsync(
                    async (cmd, ct) => await _cardService.ExecuteCommandAsync(cmd, ct),
                    cancellationToken
                )
            );
    }

    /// <summary>
    /// Establishes secure channel with SCP auto-detection and default key handling.
    /// </summary>
    private async Task<Result<bool, SmartCardError>> EstablishSecureChannelWithAutoDetection(
        Maybe<IKeySet> keySet
    )
    {
        return await keySet.Match(
            async ks =>
            {
                _logger.LogDebug("Establishing secure channel with auto-detection");

                return await ConvertToKeySet(ks)
                    .Bind(async keySetForGp =>
                        await ScpService
                            .Establishment.EstablishAsync(
                                _cardService,
                                keySetForGp,
                                SecurityLevel.CMac,
                                CancellationToken.None
                            )
                            .Tap(_ =>
                                _logger.LogInformation("Secure channel established successfully")
                            )
                            .TapError(error =>
                                _logger.LogWarning(
                                    "Failed to establish secure channel: {Error}",
                                    error.Message
                                )
                            )
                            .Map(_ => true)
                    );
            },
            () =>
                Task.FromResult(
                    Result.Failure<bool, SmartCardError>(
                        SmartCardError.InvalidArgument(
                            "Key set is required for secure channel establishment"
                        )
                    )
                )
        );
    }

    /// <summary>
    /// Converts IKeySet to KeySet for GlobalPlatformService compatibility.
    /// </summary>
    private static Result<KeySet, SmartCardError> ConvertToKeySet(IKeySet keySet)
    {
        if (keySet is KeySet concreteKeySet)
        {
            return Result.Success<KeySet, SmartCardError>(concreteKeySet);
        }

        return SmartCardError.InvalidArgument("KeySet must be a concrete KeySet implementation");
    }
}
