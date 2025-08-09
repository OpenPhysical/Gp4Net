using System;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.DataObjects;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Modules;
using Gp4Net.Pipeline;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Services;

/// <summary>
/// Provides pure functional composition for retrieving complete card content.
/// Implements the full GlobalPlatform applet listing flow with auto-detection.
/// </summary>
[PublicAPI]
public class CardContentRetriever
{
    private readonly ISmartCardService _cardService;
    private readonly IGlobalPlatformService _gpService;
    private readonly ILogger<CardContentRetriever> _logger;


    /// <summary>
    /// Initializes a new instance of the CardContentRetriever class.
    /// </summary>
    /// <param name="cardService">The smart card service for command execution.</param>
    /// <param name="gpService">The GlobalPlatform service for high-level operations.</param>
    /// <param name="logger">The logger for diagnostic output.</param>
    public CardContentRetriever(ISmartCardService cardService, IGlobalPlatformService gpService, ILogger<CardContentRetriever> logger)
    {
        _cardService = cardService;
        _gpService = gpService;
        _logger = logger;
    }

    /// <summary>
    /// Retrieves complete card content using functional composition.
    /// Performs ISD selection, secure channel establishment, and comprehensive GET STATUS queries.
    /// </summary>
    /// <param name="keySet">The key set to use (defaults to GP test keys if null).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Complete card content or error.</returns>
    public async Task<Result<CardContent, SmartCardError>> RetrieveCardContentAsync(
        IKeySet keySet = null,
        CancellationToken cancellationToken = default)
    {
        // Select ISD
        var selectResult = await CardDiscovery.DetectAndSelectIsdAsync(
            async (cmd, ct) => await _cardService.ExecuteCommandAsync(cmd, ct),
            cancellationToken);
        
        if (selectResult.IsFailure)
        {
            return Result.Failure<CardContent, SmartCardError>(selectResult.Error);
        }

        // Establish secure channel
        var secureChannelResult = await EstablishSecureChannelWithAutoDetection(keySet);
        if (secureChannelResult.IsFailure)
        {
            return Result.Failure<CardContent, SmartCardError>(secureChannelResult.Error);
        }

        // Retrieve complete card content
        return await CardStatusRetriever.RetrieveCompleteCardContentAsync(
            async (cmd, ct) => await _cardService.ExecuteCommandAsync(cmd, ct),
            cancellationToken);
    }


    /// <summary>
    /// Establishes secure channel with SCP auto-detection and default key handling.
    /// </summary>
    private async Task<Result<bool, SmartCardError>> EstablishSecureChannelWithAutoDetection(IKeySet keySet)
    {
        // Use GP test keys if no key set provided
        var effectiveKeySet = keySet ?? CreateDefaultTestKeySet();

        _logger.LogDebug("Establishing secure channel with auto-detection");
        
        // Convert IKeySet to KeySet for GlobalPlatformService
        return await ConvertToKeySet(effectiveKeySet)
            .Bind(async keySetForGp =>
            {
                var secureChannelResult = await _gpService.EstablishSecureChannelAsync(
                    keySetForGp,
                    SecurityLevel.CMac);

                if (secureChannelResult.IsSuccess)
                {
                    _logger.LogInformation("Secure channel established successfully");
                    return Result.Success<bool, SmartCardError>(true);
                }
                else
                {
                    _logger.LogWarning("Failed to establish secure channel: {Error}", secureChannelResult.Error.Message);
                    return Result.Failure<bool, SmartCardError>(secureChannelResult.Error);
                }
            });
    }

    /// <summary>
    /// Creates a default SCP02 test key set for auto-detection scenarios.
    /// </summary>
    private static IKeySet CreateDefaultTestKeySet()
    {
        return GpTestKeys.CreateScp02TestKeySet();
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