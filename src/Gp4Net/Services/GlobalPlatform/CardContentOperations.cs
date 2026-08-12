using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Pipeline;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using WSCT.ISO7816;

namespace Gp4Net.Services.GlobalPlatform;

/// <summary>
/// Provides pure functional composition for retrieving complete card content.
/// Implements the full GlobalPlatform applet listing flow with auto-detection.
/// </summary>
[PublicAPI]
public static class CardContentOperations
{
    /// <summary>
    /// Retrieves complete card content using functional composition.
    /// Performs ISD selection, secure channel establishment, and comprehensive GET STATUS queries.
    /// </summary>
    /// <param name="execute">The parsed command execution boundary.</param>
    /// <param name="transmit">The raw command transmission boundary.</param>
    /// <param name="logger">The diagnostic sink.</param>
    /// <param name="keySet">The key set to use (defaults to GP test keys if not provided).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Complete card content or error.</returns>
    public static async Task<Result<CardContent, SmartCardError>> RetrieveAsync(
        Func<CommandAPDU, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> execute,
        ScpOperations.Transmit transmit,
        ILogger logger,
        Maybe<IKeySet> keySet = default,
        CancellationToken cancellationToken = default
    )
    {
        // Select ISD, establish secure channel, and retrieve complete card content
        return await Discovery
            .DetectAndSelectIsdAsync(execute, cancellationToken)
            .Bind(async _ =>
                await EstablishSecureChannelWithAutoDetection(transmit, logger, keySet)
            )
            .Bind(async _ =>
                await Applications.RetrieveCompleteCardContentAsync(execute, cancellationToken)
            );
    }

    /// <summary>
    /// Establishes secure channel with SCP auto-detection and default key handling.
    /// </summary>
    private static async Task<Result<bool, SmartCardError>> EstablishSecureChannelWithAutoDetection(
        ScpOperations.Transmit transmit,
        ILogger logger,
        Maybe<IKeySet> keySet
    )
    {
        return await keySet.Match(
            async ks =>
            {
                logger.LogDebug("Establishing secure channel with auto-detection");

                return await ConvertToKeySet(ks)
                    .Bind(async keySetForGp =>
                        await ScpOperations
                            .Establishment.EstablishAsync(
                                transmit,
                                keySetForGp,
                                SecurityLevel.CMac,
                                CancellationToken.None
                            )
                            .Tap(_ =>
                                logger.LogInformation("Secure channel established successfully")
                            )
                            .TapError(error =>
                                logger.LogWarning(
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
