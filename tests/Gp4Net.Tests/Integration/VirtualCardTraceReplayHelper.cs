using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Helper class for creating virtual cards configured for trace replay testing.
/// Provides methods to create cards with deterministic entropy extracted from traces.
/// </summary>
[PublicAPI]
public static class VirtualCardTraceReplayHelper
{
    /// <summary>
    /// Creates a virtual card configured for exact trace replay using extracted trace data.
    /// Uses separated entropy sources for host and card challenges to match trace behavior.
    /// Per user directive: "We have a deterministic RNG specifically for this purpose. Fill its RNG with the trace data."
    /// </summary>
    /// <param name="trace">Trace data containing INITIALIZE UPDATE exchanges with challenges.</param>
    /// <param name="config">Optional card configuration (defaults to Generic).</param>
    /// <returns>A virtual card that will reproduce the exact trace behavior.</returns>
    public static Result<VirtualCard, SmartCardError> ForTraceReplay(
        TraceData trace,
        Maybe<CardConfiguration> config)
    {
        CardConfiguration cardConfig = config.GetValueOrDefault(CardConfiguration.Generic());

        return TraceEntropyExtractor.ExtractCardChallengesFromTrace(trace)
            .Bind(cardChallenges => PreloadedRngService.FromTraceChallenges(cardChallenges)
                .Map(cardRng => new VirtualCard(cardConfig, new CryptographicService(cardRng))));
    }

    /// <summary>
    /// Creates separate host and card services for trace replay testing.
    /// Enables proper entropy coordination where host and card use different deterministic sequences.
    /// This matches the user's requirement: "Host challenge comes from test entropy, Card challenge comes from card entropy."
    /// </summary>
    /// <param name="trace">Trace data to extract challenges from.</param>
    /// <param name="config">Optional card configuration (defaults to Generic).</param>
    /// <returns>Tuple of (virtualCard, testCryptoService) with separate entropy sources.</returns>
    public static Result<(VirtualCard card, CryptographicService testService), SmartCardError> ForTraceReplayWithSeparateEntropy(
        TraceData trace,
        Maybe<CardConfiguration> config)
    {
        CardConfiguration cardConfig = config.GetValueOrDefault(CardConfiguration.Generic());

        return TraceEntropyExtractor.CreateSeparatedRngServicesFromTrace(trace)
            .Map(services =>
            {
                (PreloadedRngService hostRng, PreloadedRngService cardRng) = services;
                VirtualCard virtualCard = new VirtualCard(cardConfig, new CryptographicService(cardRng));
                CryptographicService testService = new CryptographicService(hostRng);
                return (virtualCard, (CryptographicService)testService);
            });
    }

    /// <summary>
    /// Convenience overload for ForTraceReplay with default Generic configuration.
    /// </summary>
    /// <param name="trace">Trace data containing INITIALIZE UPDATE exchanges with challenges.</param>
    /// <returns>A virtual card that will reproduce the exact trace behavior.</returns>
    public static Result<VirtualCard, SmartCardError> ForTraceReplay(TraceData trace)
    {
        return ForTraceReplay(trace, Maybe<CardConfiguration>.None);
    }

    /// <summary>
    /// Convenience overload for ForTraceReplayWithSeparateEntropy with default Generic configuration.
    /// </summary>
    /// <param name="trace">Trace data to extract challenges from.</param>
    /// <returns>Tuple of (virtualCard, testCryptoService) with separate entropy sources.</returns>
    public static Result<(VirtualCard card, CryptographicService testService), SmartCardError> ForTraceReplayWithSeparateEntropy(
        TraceData trace)
    {
        return ForTraceReplayWithSeparateEntropy(trace, Maybe<CardConfiguration>.None);
    }
}