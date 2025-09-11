using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Test builder for creating functional virtual cards with various configurations.
/// Provides generic methods for setting up test scenarios with different RNG contexts.
/// </summary>
[PublicAPI]
public static class VirtualCardTestBuilder
{
    /// <summary>
    /// Creates a virtual card with deterministic entropy for reproducible testing.
    /// </summary>
    /// <param name="config">The card configuration.</param>
    /// <param name="entropy">The complete entropy supply for all random operations.</param>
    /// <returns>A virtual card with deterministic behavior.</returns>
    public static Result<VirtualCard, SmartCardError> CreateWithEntropy(
        CardConfiguration config,
        byte[] entropy
    )
    {
        return CryptoService
            .Rng.CreateDeterministicContext(entropy)
            .Bind(rng => VirtualCard.Create(config, rng));
    }

    /// <summary>
    /// Creates a virtual card with secure random number generation.
    /// </summary>
    /// <param name="config">The card configuration.</param>
    /// <returns>A virtual card with secure RNG.</returns>
    public static VirtualCard CreateWithSecureRng(CardConfiguration config)
    {
        var rng = CryptoService.Rng.CreateSecureContext();
        return VirtualCard.Create(config, rng).Value;
    }

    /// <summary>
    /// Creates a virtual card with entropy from trace challenges for exact replay.
    /// </summary>
    /// <param name="config">The card configuration.</param>
    /// <param name="traceChallenges">Sequential challenges extracted from a card trace.</param>
    /// <returns>A virtual card that will behave exactly like the traced card.</returns>
    public static Result<VirtualCard, SmartCardError> CreateWithTraceChallenges(
        CardConfiguration config,
        IEnumerable<byte[]> traceChallenges
    )
    {
        // Convert trace challenges to entropy array for deterministic mode
        byte[] entropy = traceChallenges.SelectMany(challenge => challenge).ToArray();
        return CreateWithEntropy(config, entropy);
    }

    /// <summary>
    /// Creates a virtual card with repeating entropy pattern for unit tests.
    /// </summary>
    /// <param name="config">The card configuration.</param>
    /// <param name="pattern">The entropy pattern to repeat.</param>
    /// <param name="repetitions">Number of times to repeat the pattern.</param>
    /// <returns>A virtual card with repeating deterministic behavior.</returns>
    public static Result<VirtualCard, SmartCardError> CreateWithRepeatingEntropy(
        CardConfiguration config,
        byte[] pattern,
        int repetitions
    )
    {
        // Create repeating entropy by concatenating the pattern multiple times
        byte[] repeatingEntropy = Enumerable
            .Range(0, repetitions)
            .SelectMany(_ => pattern)
            .ToArray();

        return CreateWithEntropy(config, repeatingEntropy);
    }

    /// <summary>
    /// Creates a virtual card with insufficient entropy to test error handling.
    /// </summary>
    /// <param name="config">The card configuration.</param>
    /// <param name="entropyBytes">Number of entropy bytes (should be insufficient for operations).</param>
    /// <returns>A virtual card that may fail on operations requiring more entropy.</returns>
    public static Result<VirtualCard, SmartCardError> CreateWithLimitedEntropy(
        CardConfiguration config,
        int entropyBytes
    )
    {
        byte[] limitedEntropy = Enumerable.Range(0, entropyBytes).Select(i => (byte)i).ToArray();

        return CreateWithEntropy(config, limitedEntropy);
    }
}
