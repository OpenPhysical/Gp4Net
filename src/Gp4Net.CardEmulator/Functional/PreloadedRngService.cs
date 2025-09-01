using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Pure functional deterministic RNG service with immutable entropy state.
/// Used for testing to ensure reproducible cryptographic behavior.
/// Perfect for trace replay and unit testing scenarios.
/// All operations return new instances - no mutable state.
/// </summary>
[PublicAPI]
public sealed record PreloadedRngService(
    ImmutableList<byte> EntropyBuffer,
    int Position = 0
) : IRngService
{

    /// <summary>
    /// Creates a new PreloadedRngService with the specified entropy buffer.
    /// </summary>
    /// <param name="entropy">The complete entropy supply to use for all random operations.</param>
    /// <returns>A result containing the RNG service or an error.</returns>
    public static Result<PreloadedRngService, SmartCardError> Create(byte[] entropy) =>
        Maybe.From(entropy)
            .ToResult(SmartCardError.InvalidArgument("Entropy cannot be null"))
            .Ensure(e => e.Length > 0, SmartCardError.InvalidArgument("Entropy buffer cannot be empty"))
            .Map(e => new PreloadedRngService(e.ToImmutableList()));

    /// <summary>
    /// Creates a new PreloadedRngService from entropy chunks (e.g., from trace data).
    /// </summary>
    /// <param name="entropyChunks">Sequence of entropy chunks to concatenate.</param>
    /// <returns>A result containing the RNG service or an error.</returns>
    public static Result<PreloadedRngService, SmartCardError> Create(IEnumerable<byte[]> entropyChunks) =>
        Maybe.From(entropyChunks)
            .ToResult(SmartCardError.InvalidArgument("Entropy chunks cannot be null"))
            .Map(chunks => chunks.SelectMany(chunk => chunk).ToArray())
            .Bind(Create);

    /// <summary>
    /// Creates a PreloadedRngService from known challenges extracted from a trace.
    /// </summary>
    /// <param name="challenges">Sequential challenges from a card trace.</param>
    /// <returns>A result containing the RNG service or an error.</returns>
    public static Result<PreloadedRngService, SmartCardError> FromTraceChallenges(IEnumerable<byte[]> challenges) =>
        Create(challenges);

    /// <summary>
    /// Creates a PreloadedRngService with repeating entropy pattern for unit tests.
    /// </summary>
    /// <param name="pattern">The entropy pattern to repeat.</param>
    /// <param name="repetitions">Number of times to repeat the pattern.</param>
    /// <returns>A result containing the RNG service or an error.</returns>
    public static Result<PreloadedRngService, SmartCardError> WithRepeatingPattern(
        byte[] pattern,
        int repetitions
    ) =>
        Maybe.From(pattern)
            .ToResult(SmartCardError.InvalidArgument("Pattern cannot be null"))
            .Ensure(p => p.Length > 0, SmartCardError.InvalidArgument("Pattern cannot be empty"))
            .Ensure(_ => repetitions > 0, SmartCardError.InvalidArgument($"Repetitions must be positive: {repetitions}"))
            .Map(p => Enumerable.Range(0, repetitions).SelectMany(_ => p).ToArray())
            .Bind(Create);

    /// <inheritdoc />
    /// <remarks>
    /// This method violates pure functional design by returning entropy without state transition.
    /// Use GetBytesWithNewState for pure functional usage that returns updated service instance.
    /// </remarks>
    public Result<byte[], SmartCardError> GetBytes(int length) =>
        GetBytesWithNewState(length).Map(result => result.entropy);

    /// <summary>
    /// Pure functional entropy extraction that returns both entropy and new service state.
    /// </summary>
    /// <param name="length">Number of bytes to extract.</param>
    /// <returns>Result containing entropy and new service instance with updated position.</returns>
    public Result<(byte[] entropy, PreloadedRngService newState), SmartCardError> GetBytesWithNewState(int length)
    {
        if (length < 0)
            return SmartCardError.InvalidArgument($"Length cannot be negative: {length}");

        if (length == 0)
            return (Array.Empty<byte>(), this);

        if (Position + length > EntropyBuffer.Count)
            return SmartCardError.CryptographicError(
                $"Insufficient entropy: requested {length} bytes, but only {EntropyBuffer.Count - Position} bytes remaining"
            );

        var entropy = EntropyBuffer.Skip(Position).Take(length).ToArray();
        var newState = this with { Position = Position + length };
        
        return (entropy, newState);
    }

    /// <inheritdoc />
    public bool HasEnoughEntropy(int requiredBytes) =>
        requiredBytes >= 0 && Position + requiredBytes <= EntropyBuffer.Count;

    /// <inheritdoc />
    public Maybe<int> RemainingEntropy => Maybe<int>.From(EntropyBuffer.Count - Position);

    /// <summary>
    /// Gets the total size of the entropy buffer.
    /// </summary>
    public int TotalEntropy => EntropyBuffer.Count;

    /// <summary>
    /// Creates a copy of this service reset to the beginning of the entropy buffer.
    /// Useful for running the same test scenario multiple times.
    /// </summary>
    /// <returns>A new PreloadedRngService with the same entropy but reset position.</returns>
    public PreloadedRngService Reset() => this with { Position = 0 };
}
