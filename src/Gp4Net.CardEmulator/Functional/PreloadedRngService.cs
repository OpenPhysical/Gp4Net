using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Deterministic RNG service pre-loaded with a complete entropy supply.
/// Used for testing to ensure reproducible cryptographic behavior.
/// Perfect for trace replay and unit testing scenarios.
/// </summary>
[PublicAPI]
public class PreloadedRngService : IRngService
{
    private readonly ImmutableList<byte> _entropyBuffer;
    private int _position;

    /// <summary>
    /// Private constructor for internal use.
    /// </summary>
    private PreloadedRngService(ImmutableList<byte> entropyBuffer, int position = 0)
    {
        _entropyBuffer = entropyBuffer;
        _position = position;
    }

    /// <summary>
    /// Creates a new PreloadedRngService with the specified entropy buffer.
    /// </summary>
    /// <param name="entropy">The complete entropy supply to use for all random operations.</param>
    /// <returns>A result containing the RNG service or an error.</returns>
    public static Result<PreloadedRngService, SmartCardError> Create(byte[] entropy)
    {
        if (entropy.Length == 0)
        {
            return SmartCardError.InvalidArgument("Entropy buffer cannot be empty");
        }
        
        return Result.Success<PreloadedRngService, SmartCardError>(
            new PreloadedRngService(entropy.ToImmutableList()));
    }

    /// <summary>
    /// Creates a new PreloadedRngService from entropy chunks (e.g., from trace data).
    /// </summary>
    /// <param name="entropyChunks">Sequence of entropy chunks to concatenate.</param>
    /// <returns>A result containing the RNG service or an error.</returns>
    public static Result<PreloadedRngService, SmartCardError> Create(IEnumerable<byte[]> entropyChunks)
    {
        byte[] concatenated = entropyChunks.SelectMany(chunk => chunk).ToArray();
        return Create(concatenated);
    }

    /// <summary>
    /// Creates a PreloadedRngService from known challenges extracted from a trace.
    /// </summary>
    /// <param name="challenges">Sequential challenges from a card trace.</param>
    /// <returns>A result containing the RNG service or an error.</returns>
    public static Result<PreloadedRngService, SmartCardError> FromTraceChallenges(IEnumerable<byte[]> challenges)
    {
        return Create(challenges);
    }

    /// <summary>
    /// Creates a PreloadedRngService with repeating entropy pattern for unit tests.
    /// </summary>
    /// <param name="pattern">The entropy pattern to repeat.</param>
    /// <param name="repetitions">Number of times to repeat the pattern.</param>
    /// <returns>A result containing the RNG service or an error.</returns>
    public static Result<PreloadedRngService, SmartCardError> WithRepeatingPattern(byte[] pattern, int repetitions)
    {
        if (pattern.Length == 0)
        {
            return SmartCardError.InvalidArgument("Pattern cannot be empty");
        }

        if (repetitions <= 0)
        {
            return SmartCardError.InvalidArgument($"Repetitions must be positive: {repetitions}");
        }

        byte[] entropy = Enumerable.Range(0, repetitions)
            .SelectMany(_ => pattern)
            .ToArray();

        return Create(entropy);
    }

    /// <inheritdoc />
    public Result<byte[], SmartCardError> GetBytes(int length)
    {
        if (length < 0)
        {
            return SmartCardError.InvalidArgument($"Length cannot be negative: {length}");
        }

        if (length == 0)
        {
            return Result.Success<byte[], SmartCardError>([]);
        }

        if (_position + length > _entropyBuffer.Count)
        {
            return SmartCardError.CryptographicError(
                $"Insufficient entropy: requested {length} bytes, but only {_entropyBuffer.Count - _position} bytes remaining");
        }

        byte[] result = _entropyBuffer
            .Skip(_position)
            .Take(length)
            .ToArray();

        _position += length;

        return Result.Success<byte[], SmartCardError>(result);
    }

    /// <inheritdoc />
    public bool HasEnoughEntropy(int requiredBytes)
    {
        return requiredBytes >= 0 && _position + requiredBytes <= _entropyBuffer.Count;
    }

    /// <inheritdoc />
    public Maybe<int> RemainingEntropy => Maybe<int>.From(_entropyBuffer.Count - _position);

    /// <summary>
    /// Gets the current position in the entropy buffer (for debugging).
    /// </summary>
    public int Position => _position;

    /// <summary>
    /// Gets the total size of the entropy buffer.
    /// </summary>
    public int TotalEntropy => _entropyBuffer.Count;

    /// <summary>
    /// Creates a copy of this service reset to the beginning of the entropy buffer.
    /// Useful for running the same test scenario multiple times.
    /// </summary>
    /// <returns>A new PreloadedRngService with the same entropy but reset position.</returns>
    public PreloadedRngService Reset()
    {
        return new PreloadedRngService(_entropyBuffer, 0);
    }
}