using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Shared;
using Org.BouncyCastle.Security;

namespace Gp4Net.Cryptography;

/// <summary>
/// Interface for random number generation context.
/// Provides a pure functional interface for RNG operations.
/// </summary>
public interface IRngContext
{
    /// <summary>
    /// Generates random bytes using the context's RNG implementation.
    /// </summary>
    /// <param name="length">Number of random bytes to generate.</param>
    /// <returns>Random bytes or error if generation fails.</returns>
    Result<byte[], SmartCardError> GenerateBytes(int length);

    /// <summary>
    /// Checks if the context has enough entropy for the specified number of bytes.
    /// </summary>
    /// <param name="requiredBytes">The number of bytes that will be requested.</param>
    /// <returns>True if the RNG can generate the required bytes.</returns>
    bool HasEnoughEntropy(int requiredBytes);

    /// <summary>
    /// Gets the remaining entropy available in the context.
    /// Returns None for unlimited entropy (secure mode).
    /// Returns Some(count) for pre-loaded entropy (deterministic mode).
    /// </summary>
    Maybe<int> RemainingEntropy { get; }
}

/// <summary>
/// Advanced interface for preloaded RNG context with pure functional state management.
/// Extends IRngContext with stateless operations that return both results and new state.
/// Used for deterministic testing with immutable entropy tracking.
/// </summary>
public interface IPreloadedRngContext : IRngContext
{
    /// <summary>
    /// Pure functional entropy extraction that returns both entropy and new context state.
    /// Unlike GenerateBytes(), this method does not modify the current instance.
    /// </summary>
    /// <param name="length">Number of bytes to extract.</param>
    /// <returns>Result containing entropy and new context instance with updated position.</returns>
    Result<(byte[] entropy, IPreloadedRngContext newState), SmartCardError> GetBytesWithNewState(
        int length
    );

    /// <summary>
    /// Gets the total size of the entropy buffer.
    /// </summary>
    int TotalEntropy { get; }

    /// <summary>
    /// Creates a copy of this context reset to the beginning of the entropy buffer.
    /// Useful for running the same test scenario multiple times.
    /// </summary>
    /// <returns>A new PreloadedRngContext with the same entropy but reset position.</returns>
    IPreloadedRngContext Reset();

    /// <summary>
    /// Gets the current position in the entropy buffer.
    /// </summary>
    int Position { get; }
}

public static partial class CryptoOperations
{
    /// <summary>
    /// Random number generation with configurable modes for testing and production.
    /// Supports both deterministic entropy (for testing) and secure random (for production).
    /// All RNG configuration is static and thread-safe.
    /// </summary>
    public static class Rng
    {
        private static volatile IRngMode _currentMode = new SecureRngMode();
        private static readonly object ModeLock = new object();

        /// <summary>
        /// Configures RNG to use secure cryptographic random generation for production.
        /// This is the default mode and provides unlimited entropy.
        /// Thread-safe configuration method.
        /// </summary>
        public static void UseSecureMode()
        {
            lock (ModeLock)
            {
                _currentMode = new SecureRngMode();
            }
        }

        /// <summary>
        /// Configures RNG to use deterministic entropy for testing and trace replay.
        /// Provides reproducible random generation for unit tests and integration scenarios.
        /// Thread-safe configuration method.
        /// </summary>
        /// <param name="entropy">The complete entropy supply for all random operations.</param>
        /// <returns>Success or failure based on entropy validation.</returns>
        public static UnitResult<SmartCardError> UseDeterministicMode(byte[] entropy)
        {
            return DeterministicRngMode
                .Create(entropy)
                .Match(
                    mode =>
                    {
                        lock (ModeLock)
                        {
                            _currentMode = mode;
                        }
                        return UnitResult.Success<SmartCardError>();
                    },
                    error => UnitResult.Failure(error)
                );
        }

        /// <summary>
        /// Generates random bytes using the currently configured RNG mode.
        /// Used by all cryptographic operations requiring randomness.
        /// Thread-safe generation method.
        /// </summary>
        /// <param name="length">Number of random bytes to generate.</param>
        /// <returns>Random bytes or error if insufficient entropy.</returns>
        public static Result<byte[], SmartCardError> GenerateBytes(int length)
        {
            if (length <= 0)
            {
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument("Length must be positive")
                );
            }

            return _currentMode.GetBytes(length);
        }

        /// <summary>
        /// Checks if the current RNG mode has enough entropy for the specified number of bytes.
        /// Always returns true for secure mode, may return false for deterministic mode.
        /// </summary>
        /// <param name="requiredBytes">The number of bytes that will be requested.</param>
        /// <returns>True if the RNG can generate the required bytes.</returns>
        public static bool HasEnoughEntropy(int requiredBytes) =>
            _currentMode.HasEnoughEntropy(requiredBytes);

        /// <summary>
        /// Gets the remaining entropy available in the current RNG mode.
        /// Returns None for unlimited entropy (secure mode).
        /// Returns Some(count) for pre-loaded entropy (deterministic mode).
        /// </summary>
        public static Maybe<int> RemainingEntropy => _currentMode.RemainingEntropy;

        /// <summary>
        /// Creates a deterministic RNG context with pre-loaded entropy for testing.
        /// Pure functional - returns a new context without modifying global state.
        /// </summary>
        /// <param name="entropy">The complete entropy supply for all random operations.</param>
        /// <returns>A deterministic RNG context or error if entropy is invalid.</returns>
        public static Result<IRngContext, SmartCardError> CreateDeterministicContext(byte[] entropy)
        {
            return DeterministicRngMode
                .Create(entropy)
                .Map(mode => (IRngContext)new RngContextAdapter(mode));
        }

        /// <summary>
        /// Creates a secure RNG context with unlimited cryptographic entropy.
        /// Pure functional - returns a new context without modifying global state.
        /// </summary>
        /// <returns>A secure RNG context.</returns>
        public static IRngContext CreateSecureContext()
        {
            return new RngContextAdapter(new SecureRngMode());
        }

        /// <summary>
        /// Creates a preloaded RNG context from known challenges extracted from a trace.
        /// Useful for trace replay and deterministic testing scenarios.
        /// </summary>
        /// <param name="challenges">Sequential challenges from a card trace.</param>
        /// <returns>A deterministic RNG context or error if challenges are invalid.</returns>
        public static Result<IRngContext, SmartCardError> CreateFromTraceChallenges(
            IEnumerable<byte[]> challenges
        )
        {
            return Maybe
                .From(challenges)
                .ToResult(Errors.NullArgument("Challenges"))
                .Map(c => c.SelectMany(chunk => chunk).ToArray())
                .Bind(CreateDeterministicContext);
        }

        /// <summary>
        /// Creates a preloaded RNG context with repeating entropy pattern for unit tests.
        /// </summary>
        /// <param name="pattern">The entropy pattern to repeat.</param>
        /// <param name="repetitions">Number of times to repeat the pattern.</param>
        /// <returns>A deterministic RNG context or error if parameters are invalid.</returns>
        public static Result<IRngContext, SmartCardError> CreateWithRepeatingPattern(
            byte[] pattern,
            int repetitions
        )
        {
            return Maybe
                .From(pattern)
                .ToResult(Errors.NullArgument("Pattern"))
                .Ensure(p => p.Length > 0, Errors.EmptyArgument("Pattern"))
                .Ensure(
                    _ => repetitions > 0,
                    SmartCardError.InvalidArgument($"Repetitions must be positive: {repetitions}")
                )
                .Map(p => Enumerable.Range(0, repetitions).SelectMany(_ => p).ToArray())
                .Bind(CreateDeterministicContext);
        }

        /// <summary>
        /// Creates an advanced preloaded RNG context with pure functional state tracking.
        /// Provides the same functionality as the legacy PreloadedRngService but integrated
        /// with the unified CryptoOperations.Rng architecture.
        /// </summary>
        /// <param name="entropy">The complete entropy supply for all random operations.</param>
        /// <returns>A preloaded RNG context or error if entropy is invalid.</returns>
        public static Result<IPreloadedRngContext, SmartCardError> CreatePreloadedContext(
            byte[] entropy
        )
        {
            return PreloadedRngContext.Create(entropy);
        }

        /// <summary>
        /// Creates an advanced preloaded RNG context from entropy chunks (e.g., from trace data).
        /// </summary>
        /// <param name="entropyChunks">Sequence of entropy chunks to concatenate.</param>
        /// <returns>A preloaded RNG context or error if entropy is invalid.</returns>
        public static Result<IPreloadedRngContext, SmartCardError> CreatePreloadedContext(
            IEnumerable<byte[]> entropyChunks
        )
        {
            return Maybe
                .From(entropyChunks)
                .ToResult(Errors.NullArgument("Entropy chunks"))
                .Map(chunks => chunks.SelectMany(chunk => chunk).ToArray())
                .Bind(CreatePreloadedContext);
        }

        /// <summary>
        /// Generates an 8-byte host challenge for secure channel establishment.
        /// Per GP Card Specification, host challenge is always 8 bytes.
        /// </summary>
        /// <returns>8-byte host challenge or error.</returns>
        public static Result<byte[], SmartCardError> GenerateHostChallenge()
        {
            return GenerateBytes(8);
        }

        /// <summary>
        /// Generates a 16-byte sequence counter for SCP03.
        /// Per GP SCP03 Specification, sequence counter is 16 bytes.
        /// </summary>
        /// <returns>16-byte sequence counter or error.</returns>
        public static Result<byte[], SmartCardError> GenerateSequenceCounter()
        {
            return GenerateBytes(16);
        }

        /// <summary>
        /// Generates an 8-byte card challenge for secure channel establishment.
        /// Per GP Card Specification, card challenge is always 8 bytes.
        /// </summary>
        /// <returns>8-byte card challenge or error.</returns>
        public static Result<byte[], SmartCardError> GenerateCardChallenge()
        {
            return GenerateBytes(8);
        }

        /// <summary>
        /// Adapter to expose IRngMode as IRngContext.
        /// Provides a clean public interface for RNG operations.
        /// </summary>
        private sealed class RngContextAdapter : IRngContext
        {
            private readonly IRngMode _mode;

            public RngContextAdapter(IRngMode mode)
            {
                _mode = mode;
            }

            public Result<byte[], SmartCardError> GenerateBytes(int length)
            {
                if (length <= 0)
                {
                    return Result.Failure<byte[], SmartCardError>(
                        SmartCardError.InvalidArgument("Length must be positive")
                    );
                }
                return _mode.GetBytes(length);
            }

            public bool HasEnoughEntropy(int requiredBytes) =>
                _mode.HasEnoughEntropy(requiredBytes);

            public Maybe<int> RemainingEntropy => _mode.RemainingEntropy;
        }

        /// <summary>
        /// Internal interface for RNG mode implementations.
        /// </summary>
        private interface IRngMode
        {
            Result<byte[], SmartCardError> GetBytes(int length);
            bool HasEnoughEntropy(int requiredBytes);
            Maybe<int> RemainingEntropy { get; }
        }

        /// <summary>
        /// Secure random mode using BouncyCastle's SecureRandom for production.
        /// Provides unlimited cryptographically secure entropy.
        /// </summary>
        private sealed class SecureRngMode : IRngMode
        {
            public Result<byte[], SmartCardError> GetBytes(int length)
            {
                return Result.Try(
                    () =>
                    {
                        byte[] bytes = new byte[length];
                        var random = new SecureRandom();
                        random.NextBytes(bytes);
                        return bytes;
                    },
                    ex =>
                        SmartCardError.CryptographicError(
                            $"Secure random generation failed: {ex.Message}"
                        )
                );
            }

            public bool HasEnoughEntropy(int requiredBytes) => true;

            public Maybe<int> RemainingEntropy => Maybe<int>.None;
        }

        /// <summary>
        /// Deterministic RNG mode using pre-loaded entropy for testing.
        /// Provides reproducible random generation with finite entropy supply.
        /// Thread-safe implementation with immutable state.
        /// </summary>
        private sealed class DeterministicRngMode : IRngMode
        {
            private readonly byte[] _entropy;
            private volatile int _position;

            private DeterministicRngMode(byte[] entropy)
            {
                _entropy = entropy;
                _position = 0;
            }

            public static Result<DeterministicRngMode, SmartCardError> Create(byte[] entropy)
            {
                return Maybe
                    .From(entropy)
                    .ToResult(Errors.NullArgument("Entropy"))
                    .Ensure(e => e.Length > 0, Errors.EmptyArgument("Entropy buffer"))
                    .Map(e => new DeterministicRngMode((byte[])e.Clone()));
            }

            public Result<byte[], SmartCardError> GetBytes(int length)
            {
                lock (_entropy) // Ensure thread-safe access to position
                {
                    if (_position + length > _entropy.Length)
                    {
                        return Result.Failure<byte[], SmartCardError>(
                            SmartCardError.CryptographicError(
                                $"Insufficient entropy: requested {length} bytes, but only {_entropy.Length - _position} bytes remaining"
                            )
                        );
                    }

                    byte[] result = new byte[length];
                    Array.Copy(_entropy, _position, result, 0, length);
                    _position += length;
                    return Result.Success<byte[], SmartCardError>(result);
                }
            }

            public bool HasEnoughEntropy(int requiredBytes)
            {
                return requiredBytes >= 0 && _position + requiredBytes <= _entropy.Length;
            }

            public Maybe<int> RemainingEntropy => Maybe<int>.From(_entropy.Length - _position);
        }

        /// <summary>
        /// Pure functional deterministic RNG context with immutable entropy state.
        /// Used for testing to ensure reproducible cryptographic behavior.
        /// Perfect for trace replay and unit testing scenarios.
        /// All operations return new instances - no mutable state.
        /// </summary>
        private sealed record PreloadedRngContext(
            ImmutableList<byte> EntropyBuffer,
            int Position = 0
        ) : IPreloadedRngContext
        {
            /// <summary>
            /// Creates a new PreloadedRngContext with the specified entropy buffer.
            /// </summary>
            /// <param name="entropy">The complete entropy supply to use for all random operations.</param>
            /// <returns>A result containing the RNG context or an error.</returns>
            public static Result<IPreloadedRngContext, SmartCardError> Create(byte[] entropy) =>
                Maybe
                    .From(entropy)
                    .ToResult(Errors.NullArgument("Entropy"))
                    .Ensure(e => e.Length > 0, Errors.EmptyArgument("Entropy buffer"))
                    .Map(e => (IPreloadedRngContext)new PreloadedRngContext(e.ToImmutableList()));

            /// <inheritdoc />
            public Result<byte[], SmartCardError> GenerateBytes(int length) =>
                GetBytesWithNewState(length).Map(result => result.entropy);

            /// <inheritdoc />
            public Result<
                (byte[] entropy, IPreloadedRngContext newState),
                SmartCardError
            > GetBytesWithNewState(int length)
            {
                if (length < 0)
                    return SmartCardError.InvalidArgument($"Length cannot be negative: {length}");

                if (length == 0)
                    return ([], this);

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

            /// <inheritdoc />
            public int TotalEntropy => EntropyBuffer.Count;

            /// <inheritdoc />
            public IPreloadedRngContext Reset() => this with { Position = 0 };
        }
    }
}
