using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
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

public static partial class CryptoService
{
    /// <summary>
    /// Random number generation with configurable modes for testing and production.
    /// Supports both deterministic entropy (for testing) and secure random (for production).
    /// All RNG configuration is static and thread-safe.
    /// </summary>
    public static class Rng
    {
        private static volatile IRngMode _currentMode = new SecureRngMode();
        private static readonly object _modeLock = new object();

        /// <summary>
        /// Configures RNG to use secure cryptographic random generation for production.
        /// This is the default mode and provides unlimited entropy.
        /// Thread-safe configuration method.
        /// </summary>
        public static void UseSecureMode()
        {
            lock (_modeLock)
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
            return DeterministicRngMode.Create(entropy)
                .Match(
                    mode =>
                    {
                        lock (_modeLock)
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
            return DeterministicRngMode.Create(entropy)
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

            public Maybe<int> RemainingEntropy => 
                _mode.RemainingEntropy;
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
                        SecureRandom random = new SecureRandom();
                        random.NextBytes(bytes);
                        return bytes;
                    },
                    ex => SmartCardError.CryptographicError($"Secure random generation failed: {ex.Message}")
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
                return Maybe.From(entropy)
                    .ToResult(SmartCardError.InvalidArgument("Entropy cannot be null"))
                    .Ensure(e => e.Length > 0, SmartCardError.InvalidArgument("Entropy buffer cannot be empty"))
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

            public Maybe<int> RemainingEntropy =>
                Maybe<int>.From(_entropy.Length - _position);
        }
    }
}
