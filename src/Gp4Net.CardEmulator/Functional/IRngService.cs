using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Interface for random number generation services used by cryptographic operations.
/// Allows injection of deterministic entropy sources for testing while maintaining
/// secure random generation for production use.
/// </summary>
[PublicAPI]
public interface IRngService
{
    /// <summary>
    /// Generates random bytes of the specified length.
    /// </summary>
    /// <param name="length">The number of random bytes to generate.</param>
    /// <returns>A result containing the random bytes or an error.</returns>
    Result<byte[], SmartCardError> GetBytes(int length);

    /// <summary>
    /// Checks if the RNG service has enough entropy to generate the specified number of bytes.
    /// Always returns true for secure random services, but may return false for pre-loaded services.
    /// </summary>
    /// <param name="requiredBytes">The number of bytes that will be requested.</param>
    /// <returns>True if the service can generate the required bytes.</returns>
    bool HasEnoughEntropy(int requiredBytes);

    /// <summary>
    /// Gets the remaining entropy available in the service.
    /// Returns None for unlimited entropy services (secure random).
    /// Returns Some(count) for pre-loaded entropy services.
    /// </summary>
    Maybe<int> RemainingEntropy { get; }
}
