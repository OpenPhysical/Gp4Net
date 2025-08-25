using Gp4Net.Domain.Protocol;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Challenge generator that returns predetermined challenges for trace-based testing.
/// </summary>
public class DeterministicChallengeGenerator : IChallengeGenerator
{
    private readonly byte[] _challenge;

    /// <summary>
    /// Creates a new deterministic challenge generator.
    /// </summary>
    /// <param name="challenge">The challenge to return for all requests.</param>
    public DeterministicChallengeGenerator(byte[] challenge)
    {
        _challenge = challenge;
    }

    /// <summary>
    /// Returns the predetermined challenge regardless of requested length.
    /// </summary>
    /// <param name="length">Requested challenge length (ignored).</param>
    /// <returns>The predetermined challenge bytes.</returns>
    public byte[] GenerateChallenge(int length) => _challenge;
}