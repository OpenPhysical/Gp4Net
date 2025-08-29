// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using Org.BouncyCastle.Security;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Default implementation of challenge generator using cryptographically secure random number generation.
/// </summary>
[PublicAPI]
public class DefaultChallengeGenerator : IChallengeGenerator
{
    private readonly ILogger<DefaultChallengeGenerator> _logger;

    /// <summary>
    /// Initializes a new instance of DefaultChallengeGenerator.
    /// </summary>
    /// <param name="logger">The logger.</param>
    public DefaultChallengeGenerator(ILogger<DefaultChallengeGenerator> logger)
    {
        _logger = logger;
    }

    /// <inheritdoc />
    public byte[] GenerateChallenge(int length)
    {
        if (length <= 0)
        {
            throw new ArgumentException("Challenge length must be positive.", nameof(length));
        }

        byte[] challenge = new byte[length];
        SecureRandom rng = new SecureRandom();
        rng.NextBytes(challenge);

        _logger.LogDebug(
            "Generated {Length}-byte challenge: {Challenge}",
            length,
            Convert.ToHexString(challenge)
        );

        return challenge;
    }
}