// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
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
    public Result<byte[], SmartCardError> GenerateChallenge(int length)
    {
        return length <= 0
            ? SmartCardError.InvalidArgument("Challenge length must be positive")
            : CryptoService.Utils.GenerateRandomBytes(length)
                .Tap(challenge =>
                    _logger.LogDebug(
                        "Generated {Length}-byte challenge: {Challenge}",
                        length,
                        Convert.ToHexString(challenge)
                    )
                );
    }
}
