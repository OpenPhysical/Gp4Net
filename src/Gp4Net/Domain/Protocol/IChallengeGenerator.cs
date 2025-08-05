// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Interface for generating cryptographic challenges.
/// </summary>
[PublicAPI]
public interface IChallengeGenerator
{
    /// <summary>
    /// Generates a cryptographically secure challenge.
    /// </summary>
    /// <param name="length">The length of the challenge in bytes.</param>
    /// <returns>A cryptographically secure random challenge.</returns>
    byte[] GenerateChallenge(int length);
}