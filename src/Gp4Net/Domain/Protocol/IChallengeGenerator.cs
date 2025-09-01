// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Interface for generating cryptographic challenges.
/// Uses functional programming Result&lt;T&gt; pattern for error handling.
/// </summary>
[PublicAPI]
public interface IChallengeGenerator
{
    /// <summary>
    /// Generates a cryptographically secure challenge.
    /// </summary>
    /// <param name="length">The length of the challenge in bytes.</param>
    /// <returns>A result containing the cryptographically secure random challenge or an error.</returns>
    Result<byte[], SmartCardError> GenerateChallenge(int length);
}
