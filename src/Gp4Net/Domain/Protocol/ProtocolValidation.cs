// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Core.Functional;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Shared validation utilities for secure channel protocols.
/// Provides common validation logic used across SCP02, SCP03, and other protocols.
/// </summary>
[PublicAPI]
public static class ProtocolValidation
{
    /// <summary>
    /// Validates that a host challenge is exactly 8 bytes.
    /// </summary>
    /// <param name="hostChallenge">The host challenge to validate.</param>
    /// <returns>Success if valid, error if invalid.</returns>
    public static Result ValidateHostChallenge(byte[] hostChallenge)
    {
        return hostChallenge?.Length == 8
            ? Result.Success()
            : Result.Failure(SmartCardError.InvalidData($"Host challenge must be 8 bytes, got {hostChallenge?.Length ?? 0}").Message);
    }

    /// <summary>
    /// Validates that a card challenge meets the minimum length requirement.
    /// </summary>
    /// <param name="cardChallenge">The card challenge to validate.</param>
    /// <param name="expectedLength">The expected minimum length.</param>
    /// <returns>Success if valid, error if invalid.</returns>
    public static Result ValidateCardChallenge(byte[] cardChallenge, int expectedLength)
    {
        return cardChallenge?.Length >= expectedLength
            ? Result.Success()
            : Result.Failure(SmartCardError.InvalidResponse($"Card challenge must be at least {expectedLength} bytes, got {cardChallenge?.Length ?? 0}").Message);
    }

    /// <summary>
    /// Validates that a sequence counter meets the expected length requirement.
    /// </summary>
    /// <param name="sequenceCounter">The sequence counter to validate.</param>
    /// <param name="expectedLength">The expected minimum length.</param>
    /// <returns>Success if valid, error if invalid.</returns>
    public static Result ValidateSequenceCounter(byte[] sequenceCounter, int expectedLength)
    {
        return sequenceCounter?.Length >= expectedLength
            ? Result.Success()
            : Result.Failure(SmartCardError.InvalidResponse($"Sequence counter must be at least {expectedLength} bytes, got {sequenceCounter?.Length ?? 0}").Message);
    }

    /// <summary>
    /// Validates that a response is for the expected secure channel protocol.
    /// </summary>
    /// <param name="responseScpId">The SCP ID from the response.</param>
    /// <param name="expectedProtocol">The expected protocol version.</param>
    /// <returns>Success if valid, error if invalid.</returns>
    public static Result ValidateProtocolVersion(Maybe<ScpVersion> responseScpId, ScpVersion expectedProtocol)
    {
        return responseScpId == expectedProtocol
            ? Result.Failure($"Expected {expectedProtocol:X2} but received {responseScpId:X2}")
            : Result.Success();
    }

    /// <summary>
    /// Validates that a key set is compatible with the specified protocol.
    /// </summary>
    /// <param name="keySet">The key set to validate.</param>
    /// <param name="expectedType">The expected key set type.</param>
    /// <returns>Success if valid, error if invalid.</returns>
    public static Result ValidateKeySetType<T>(object keySet, System.Type expectedType)
    {
        return keySet.GetType() == expectedType
            ? Result.Success()
            : Result.Failure(SmartCardError.InvalidArgument($"Expected {expectedType.Name} but got {keySet.GetType().Name}").Message);
    }
}
