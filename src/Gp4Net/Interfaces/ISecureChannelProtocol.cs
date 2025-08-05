// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;

namespace Gp4Net.Interfaces;

/// <summary>
/// Defines the interface for a secure channel protocol implementation.
/// </summary>
public interface ISecureChannelProtocol
{
    /// <summary>
    /// Gets the protocol version identifier.
    /// </summary>
    byte ProtocolVersion { get; }

    /// <summary>
    /// Creates an INITIALIZE UPDATE command.
    /// </summary>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <returns>The INITIALIZE UPDATE command.</returns>
    Result<InitializeUpdateCommand, SmartCardError> CreateInitializeUpdateCommand(byte[] hostChallenge);

    /// <summary>
    /// Processes an INITIALIZE UPDATE response and establishes a context.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge that was sent.</param>
    /// <returns>The secure channel context with derived session keys.</returns>
    Result<SecureChannelContext, SmartCardError> ProcessInitializeUpdateResponse(
        InitializeUpdateResponse response,
        byte[] hostChallenge
    );

    /// <summary>
    /// Creates an EXTERNAL AUTHENTICATE command.
    /// </summary>
    /// <param name="context">The secure channel context.</param>
    /// <param name="securityLevel">The desired security level.</param>
    /// <returns>The EXTERNAL AUTHENTICATE command.</returns>
    Result<ExternalAuthenticateCommand, SmartCardError> CreateExternalAuthenticateCommand(
        SecureChannelContext context,
        SecurityLevel securityLevel
    );

    /// <summary>
    /// Verifies the card cryptogram.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <param name="sessionKeys">The derived session keys.</param>
    /// <returns>True if the card cryptogram is valid; otherwise, false.</returns>
    Result<bool, SmartCardError> VerifyCardCryptogram(
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        SessionKeys sessionKeys
    );

    /// <summary>
    /// Calculates the host cryptogram.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <param name="sessionKeys">The derived session keys.</param>
    /// <returns>The host cryptogram.</returns>
    Result<byte[], SmartCardError> CalculateHostCryptogram(
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        SessionKeys sessionKeys
    );
}