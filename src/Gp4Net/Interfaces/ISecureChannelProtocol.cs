// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using Gp4Net.Domain;

namespace Gp4Net.Interfaces
{
    using Constants;
    using Domain.Commands;
    using Domain.Keys;

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
        InitializeUpdateCommand CreateInitializeUpdateCommand(byte[] hostChallenge);

        /// <summary>
        /// Processes an INITIALIZE UPDATE response and establishes a session.
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response.</param>
        /// <param name="hostChallenge">The host challenge that was sent.</param>
        /// <returns>The established secure channel session.</returns>
        SecureChannelSession ProcessInitializeUpdateResponse(InitializeUpdateResponse response, byte[] hostChallenge);

        /// <summary>
        /// Creates an EXTERNAL AUTHENTICATE command.
        /// </summary>
        /// <param name="session">The secure channel session.</param>
        /// <param name="securityLevel">The desired security level.</param>
        /// <returns>The EXTERNAL AUTHENTICATE command.</returns>
        ExternalAuthenticateCommand CreateExternalAuthenticateCommand(SecureChannelSession session, SecurityLevel securityLevel);

        /// <summary>
        /// Verifies the card cryptogram.
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response.</param>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <param name="sessionKeys">The derived session keys.</param>
        /// <returns>True if the card cryptogram is valid; otherwise, false.</returns>
        bool VerifyCardCryptogram(InitializeUpdateResponse response, byte[] hostChallenge, SessionKeys sessionKeys);

        /// <summary>
        /// Calculates the host cryptogram.
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response.</param>
        /// <param name="hostChallenge">The host challenge.</param>
        /// <param name="sessionKeys">The derived session keys.</param>
        /// <returns>The host cryptogram.</returns>
        byte[] CalculateHostCryptogram(InitializeUpdateResponse response, byte[] hostChallenge, SessionKeys sessionKeys);
    }
}
