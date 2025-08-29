// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Essential interface for SCP protocol implementations focused on secure channel establishment.
/// Contains only the core operations needed for protocol-agnostic secure channel setup.
/// Additional protocol-specific methods remain as static methods in the protocol classes.
/// </summary>
/// <typeparam name="TSelf">The implementing type (CRTP pattern).</typeparam>
[PublicAPI]
public interface ISecureChannelProtocol<TSelf> where TSelf : ISecureChannelProtocol<TSelf>
{
    // Protocol Identity

    /// <summary>
    /// The protocol version identifier (0x02 for SCP02, 0x03 for SCP03).
    /// </summary>
    static abstract ScpVersion ProtocolVersion { get; }

    // Core Protocol Operations for Secure Channel Establishment

    /// <summary>
    /// Creates an INITIALIZE UPDATE command with the specified host challenge.
    /// </summary>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <returns>The INITIALIZE UPDATE command or error.</returns>
    static abstract Result<InitializeUpdateCommand, SmartCardError> CreateInitializeUpdateCommand(byte[] hostChallenge);

    /// <summary>
    /// Processes an INITIALIZE UPDATE response and creates a secure channel context.
    /// Includes protocol validation, key derivation, and cryptogram verification.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge that was sent.</param>
    /// <param name="keySet">The key set to use for session key derivation.</param>
    /// <returns>A secure channel context for further protocol operations or error.</returns>
    static abstract Result<SecureChannelContext, SmartCardError> ProcessInitializeUpdateResponse(
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        IKeySet keySet);

    /// <summary>
    /// Creates an EXTERNAL AUTHENTICATE command for the specified security level.
    /// </summary>
    /// <param name="context">The secure channel context from INITIALIZE UPDATE.</param>
    /// <param name="securityLevel">The requested security level.</param>
    /// <returns>The EXTERNAL AUTHENTICATE command with cryptogram and MAC or error.</returns>
    static abstract Result<ExternalAuthenticateCommand, SmartCardError> CreateExternalAuthenticateCommand(
        SecureChannelContext context,
        SecurityLevel securityLevel);

    /// <summary>
    /// Creates a secure channel session from the established context.
    /// </summary>
    /// <param name="context">The secure channel context.</param>
    /// <param name="securityLevel">The established security level.</param>
    /// <returns>The secure channel session state or error.</returns>
    static abstract Result<SecureChannelState, SmartCardError> CreateSecureChannelSession(
        SecureChannelContext context,
        SecurityLevel securityLevel);
}
