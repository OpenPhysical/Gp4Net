// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Abstract base class for secure channel protocol implementations.
/// Provides shared functionality and enforces common patterns across SCP02, SCP03, and other protocols.
/// </summary>
[PublicAPI]
public abstract class SecureChannelProtocolBase : ISecureChannelProtocol
{
    protected readonly IKeySet _keySet;
    protected readonly IKeyDerivationService _keyDerivationService;
    protected readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the SecureChannelProtocolBase class.
    /// </summary>
    /// <param name="keySet">The static key set.</param>
    /// <param name="keyDerivationService">The key derivation service.</param>
    /// <param name="logger">The logger.</param>
    protected SecureChannelProtocolBase(
        IKeySet keySet,
        IKeyDerivationService keyDerivationService,
        ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(keySet);
        ArgumentNullException.ThrowIfNull(keyDerivationService);
        ArgumentNullException.ThrowIfNull(logger);
            
        _keySet = keySet;
        _keyDerivationService = keyDerivationService;
        _logger = logger;
    }

    /// <inheritdoc />
    public abstract byte ProtocolVersion { get; }

    /// <inheritdoc />
    public Result<InitializeUpdateCommand, SmartCardError> CreateInitializeUpdateCommand(byte[] hostChallenge)
    {
        var validationResult = ProtocolValidation.ValidateHostChallenge(hostChallenge);
        return validationResult.IsSuccess
            ? CreateInitializeUpdateCommandImpl(hostChallenge)
            : Result.Failure<InitializeUpdateCommand, SmartCardError>(
                SmartCardError.InvalidData(validationResult.Error));
    }

    /// <inheritdoc />
    public Result<SecureChannelContext, SmartCardError> ProcessInitializeUpdateResponse(
        InitializeUpdateResponse response,
        byte[] hostChallenge)
    {
        ArgumentNullException.ThrowIfNull(response);
            
        var hostValidation = ProtocolValidation.ValidateHostChallenge(hostChallenge);
        if (hostValidation.IsFailure)
        {
            return Result.Failure<SecureChannelContext, SmartCardError>(
                SmartCardError.InvalidData(hostValidation.Error));
        }

        var protocolValidation = ProtocolValidation.ValidateProtocolVersion(response.ScpId, ProtocolVersion);
        if (protocolValidation.IsFailure)
        {
            return Result.Failure<SecureChannelContext, SmartCardError>(
                SmartCardError.InvalidResponse(protocolValidation.Error));
        }

        return ProcessInitializeUpdateResponseImpl(response, hostChallenge);
    }

    /// <inheritdoc />
    public Result<ExternalAuthenticateCommand, SmartCardError> CreateExternalAuthenticateCommand(
        SecureChannelContext context,
        SecurityLevel securityLevel)
    {
        ArgumentNullException.ThrowIfNull(context);
            
        return CreateExternalAuthenticateCommandImpl(context, securityLevel);
    }

    /// <inheritdoc />
    public abstract Result<Security.SecureChannelState, SmartCardError> CreateSecureChannelSession(
        SecureChannelContext context,
        SecurityLevel securityLevel);

    /// <summary>
    /// Protocol-specific implementation of INITIALIZE UPDATE command creation.
    /// </summary>
    /// <param name="hostChallenge">The host challenge (already validated).</param>
    /// <returns>The INITIALIZE UPDATE command.</returns>
    protected abstract Result<InitializeUpdateCommand, SmartCardError> CreateInitializeUpdateCommandImpl(
        byte[] hostChallenge);

    /// <summary>
    /// Protocol-specific implementation of INITIALIZE UPDATE response processing.
    /// </summary>
    /// <param name="response">The response (protocol version already validated).</param>
    /// <param name="hostChallenge">The host challenge (already validated).</param>
    /// <returns>The secure channel context.</returns>
    protected abstract Result<SecureChannelContext, SmartCardError> ProcessInitializeUpdateResponseImpl(
        InitializeUpdateResponse response,
        byte[] hostChallenge);

    /// <summary>
    /// Protocol-specific implementation of EXTERNAL AUTHENTICATE command creation.
    /// </summary>
    /// <param name="context">The secure channel context.</param>
    /// <param name="securityLevel">The security level.</param>
    /// <returns>The EXTERNAL AUTHENTICATE command.</returns>
    protected abstract Result<ExternalAuthenticateCommand, SmartCardError> CreateExternalAuthenticateCommandImpl(
        SecureChannelContext context,
        SecurityLevel securityLevel);

    /// <summary>
    /// Builds the card cryptogram data for the specific protocol.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <returns>The card cryptogram data.</returns>
    protected abstract Result<byte[], SmartCardError> BuildCardCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge);

    /// <summary>
    /// Builds the host cryptogram data for the specific protocol.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <returns>The host cryptogram data.</returns>
    protected abstract Result<byte[], SmartCardError> BuildHostCryptogramData(
        InitializeUpdateResponse response,
        byte[] hostChallenge);

    /// <summary>
    /// Verifies the card cryptogram from the INITIALIZE UPDATE response using shared logic.
    /// </summary>
    /// <param name="response">The response.</param>
    /// <param name="hostChallenge">The host challenge.</param>
    /// <param name="sessionKeys">The session keys.</param>
    /// <returns>True if cryptogram is valid, false otherwise.</returns>
    protected Result<bool, SmartCardError> VerifyCardCryptogram(
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        SessionKeys sessionKeys)
    {
        return CryptogramBuilder.VerifyCardCryptogram(
            response,
            hostChallenge,
            sessionKeys,
            BuildCardCryptogramData,
            _keyDerivationService,
            ProtocolVersion);
    }

    /// <summary>
    /// Calculates the host cryptogram for EXTERNAL AUTHENTICATE using shared logic.
    /// </summary>
    /// <param name="context">The secure channel context.</param>
    /// <returns>The host cryptogram.</returns>
    protected Result<byte[], SmartCardError> CalculateHostCryptogram(SecureChannelContext context)
    {
        return CryptogramBuilder.CalculateHostCryptogram(
            context.InitializeUpdateResponse,
            context.HostChallenge,
            context.SessionKeys,
            BuildHostCryptogramData,
            _keyDerivationService,
            ProtocolVersion);
    }
}