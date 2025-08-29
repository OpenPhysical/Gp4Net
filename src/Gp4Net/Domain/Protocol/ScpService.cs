// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Core.Functional;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Unified SCP service that coordinates all secure channel protocol operations.
/// Consolidates SCP02 and SCP03 functionality into a single, clean functional API.
/// Per GlobalPlatform Card Specification v2.3.1 Appendix E "Secure Channel Protocol".
/// </summary>
[PublicAPI]
public sealed class ScpService
{
    private readonly ScpChannelProcessor _channelProcessor;
    private readonly ScpCryptographyService _cryptographyService;
    private readonly IChallengeGenerator _challengeGenerator;
    private readonly ILogger<ScpService> _logger;

    /// <summary>
    /// Private constructor for functional creation pattern.
    /// </summary>
    private ScpService(
        ScpChannelProcessor channelProcessor,
        ScpCryptographyService cryptographyService,
        IChallengeGenerator challengeGenerator,
        ILogger<ScpService> logger)
    {
        _channelProcessor = channelProcessor;
        _cryptographyService = cryptographyService;
        _challengeGenerator = challengeGenerator;
        _logger = logger;
    }

    /// <summary>
    /// Creates a new ScpService instance with functional validation.
    /// </summary>
    /// <param name="challengeGenerator">The challenge generator for host challenges.</param>
    /// <param name="logger">The logger for diagnostic information.</param>
    /// <returns>A result containing the service or an error.</returns>
    public static Result<ScpService, SmartCardError> Create(
        IChallengeGenerator challengeGenerator,
        ILogger<ScpService> logger)
    {
        return Maybe<IChallengeGenerator>.From(challengeGenerator)
            .ToResult(SmartCardError.InvalidArgument("Challenge generator cannot be null"))
            .Bind(validChallengeGenerator => Maybe<ILogger<ScpService>>.From(logger)
                .ToResult(SmartCardError.InvalidArgument("Logger cannot be null"))
                .Bind(validLogger => ScpChannelProcessor.Create()
                    .Bind(processor => ScpCryptographyService.Create()
                        .Map(cryptoService => new ScpService(
                            processor,
                            cryptoService,
                            validChallengeGenerator,
                            validLogger)))));
    }

    /// <summary>
    /// Establishes a secure channel using the specified protocol and parameters.
    /// Handles both SCP02 and SCP03 protocols transparently.
    /// </summary>
    /// <param name="channel">The card channel for communication.</param>
    /// <param name="transport">The APDU transport for command transmission.</param>
    /// <param name="keySet">The key set containing static keys for the protocol.</param>
    /// <param name="securityLevel">The desired security level (C-MAC, C-ENC, R-MAC, R-ENC).</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A result containing the established secure channel state or error.</returns>
    public async Task<Result<SecureChannelState, SmartCardError>> EstablishChannelAsync(
        ICardChannel channel,
        IApduTransport transport,
        IKeySet keySet,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Establishing secure channel with security level {SecurityLevel}", securityLevel);

        var validationResult = ValidateEstablishmentInputs(channel, transport, keySet);
        if (validationResult.IsFailure)
            return Result.Failure<SecureChannelState, SmartCardError>(validationResult.Error);
            
        return await PerformChannelEstablishment(channel, transport, keySet, securityLevel, cancellationToken);
    }

    /// <summary>
    /// Wraps a command with secure channel protection (C-MAC, C-ENC) based on the current state.
    /// </summary>
    /// <param name="command">The command to wrap.</param>
    /// <param name="state">The current secure channel state.</param>
    /// <returns>A result containing the wrapped command and updated state or error.</returns>
    public Result<(byte[] wrappedCommand, SecureChannelState newState), SmartCardError> WrapCommand(
        IApduCommand command,
        SecureChannelState state)
    {
        _logger.LogDebug("Wrapping command with protocol {Protocol:X2}", state.ProtocolVersion);

        return ValidateWrapInputs(command, state)
            .ToResult()
            .Bind(_ => _channelProcessor.ApplyCommandSecurity(command, state));
    }

    /// <summary>
    /// Unwraps a response by verifying and removing secure channel protection (R-MAC, R-ENC).
    /// </summary>
    /// <param name="response">The response to unwrap.</param>
    /// <param name="state">The current secure channel state.</param>
    /// <returns>A result containing the unwrapped response and updated state or error.</returns>
    public Result<(byte[] unwrappedResponse, SecureChannelState newState), SmartCardError> UnwrapResponse(
        byte[] response,
        SecureChannelState state)
    {
        _logger.LogDebug("Unwrapping response with protocol {Protocol:X2}", state.ProtocolVersion);

        return ValidateUnwrapInputs(response, state)
            .ToResult()
            .Bind(_ => _channelProcessor.ApplyResponseSecurity(response, state));
    }

    /// <summary>
    /// Detects the SCP protocol version from a key set type.
    /// </summary>
    /// <param name="keySet">The key set to analyze.</param>
    /// <returns>A result containing the detected protocol version or error.</returns>
    public static Result<ScpVersion, SmartCardError> DetectProtocolVersion(IKeySet keySet)
    {
        return keySet switch
        {
            Scp02KeySet _ => Result.Success<ScpVersion, SmartCardError>(ScpVersion.Scp02),
            Scp03KeySet _ => Result.Success<ScpVersion, SmartCardError>(ScpVersion.Scp03),
            _ => SmartCardError.InvalidArgument($"Unknown key set type: {keySet.GetType().Name}")
        };
    }

    /// <summary>
    /// Validates that an implementation parameter is supported for the given protocol.
    /// </summary>
    /// <param name="protocolVersion">The protocol version.</param>
    /// <param name="implementationParameter">The implementation parameter to validate.</param>
    /// <returns>A result indicating validation success or error.</returns>
    public static UnitResult<SmartCardError> ValidateImplementationParameter(
        ScpVersion protocolVersion,
        byte implementationParameter)
    {
        return protocolVersion switch
        {
            ScpVersion.Scp02 => ValidateScp02Implementation(implementationParameter),
            ScpVersion.Scp03 => ValidateScp03Implementation(implementationParameter),
            _ => SmartCardError.InvalidArgument($"Unsupported protocol version: {protocolVersion:X2}")
        };
    }

    // Private implementation methods

    private static UnitResult<SmartCardError> ValidateEstablishmentInputs(
        ICardChannel channel,
        IApduTransport transport,
        IKeySet keySet)
    {
        return Maybe<ICardChannel>.From(channel)
            .ToResult(SmartCardError.InvalidArgument("Channel cannot be null"))
            .Bind(_ => Maybe<IApduTransport>.From(transport)
                .ToResult(SmartCardError.InvalidArgument("Transport cannot be null")))
            .Bind(_ => Maybe<IKeySet>.From(keySet)
                .ToResult(SmartCardError.InvalidArgument("Key set cannot be null")))
            .ToUnitResult();
    }

    private async Task<Result<SecureChannelState, SmartCardError>> PerformChannelEstablishment(
        ICardChannel channel,
        IApduTransport transport,
        IKeySet keySet,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken)
    {
        // Detect protocol from key set
        return await DetectProtocolVersion(keySet)
            .Match(
                protocolVersion =>
                {
                    _logger.LogDebug("Detected protocol version: {Protocol:X2}", protocolVersion);

                    // Generate host challenge
                    byte[] hostChallenge = _challengeGenerator.GenerateChallenge(8);

                    return protocolVersion switch
                    {
                        ScpVersion.Scp02 => EstablishScp02Channel(channel, transport, keySet, securityLevel, hostChallenge, cancellationToken),
                        ScpVersion.Scp03 => EstablishScp03Channel(channel, transport, keySet, securityLevel, hostChallenge, cancellationToken),
                        _ => Task.FromResult<Result<SecureChannelState, SmartCardError>>(
                            SmartCardError.InvalidArgument($"Unsupported protocol version: {protocolVersion:X2}"))
                    };
                },
                error => Task.FromResult<Result<SecureChannelState, SmartCardError>>(error));
    }

    private async Task<Result<SecureChannelState, SmartCardError>> EstablishScp02Channel(
        ICardChannel channel,
        IApduTransport transport,
        IKeySet keySet,
        SecurityLevel securityLevel,
        byte[] hostChallenge,
        CancellationToken cancellationToken)
    {
        // Use existing Scp02Protocol methods for establishment
        var initUpdateCmdResult = Scp02Protocol.CreateInitializeUpdateCommand(hostChallenge);
        if (initUpdateCmdResult.IsFailure)
            return Result.Failure<SecureChannelState, SmartCardError>(initUpdateCmdResult.Error);

        var initUpdateCmd = initUpdateCmdResult.Value;
        _logger.LogDebug("Sending SCP02 INITIALIZE UPDATE command");

        var initResponse = await transport.TransmitAsync(initUpdateCmd, channel, cancellationToken);
        if (!initResponse.IsSuccess)
            return Result.Failure<SecureChannelState, SmartCardError>(
                SmartCardError.CommunicationError($"INITIALIZE UPDATE failed: SW={initResponse.StatusWord:X4}"));

        var parseResult = InitializeUpdateResponse.Parse(initResponse.Data);
        if (parseResult.IsFailure)
            return Result.Failure<SecureChannelState, SmartCardError>(parseResult.Error);

        var processResult = Scp02Protocol.ProcessInitializeUpdateResponse(parseResult.Value, hostChallenge, keySet);
        if (processResult.IsFailure)
            return Result.Failure<SecureChannelState, SmartCardError>(processResult.Error);

        return await CompleteScp02Authentication(processResult.Value, securityLevel, channel, transport, cancellationToken);
    }

    private async Task<Result<SecureChannelState, SmartCardError>> EstablishScp03Channel(
        ICardChannel channel,
        IApduTransport transport,
        IKeySet keySet,
        SecurityLevel securityLevel,
        byte[] hostChallenge,
        CancellationToken cancellationToken)
    {
        // Use existing Scp03Protocol methods for establishment
        var initUpdateCmdResult = Scp03Protocol.CreateInitializeUpdateCommand(0x00, hostChallenge);
        if (initUpdateCmdResult.IsFailure)
            return Result.Failure<SecureChannelState, SmartCardError>(initUpdateCmdResult.Error);

        var initUpdateCmd = initUpdateCmdResult.Value;
        _logger.LogDebug("Sending SCP03 INITIALIZE UPDATE command");

        var initResponse = await transport.TransmitAsync(initUpdateCmd, channel, cancellationToken);
        if (!initResponse.IsSuccess)
            return Result.Failure<SecureChannelState, SmartCardError>(
                SmartCardError.CommunicationError($"INITIALIZE UPDATE failed: SW={initResponse.StatusWord:X4}"));

        var parseResult = InitializeUpdateResponse.Parse(initResponse.Data);
        if (parseResult.IsFailure)
            return Result.Failure<SecureChannelState, SmartCardError>(parseResult.Error);

        var processResult = Scp03Protocol.ProcessInitializeUpdateResponse(parseResult.Value, hostChallenge, keySet);
        if (processResult.IsFailure)
            return Result.Failure<SecureChannelState, SmartCardError>(processResult.Error);

        return await CompleteScp03Authentication(processResult.Value, securityLevel, channel, transport, cancellationToken);
    }

    private async Task<Result<SecureChannelState, SmartCardError>> CompleteScp02Authentication(
        SecureChannelContext context,
        SecurityLevel securityLevel,
        ICardChannel channel,
        IApduTransport transport,
        CancellationToken cancellationToken)
    {
        var extAuthCmdResult = Scp02Protocol.CreateExternalAuthenticateCommand(context, securityLevel);
        if (extAuthCmdResult.IsFailure)
            return Result.Failure<SecureChannelState, SmartCardError>(extAuthCmdResult.Error);

        var extAuthCmd = extAuthCmdResult.Value;
        _logger.LogDebug("Sending SCP02 EXTERNAL AUTHENTICATE command");

        var extAuthResponse = await transport.TransmitAsync(extAuthCmd, channel, cancellationToken);
        if (!extAuthResponse.IsSuccess)
            return Result.Failure<SecureChannelState, SmartCardError>(
                SmartCardError.AuthenticationFailed($"EXTERNAL AUTHENTICATE failed: SW={extAuthResponse.StatusWord:X4}"));

        return Scp02Protocol.CreateSecureChannelSession(context, securityLevel);
    }

    private async Task<Result<SecureChannelState, SmartCardError>> CompleteScp03Authentication(
        SecureChannelContext context,
        SecurityLevel securityLevel,
        ICardChannel channel,
        IApduTransport transport,
        CancellationToken cancellationToken)
    {
        // For SCP03, we need to build the host cryptogram and create the command
        var hostCryptogramDataResult = CryptographicOperations.BuildScp03HostCryptogramData(context.InitializeUpdateResponse, context.HostChallenge);
        if (hostCryptogramDataResult.IsFailure)
            return Result.Failure<SecureChannelState, SmartCardError>(hostCryptogramDataResult.Error);

        var cryptogramResult = MacCalculations.CalculateScp03Cryptogram(context.SessionKeys.SEnc, hostCryptogramDataResult.Value);
        if (cryptogramResult.IsFailure)
            return Result.Failure<SecureChannelState, SmartCardError>(cryptogramResult.Error);

        byte[] truncatedCryptogram = cryptogramResult.Value.Take(8).ToArray();
        
        var extAuthCmdResult = Scp03Protocol.CreateExternalAuthenticateCommand(securityLevel, truncatedCryptogram, context.SessionKeys.SMac);
        if (extAuthCmdResult.IsFailure)
            return Result.Failure<SecureChannelState, SmartCardError>(extAuthCmdResult.Error);

        var extAuthCmd = extAuthCmdResult.Value;
        _logger.LogDebug("Sending SCP03 EXTERNAL AUTHENTICATE command");

        var extAuthResponse = await transport.TransmitAsync(extAuthCmd, channel, cancellationToken);
        if (!extAuthResponse.IsSuccess)
            return Result.Failure<SecureChannelState, SmartCardError>(
                SmartCardError.AuthenticationFailed($"EXTERNAL AUTHENTICATE failed: SW={extAuthResponse.StatusWord:X4}"));

        return Scp03Protocol.CreateSecureChannelSession(context, securityLevel);
    }

    private static UnitResult<SmartCardError> ValidateWrapInputs(IApduCommand command, SecureChannelState state)
    {
        return Maybe<IApduCommand>.From(command)
            .ToResult(SmartCardError.InvalidArgument("Command cannot be null"))
            .Bind(_ => Maybe<SecureChannelState>.From(state)
                .ToResult(SmartCardError.InvalidArgument("State cannot be null")))
            .ToUnitResult();
    }

    private static UnitResult<SmartCardError> ValidateUnwrapInputs(byte[] response, SecureChannelState state)
    {
        return Maybe<byte[]>.From(response)
            .ToResult(SmartCardError.InvalidArgument("Response cannot be null"))
            .Bind(_ => Maybe<SecureChannelState>.From(state)
                .ToResult(SmartCardError.InvalidArgument("State cannot be null")))
            .Bind(_ => response.Length >= 2
                ? Result.Success<bool, SmartCardError>(true)
                : Result.Failure<bool, SmartCardError>(SmartCardError.InvalidArgument("Response must be at least 2 bytes")))
            .ToUnitResult();
    }

    private static UnitResult<SmartCardError> ValidateScp02Implementation(byte implementationParameter)
    {
        return Scp02Protocol.IsValidScp02Implementation(implementationParameter)
            ? UnitResult.Success<SmartCardError>()
            : SmartCardError.InvalidArgument($"Unsupported SCP02 implementation: {implementationParameter:X2}");
    }

    private static UnitResult<SmartCardError> ValidateScp03Implementation(byte implementationParameter)
    {
        return Scp03Protocol.IsValidImplementation(implementationParameter)
            ? UnitResult.Success<SmartCardError>()
            : SmartCardError.InvalidArgument($"Unsupported SCP03 implementation: {implementationParameter:X2}");
    }
}
