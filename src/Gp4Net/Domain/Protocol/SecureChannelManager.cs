using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// High-level service for managing secure channel operations.
/// Handles the complete authentication flow and session establishment.
/// </summary>
[PublicAPI]
public class SecureChannelManager : ISecureChannelManager
{
    private readonly ISecureChannelProtocolFactory _protocolFactory;
    private readonly IChallengeGenerator _challengeGenerator;
    private readonly ILogger<SecureChannelManager> _logger;

    /// <summary>
    /// Initializes a new instance of SecureChannelManager.
    /// </summary>
    /// <param name="protocolFactory">The protocol factory.</param>
    /// <param name="challengeGenerator">The challenge generator.</param>
    /// <param name="logger">The logger.</param>
    public SecureChannelManager(
        ISecureChannelProtocolFactory protocolFactory,
        IChallengeGenerator challengeGenerator,
        ILogger<SecureChannelManager> logger
    )
    {
        ArgumentNullException.ThrowIfNull(protocolFactory);
        ArgumentNullException.ThrowIfNull(challengeGenerator);
        ArgumentNullException.ThrowIfNull(logger);
        _protocolFactory = protocolFactory;
        _challengeGenerator = challengeGenerator;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<Result<Security.SecureChannelState, SmartCardError>> EstablishAsync(
        ICardChannel channel,
        IApduTransport transport,
        IKeySet keySet,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(keySet);

        _logger.LogInformation(
            "Establishing secure channel with security level {SecurityLevel}",
            securityLevel
        );

        try
        {
            // Generate host challenge
            var hostChallenge = _challengeGenerator.GenerateChallenge(8);

            // Detect protocol version from key set
            var protocolVersionResult = DetectProtocolFromKeySet(keySet);
            if (protocolVersionResult.IsFailure)
            {
                _logger.LogError("Failed to detect protocol from key set");
                return protocolVersionResult.Error;
            }

            var protocolVersion = protocolVersionResult.Value;
            var protocol = _protocolFactory.CreateProtocol(protocolVersion, keySet);

            // Create INITIALIZE UPDATE command
            var initUpdateCmdResult = protocol.CreateInitializeUpdateCommand(hostChallenge);
            if (initUpdateCmdResult.IsFailure)
            {
                _logger.LogError("Failed to create INITIALIZE UPDATE command: {Error}", initUpdateCmdResult.Error.Message);
                return initUpdateCmdResult.Error;
            }
                
            var initUpdateCmd = initUpdateCmdResult.Value;
            _logger.LogDebug("Sending INITIALIZE UPDATE command");

            // Send INITIALIZE UPDATE
            var initUpdateResponse = await transport
                .TransmitAsync(initUpdateCmd, channel, cancellationToken)
                .ConfigureAwait(false);

            if (!initUpdateResponse.IsSuccess)
            {
                var error = SmartCardError.CommunicationError(
                    $"INITIALIZE UPDATE failed: SW={initUpdateResponse.StatusWord:X4}"
                );
                _logger.LogError("INITIALIZE UPDATE failed: SW={StatusWord:X4}", initUpdateResponse.StatusWord);
                return error;
            }

            // Parse response
            var parsedResponse = InitializeUpdateResponse.Parse(initUpdateResponse.Data);

            _logger.LogDebug(
                "Received INITIALIZE UPDATE response for protocol {Protocol:X2}",
                parsedResponse.ScpId
            );

            // Process response with appropriate protocol
            var actualProtocol = _protocolFactory.CreateProtocol(parsedResponse.ScpId, keySet);
            var contextResult = actualProtocol.ProcessInitializeUpdateResponse(
                parsedResponse,
                hostChallenge
            );

            if (contextResult.IsFailure)
            {
                _logger.LogError("Failed to process INITIALIZE UPDATE response: {Error}", contextResult.Error.Message);
                return contextResult.Error;
            }

            var context = contextResult.Value;

            // Create EXTERNAL AUTHENTICATE command
            var extAuthCmdResult = actualProtocol.CreateExternalAuthenticateCommand(
                context,
                securityLevel
            );
                
            if (extAuthCmdResult.IsFailure)
            {
                _logger.LogError("Failed to create EXTERNAL AUTHENTICATE command: {Error}", extAuthCmdResult.Error.Message);
                return extAuthCmdResult.Error;
            }
                
            var extAuthCmd = extAuthCmdResult.Value;
            _logger.LogDebug("Sending EXTERNAL AUTHENTICATE command");

            // Send EXTERNAL AUTHENTICATE
            var extAuthResponse = await transport
                .TransmitAsync(extAuthCmd, channel, cancellationToken)
                .ConfigureAwait(false);

            if (!extAuthResponse.IsSuccess)
            {
                var error = SmartCardError.CommunicationError(
                    $"EXTERNAL AUTHENTICATE failed: SW={extAuthResponse.StatusWord:X4}"
                );
                _logger.LogError("EXTERNAL AUTHENTICATE failed: SW={StatusWord:X4}", extAuthResponse.StatusWord);
                return error;
            }

            // Create secure channel session
            var sessionResult = actualProtocol.CreateSecureChannelSession(context, securityLevel);
            
            if (sessionResult.IsFailure)
            {
                _logger.LogError("Failed to create secure channel session: {Error}", sessionResult.Error.Message);
                return sessionResult.Error;
            }

            _logger.LogInformation(
                "Successfully established secure channel with protocol {Protocol:X2}",
                parsedResponse.ScpId
            );

            return sessionResult;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to establish secure channel");
            return SmartCardError.UnexpectedError($"Unexpected error during secure channel establishment: {ex.Message}", ex);
        }
    }

    /// <inheritdoc />
    public async Task<Result<Security.SecureChannelState, SmartCardError>> EstablishAutoDetectAsync(
        ICardChannel channel,
        IApduTransport transport,
        IKeySet keySet,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(keySet);

        _logger.LogInformation("Auto-detecting secure channel protocol");

        try
        {
            // Generate host challenge
            var hostChallenge = _challengeGenerator.GenerateChallenge(8);

            // Try with key version 0x00 first, using a generic INITIALIZE UPDATE
            var initUpdateCmdResult = InitializeUpdateCommand.Create(0x00, 0x00, hostChallenge);
            if (initUpdateCmdResult.IsFailure)
            {
                _logger.LogError("Failed to create INITIALIZE UPDATE command: {Error}", initUpdateCmdResult.Error.Message);
                return initUpdateCmdResult.Error;
            }
                
            var initUpdateCmd = initUpdateCmdResult.Value;
            _logger.LogDebug("Sending INITIALIZE UPDATE for protocol detection");

            // Send INITIALIZE UPDATE
            var initUpdateResponse = await transport
                .TransmitAsync(initUpdateCmd, channel, cancellationToken)
                .ConfigureAwait(false);

            if (!initUpdateResponse.IsSuccess)
            {
                // Try with key version 0xFF
                _logger.LogDebug("Retrying with key version 0xFF");

                initUpdateCmdResult = InitializeUpdateCommand.Create(0xFF, 0x00, hostChallenge);
                if (initUpdateCmdResult.IsFailure)
                {
                    _logger.LogError("Failed to create INITIALIZE UPDATE command (retry): {Error}", initUpdateCmdResult.Error.Message);
                    return initUpdateCmdResult.Error;
                }
                    
                initUpdateCmd = initUpdateCmdResult.Value;
                initUpdateResponse = await transport
                    .TransmitAsync(initUpdateCmd, channel, cancellationToken)
                    .ConfigureAwait(false);

                if (!initUpdateResponse.IsSuccess)
                {
                    var error = SmartCardError.CommunicationError(
                        $"INITIALIZE UPDATE failed: SW={initUpdateResponse.StatusWord:X4}"
                    );
                    _logger.LogError("INITIALIZE UPDATE failed: SW={StatusWord:X4}", initUpdateResponse.StatusWord);
                    return error;
                }
            }

            // Parse response to detect protocol
            var parsedResponse = InitializeUpdateResponse.Parse(initUpdateResponse.Data);
            var detectedProtocol = _protocolFactory.DetectProtocolVersion(parsedResponse);

            _logger.LogInformation("Detected protocol: {Protocol:X2}", detectedProtocol);

            // Create appropriate protocol handler
            var protocol = _protocolFactory.CreateProtocol(detectedProtocol, keySet);

            // Process response
            var contextResult = protocol.ProcessInitializeUpdateResponse(
                parsedResponse,
                hostChallenge
            );

            if (contextResult.IsFailure)
            {
                _logger.LogError("Failed to process INITIALIZE UPDATE response: {Error}", contextResult.Error.Message);
                return contextResult.Error;
            }

            var context = contextResult.Value;

            // Create EXTERNAL AUTHENTICATE command
            var extAuthCmdResult = protocol.CreateExternalAuthenticateCommand(context, securityLevel);
                
            if (extAuthCmdResult.IsFailure)
            {
                _logger.LogError("Failed to create EXTERNAL AUTHENTICATE command: {Error}", extAuthCmdResult.Error.Message);
                return extAuthCmdResult.Error;
            }
                
            var extAuthCmd = extAuthCmdResult.Value;
            _logger.LogDebug("Sending EXTERNAL AUTHENTICATE command");

            // Send EXTERNAL AUTHENTICATE
            var extAuthResponse = await transport
                .TransmitAsync(extAuthCmd, channel, cancellationToken)
                .ConfigureAwait(false);

            if (!extAuthResponse.IsSuccess)
            {
                var error = SmartCardError.CommunicationError(
                    $"EXTERNAL AUTHENTICATE failed: SW={extAuthResponse.StatusWord:X4}"
                );
                _logger.LogError("EXTERNAL AUTHENTICATE failed: SW={StatusWord:X4}", extAuthResponse.StatusWord);
                return error;
            }

            // Create secure channel session
            var sessionResult = protocol.CreateSecureChannelSession(context, securityLevel);
            
            if (sessionResult.IsFailure)
            {
                _logger.LogError("Failed to create secure channel session: {Error}", sessionResult.Error.Message);
                return sessionResult.Error;
            }

            _logger.LogInformation(
                "Successfully established secure channel with auto-detected protocol {Protocol:X2}",
                detectedProtocol
            );

            return sessionResult;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to establish secure channel with auto-detection");
            return SmartCardError.UnexpectedError($"Unexpected error during secure channel auto-detection: {ex.Message}", ex);
        }
    }


    /// <summary>
    /// Detects the protocol version from the key set type.
    /// </summary>
    private static Result<byte, SmartCardError> DetectProtocolFromKeySet(IKeySet keySet)
    {
        return keySet switch
        {
            Scp02KeySet _ => Result.Success<byte, SmartCardError>(ProtocolIdentifiers.Scp02),
            Scp03KeySet _ => Result.Success<byte, SmartCardError>(ProtocolIdentifiers.Scp03),
            _ => SmartCardError.InvalidData($"Unknown key set type: {keySet.GetType().Name}")
        };
    }
}