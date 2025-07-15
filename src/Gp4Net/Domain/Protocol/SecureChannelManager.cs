using System;
using System.Threading;
using System.Threading.Tasks;
using Gp4Net.Constants;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Domain.Protocol
{
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
        public async Task<SecureChannelSession> EstablishAsync(
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

                // Create INITIALIZE UPDATE command based on key set type
                var protocolVersion = DetectProtocolFromKeySet(keySet);
                var protocol = _protocolFactory.CreateProtocol(protocolVersion, keySet);

                var initUpdateCmdResult = protocol.CreateInitializeUpdateCommand(hostChallenge);
                
                if (initUpdateCmdResult.IsFailure)
                {
                    throw new InvalidOperationException(
                        $"Failed to create INITIALIZE UPDATE command: {initUpdateCmdResult.Error.Message}"
                    );
                }
                
                var initUpdateCmd = initUpdateCmdResult.Value;

                _logger.LogDebug("Sending INITIALIZE UPDATE command");

                // Send INITIALIZE UPDATE
                var initUpdateResponse = await transport
                    .TransmitAsync(initUpdateCmd, channel, cancellationToken)
                    .ConfigureAwait(false);

                if (!initUpdateResponse.IsSuccess)
                {
                    throw new InvalidOperationException(
                        $"INITIALIZE UPDATE failed: SW={initUpdateResponse.StatusWord:X4}"
                    );
                }

                // Parse response
                var parsedResponse = InitializeUpdateResponse.Parse(initUpdateResponse.Data);

                _logger.LogDebug(
                    "Received INITIALIZE UPDATE response for protocol {Protocol:X2}",
                    parsedResponse.ScpId
                );

                // Process response with appropriate protocol
                var actualProtocol = _protocolFactory.CreateProtocol(parsedResponse.ScpId, keySet);
                var context = actualProtocol.ProcessInitializeUpdateResponse(
                    parsedResponse,
                    hostChallenge
                );

                // Create EXTERNAL AUTHENTICATE command
                var extAuthCmdResult = actualProtocol.CreateExternalAuthenticateCommand(
                    context,
                    securityLevel
                );
                
                if (extAuthCmdResult.IsFailure)
                {
                    throw new InvalidOperationException(
                        $"Failed to create EXTERNAL AUTHENTICATE command: {extAuthCmdResult.Error.Message}"
                    );
                }
                
                var extAuthCmd = extAuthCmdResult.Value;

                _logger.LogDebug("Sending EXTERNAL AUTHENTICATE command");

                // Send EXTERNAL AUTHENTICATE
                var extAuthResponse = await transport
                    .TransmitAsync(extAuthCmd, channel, cancellationToken)
                    .ConfigureAwait(false);

                if (!extAuthResponse.IsSuccess)
                {
                    throw new InvalidOperationException(
                        $"EXTERNAL AUTHENTICATE failed: SW={extAuthResponse.StatusWord:X4}"
                    );
                }

                // Create secure channel session
                var session = actualProtocol.CreateSecureChannelSession(context, securityLevel);

                _logger.LogInformation(
                    "Successfully established secure channel with protocol {Protocol:X2}",
                    parsedResponse.ScpId
                );

                return session;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to establish secure channel");
                throw;
            }
        }

        /// <inheritdoc />
        public async Task<SecureChannelSession> EstablishAutoDetectAsync(
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
                    throw new InvalidOperationException(
                        $"Failed to create INITIALIZE UPDATE command: {initUpdateCmdResult.Error.Message}"
                    );
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
                        throw new InvalidOperationException(
                            $"Failed to create INITIALIZE UPDATE command: {initUpdateCmdResult.Error.Message}"
                        );
                    }
                    
                    initUpdateCmd = initUpdateCmdResult.Value;
                    initUpdateResponse = await transport
                        .TransmitAsync(initUpdateCmd, channel, cancellationToken)
                        .ConfigureAwait(false);

                    if (!initUpdateResponse.IsSuccess)
                    {
                        throw new InvalidOperationException(
                            $"INITIALIZE UPDATE failed: SW={initUpdateResponse.StatusWord:X4}"
                        );
                    }
                }

                // Parse response to detect protocol
                var parsedResponse = InitializeUpdateResponse.Parse(initUpdateResponse.Data);
                var detectedProtocol = _protocolFactory.DetectProtocolVersion(parsedResponse);

                _logger.LogInformation("Detected protocol: {Protocol:X2}", detectedProtocol);

                // Create appropriate protocol handler
                var protocol = _protocolFactory.CreateProtocol(detectedProtocol, keySet);

                // Process response
                var context = protocol.ProcessInitializeUpdateResponse(
                    parsedResponse,
                    hostChallenge
                );

                // Create EXTERNAL AUTHENTICATE command
                var extAuthCmdResult = protocol.CreateExternalAuthenticateCommand(context, securityLevel);
                
                if (extAuthCmdResult.IsFailure)
                {
                    throw new InvalidOperationException(
                        $"Failed to create EXTERNAL AUTHENTICATE command: {extAuthCmdResult.Error.Message}"
                    );
                }
                
                var extAuthCmd = extAuthCmdResult.Value;

                _logger.LogDebug("Sending EXTERNAL AUTHENTICATE command");

                // Send EXTERNAL AUTHENTICATE
                var extAuthResponse = await transport
                    .TransmitAsync(extAuthCmd, channel, cancellationToken)
                    .ConfigureAwait(false);

                if (!extAuthResponse.IsSuccess)
                {
                    throw new InvalidOperationException(
                        $"EXTERNAL AUTHENTICATE failed: SW={extAuthResponse.StatusWord:X4}"
                    );
                }

                // Create secure channel session
                var session = protocol.CreateSecureChannelSession(context, securityLevel);

                _logger.LogInformation(
                    "Successfully established secure channel with auto-detected protocol {Protocol:X2}",
                    detectedProtocol
                );

                return session;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to establish secure channel with auto-detection");
                throw;
            }
        }


        /// <summary>
        /// Detects the protocol version from the key set type.
        /// </summary>
        private byte DetectProtocolFromKeySet(IKeySet keySet)
        {
            return keySet switch
            {
                Scp02KeySet _ => ProtocolIdentifiers.Scp02,
                Scp03KeySet _ => ProtocolIdentifiers.Scp03,
                _
                    => throw new NotSupportedException(
                        $"Unknown key set type: {keySet.GetType().Name}"
                    ),
            };
        }
    }
}
