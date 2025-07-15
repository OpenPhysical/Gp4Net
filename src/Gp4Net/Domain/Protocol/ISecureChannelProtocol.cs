using System.Threading;
using System.Threading.Tasks;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol
{
    /// <summary>
    /// Represents a secure channel protocol implementation (SCP01, SCP02, SCP03).
    /// </summary>
    [PublicAPI]
    public interface ISecureChannelProtocol
    {
        /// <summary>
        /// Gets the protocol version identifier.
        /// </summary>
        byte ProtocolVersion { get; }

        /// <summary>
        /// Creates an INITIALIZE UPDATE command for this protocol.
        /// </summary>
        /// <param name="hostChallenge">The host challenge (8 bytes).</param>
        /// <returns>A result containing the INITIALIZE UPDATE command or an error.</returns>
        Result<InitializeUpdateCommand, SmartCardError> CreateInitializeUpdateCommand(byte[] hostChallenge);

        /// <summary>
        /// Processes an INITIALIZE UPDATE response and creates an authentication context.
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response.</param>
        /// <param name="hostChallenge">The host challenge used in the command.</param>
        /// <returns>The secure channel context for authentication.</returns>
        SecureChannelContext ProcessInitializeUpdateResponse(
            InitializeUpdateResponse response,
            byte[] hostChallenge
        );

        /// <summary>
        /// Creates an EXTERNAL AUTHENTICATE command from the context.
        /// </summary>
        /// <param name="context">The secure channel context.</param>
        /// <param name="securityLevel">The requested security level.</param>
        /// <returns>A result containing the EXTERNAL AUTHENTICATE command or an error.</returns>
        Result<ExternalAuthenticateCommand, SmartCardError> CreateExternalAuthenticateCommand(
            SecureChannelContext context,
            SecurityLevel securityLevel
        );

        /// <summary>
        /// Creates a secure channel session after successful authentication.
        /// </summary>
        /// <param name="context">The secure channel context.</param>
        /// <param name="securityLevel">The established security level.</param>
        /// <returns>The secure channel session.</returns>
        SecureChannelSession CreateSecureChannelSession(
            SecureChannelContext context,
            SecurityLevel securityLevel
        );
    }

    /// <summary>
    /// Factory for creating secure channel protocol implementations.
    /// </summary>
    [PublicAPI]
    public interface ISecureChannelProtocolFactory
    {
        /// <summary>
        /// Creates a secure channel protocol for the specified version and key set.
        /// </summary>
        /// <param name="protocolVersion">The protocol version (SCP01, SCP02, SCP03).</param>
        /// <param name="keySet">The key set to use.</param>
        /// <returns>The protocol implementation.</returns>
        ISecureChannelProtocol CreateProtocol(byte protocolVersion, IKeySet keySet);

        /// <summary>
        /// Determines the protocol version from an INITIALIZE UPDATE response.
        /// </summary>
        /// <param name="response">The INITIALIZE UPDATE response.</param>
        /// <returns>The detected protocol version.</returns>
        byte DetectProtocolVersion(InitializeUpdateResponse response);
    }

    /// <summary>
    /// High-level service for managing secure channel operations.
    /// </summary>
    [PublicAPI]
    public interface ISecureChannelManager
    {
        /// <summary>
        /// Establishes a secure channel with the card.
        /// </summary>
        /// <param name="channel">The card channel.</param>
        /// <param name="transport">The APDU transport.</param>
        /// <param name="keySet">The key set to use for authentication.</param>
        /// <param name="securityLevel">The requested security level.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The established secure channel session.</returns>
        Task<SecureChannelSession> EstablishAsync(
            ICardChannel channel,
            IApduTransport transport,
            IKeySet keySet,
            SecurityLevel securityLevel,
            CancellationToken cancellationToken = default
        );

        /// <summary>
        /// Auto-detects the protocol and establishes a secure channel.
        /// </summary>
        /// <param name="channel">The card channel.</param>
        /// <param name="transport">The APDU transport.</param>
        /// <param name="keySet">The key set to use for authentication.</param>
        /// <param name="securityLevel">The requested security level.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The established secure channel session.</returns>
        Task<SecureChannelSession> EstablishAutoDetectAsync(
            ICardChannel channel,
            IApduTransport transport,
            IKeySet keySet,
            SecurityLevel securityLevel,
            CancellationToken cancellationToken = default
        );
    }
}
