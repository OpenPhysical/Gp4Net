using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol
{
    /// <summary>
    /// Interface for safe authentication management that prevents card lockout.
    /// Provides secure channel establishment with built-in protection against too many failed attempts.
    /// </summary>
    [PublicAPI]
    public interface ISafeAuthenticationManager
    {
        /// <summary>
        /// Establishes a secure channel with the card while protecting against lockout.
        /// Tracks failed authentication attempts and blocks further attempts after reaching the limit.
        /// </summary>
        /// <param name="channel">The card channel.</param>
        /// <param name="transport">The transport layer.</param>
        /// <param name="keySet">The key set to use for authentication.</param>
        /// <param name="securityLevel">The desired security level.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A result containing the secure channel session or an error.</returns>
        Task<Result<SecureChannelSession, SmartCardError>> EstablishSecureChannelAsync(
            ICardChannel channel,
            IApduTransport transport,
            IKeySet keySet,
            SecurityLevel securityLevel,
            CancellationToken cancellationToken = default
        );

        /// <summary>
        /// Establishes a secure channel with automatic protocol detection while protecting against lockout.
        /// </summary>
        /// <param name="channel">The card channel.</param>
        /// <param name="transport">The transport layer.</param>
        /// <param name="keySet">The key set to use for authentication.</param>
        /// <param name="securityLevel">The desired security level.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A result containing the secure channel session or an error.</returns>
        Task<Result<SecureChannelSession, SmartCardError>> EstablishAutoDetectAsync(
            ICardChannel channel,
            IApduTransport transport,
            IKeySet keySet,
            SecurityLevel securityLevel,
            CancellationToken cancellationToken = default
        );

        /// <summary>
        /// Resets the failed attempt counter for a specific card.
        /// Use this when you know the card is in a good state (e.g., after successful GP Pro reset).
        /// </summary>
        /// <param name="channel">The card channel.</param>
        /// <param name="transport">The transport.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        Task ResetAttemptsAsync(
            ICardChannel channel,
            IApduTransport transport,
            CancellationToken cancellationToken = default
        );

        /// <summary>
        /// Gets the current failed attempt count for a card.
        /// </summary>
        /// <param name="channel">The card channel.</param>
        /// <param name="transport">The transport.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The number of failed attempts.</returns>
        Task<int> GetFailedAttemptsAsync(
            ICardChannel channel,
            IApduTransport transport,
            CancellationToken cancellationToken = default
        );
    }
}