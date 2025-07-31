using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Domain.Protocol
{
    /// <summary>
    /// Safe authentication manager that prevents card lockout by limiting authentication attempts.
    /// Tracks failed attempts per card and enforces configurable limits to protect against bricking cards.
    /// </summary>
    [PublicAPI]
    public class SafeAuthenticationManager : ISafeAuthenticationManager
    {
        private readonly ISecureChannelManager _innerManager;
        private readonly ILogger<SafeAuthenticationManager> _logger;
        private readonly ConcurrentDictionary<string, AttemptTracker> _attemptTrackers = new();
        private readonly int _maxAttempts;

        /// <summary>
        /// Default maximum number of authentication attempts before blocking.
        /// </summary>
        public const int DefaultMaxAttempts = 3;

        /// <summary>
        /// Initializes a new instance of SafeAuthenticationManager.
        /// </summary>
        /// <param name="innerManager">The underlying secure channel manager.</param>
        /// <param name="logger">The logger.</param>
        /// <param name="maxAttempts">Maximum attempts before blocking (default: 3).</param>
        public SafeAuthenticationManager(
            ISecureChannelManager innerManager,
            ILogger<SafeAuthenticationManager> logger,
            int maxAttempts = DefaultMaxAttempts
        )
        {
            ArgumentNullException.ThrowIfNull(innerManager);
            ArgumentNullException.ThrowIfNull(logger);
            
            if (maxAttempts < 1)
            {
                throw new ArgumentException("Maximum attempts must be at least 1", nameof(maxAttempts));
            }

            _innerManager = innerManager;
            _logger = logger;
            _maxAttempts = maxAttempts;
        }

        /// <inheritdoc />
        public async Task<Result<SecureChannelSession, SmartCardError>> EstablishSecureChannelAsync(
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

            // Generate a card identifier for attempt tracking
            var cardId = await GetCardIdentifierAsync(channel, transport, cancellationToken);
            var tracker = _attemptTrackers.GetOrAdd(cardId, _ => new AttemptTracker());

            // Check if we've exceeded the maximum attempts
            if (tracker.FailedAttempts >= _maxAttempts)
            {
                _logger.LogError(
                    "Authentication blocked: {FailedAttempts} failed attempts for card {CardId}. " +
                    "Card may be locked. Manual reset required.",
                    tracker.FailedAttempts,
                    cardId
                );

                return Result.Failure<SecureChannelSession, SmartCardError>(
                    SmartCardError.AuthenticationBlocked(
                        $"Too many failed attempts ({tracker.FailedAttempts}/{_maxAttempts}). " +
                        "Card protection activated to prevent lockout."
                    )
                );
            }

            try
            {
                _logger.LogInformation(
                    "Attempting secure channel establishment for card {CardId} " +
                    "(attempt {CurrentAttempt}/{MaxAttempts})",
                    cardId,
                    tracker.FailedAttempts + 1,
                    _maxAttempts
                );

                // Attempt authentication using the inner manager
                var sessionResult = await _innerManager.EstablishAsync(
                    channel,
                    transport,
                    keySet,
                    securityLevel,
                    cancellationToken
                );

                if (sessionResult.IsFailure)
                {
                    return sessionResult.Error;
                }

                var session = sessionResult.Value;

                // Success - reset attempt counter
                tracker.Reset();
                
                _logger.LogInformation(
                    "Secure channel established successfully for card {CardId}. Attempt counter reset.",
                    cardId
                );

                return Result.Success<SecureChannelSession, SmartCardError>(session);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("EXTERNAL AUTHENTICATE failed"))
            {
                // Authentication failed - increment counter
                tracker.IncrementFailedAttempts();
                
                _logger.LogWarning(
                    "Authentication failed for card {CardId}. Failed attempts: {FailedAttempts}/{MaxAttempts}. " +
                    "Error: {ErrorMessage}",
                    cardId,
                    tracker.FailedAttempts,
                    _maxAttempts,
                    ex.Message
                );

                if (tracker.FailedAttempts >= _maxAttempts)
                {
                    _logger.LogError(
                        "Maximum authentication attempts reached for card {CardId}. " +
                        "Further attempts blocked to prevent card lockout.",
                        cardId
                    );
                }

                return Result.Failure<SecureChannelSession, SmartCardError>(
                    SmartCardError.AuthenticationFailed(
                        $"Authentication failed ({tracker.FailedAttempts}/{_maxAttempts}): {ex.Message}"
                    )
                );
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("INITIALIZE UPDATE failed"))
            {
                // INITIALIZE UPDATE failed - this might not be a key issue, so don't increment counter
                _logger.LogWarning(
                    "INITIALIZE UPDATE failed for card {CardId}: {ErrorMessage}",
                    cardId,
                    ex.Message
                );

                return Result.Failure<SecureChannelSession, SmartCardError>(
                    SmartCardError.InitializationFailed(ex.Message)
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during secure channel establishment for card {CardId}", cardId);
                
                return Result.Failure<SecureChannelSession, SmartCardError>(
                    SmartCardError.UnexpectedError($"Secure channel establishment failed: {ex.Message}")
                );
            }
        }

        /// <inheritdoc />
        public async Task<Result<SecureChannelSession, SmartCardError>> EstablishAutoDetectAsync(
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

            var cardId = await GetCardIdentifierAsync(channel, transport, cancellationToken);
            var tracker = _attemptTrackers.GetOrAdd(cardId, _ => new AttemptTracker());

            if (tracker.FailedAttempts >= _maxAttempts)
            {
                _logger.LogError(
                    "Auto-detect authentication blocked: {FailedAttempts} failed attempts for card {CardId}",
                    tracker.FailedAttempts,
                    cardId
                );

                return Result.Failure<SecureChannelSession, SmartCardError>(
                    SmartCardError.AuthenticationBlocked(
                        $"Too many failed attempts ({tracker.FailedAttempts}/{_maxAttempts}). " +
                        "Card protection activated."
                    )
                );
            }

            try
            {
                var sessionResult = await _innerManager.EstablishAutoDetectAsync(
                    channel,
                    transport,
                    keySet,
                    securityLevel,
                    cancellationToken
                );

                if (sessionResult.IsFailure)
                {
                    return sessionResult.Error;
                }

                var session = sessionResult.Value;
                tracker.Reset();
                return Result.Success<SecureChannelSession, SmartCardError>(session);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("EXTERNAL AUTHENTICATE failed"))
            {
                tracker.IncrementFailedAttempts();
                
                return Result.Failure<SecureChannelSession, SmartCardError>(
                    SmartCardError.AuthenticationFailed(
                        $"Auto-detect authentication failed ({tracker.FailedAttempts}/{_maxAttempts}): {ex.Message}"
                    )
                );
            }
            catch (Exception ex)
            {
                return Result.Failure<SecureChannelSession, SmartCardError>(
                    SmartCardError.UnexpectedError($"Auto-detect authentication failed: {ex.Message}")
                );
            }
        }

        /// <summary>
        /// Resets the failed attempt counter for a specific card.
        /// Use this when you know the card is in a good state (e.g., after successful GP Pro reset).
        /// </summary>
        /// <param name="channel">The card channel.</param>
        /// <param name="transport">The transport.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        public async Task ResetAttemptsAsync(
            ICardChannel channel,
            IApduTransport transport,
            CancellationToken cancellationToken = default
        )
        {
            var cardId = await GetCardIdentifierAsync(channel, transport, cancellationToken);
            
            if (_attemptTrackers.TryGetValue(cardId, out var tracker))
            {
                var previousAttempts = tracker.FailedAttempts;
                tracker.Reset();
                
                _logger.LogInformation(
                    "Manually reset attempt counter for card {CardId}. Previous failed attempts: {PreviousAttempts}",
                    cardId,
                    previousAttempts
                );
            }
        }

        /// <summary>
        /// Gets the current failed attempt count for a card.
        /// </summary>
        /// <param name="channel">The card channel.</param>
        /// <param name="transport">The transport.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The number of failed attempts.</returns>
        public async Task<int> GetFailedAttemptsAsync(
            ICardChannel channel,
            IApduTransport transport,
            CancellationToken cancellationToken = default
        )
        {
            var cardId = await GetCardIdentifierAsync(channel, transport, cancellationToken);
            return _attemptTrackers.TryGetValue(cardId, out var tracker) ? tracker.FailedAttempts : 0;
        }

        /// <summary>
        /// Generates a unique identifier for the card to track attempts.
        /// Uses channel hash as identifier since ATR is not accessible.
        /// </summary>
        private Task<string> GetCardIdentifierAsync(
            ICardChannel channel,
            IApduTransport transport,
            CancellationToken cancellationToken
        )
        {
            // Use channel hash as card identifier
            // In production, you might want to send a GET DATA command to get card identifier
            var cardId = $"Card_{channel.GetHashCode():X8}";
            return Task.FromResult(cardId);
        }

        /// <summary>
        /// Tracks authentication attempts for a specific card.
        /// </summary>
        private class AttemptTracker
        {
            private readonly object _lock = new();
            private int _failedAttempts;

            public int FailedAttempts
            {
                get
                {
                    lock (_lock)
                    {
                        return _failedAttempts;
                    }
                }
            }

            public void IncrementFailedAttempts()
            {
                lock (_lock)
                {
                    _failedAttempts++;
                }
            }

            public void Reset()
            {
                lock (_lock)
                {
                    _failedAttempts = 0;
                }
            }
        }
    }
}