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

namespace Gp4Net.Domain.Protocol;

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
    /// Private constructor for successful creation.
    /// </summary>
    private SafeAuthenticationManager(
        ISecureChannelManager innerManager,
        ILogger<SafeAuthenticationManager> logger,
        int maxAttempts)
    {
        _innerManager = innerManager;
        _logger = logger;
        _maxAttempts = maxAttempts;
    }

    /// <summary>
    /// Creates a SafeAuthenticationManager with functional validation.
    /// </summary>
    /// <param name="innerManager">The underlying secure channel manager.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="maxAttempts">Maximum attempts before blocking (default: 3).</param>
    /// <returns>A result containing the manager or an error.</returns>
    public static Result<SafeAuthenticationManager, SmartCardError> Create(
        ISecureChannelManager innerManager,
        ILogger<SafeAuthenticationManager> logger,
        int maxAttempts = DefaultMaxAttempts)
    {
        if (innerManager == null)
        {
            return Result.Failure<SafeAuthenticationManager, SmartCardError>(
                SmartCardError.InvalidArgument("Inner manager cannot be null"));
        }

        if (logger == null)
        {
            return Result.Failure<SafeAuthenticationManager, SmartCardError>(
                SmartCardError.InvalidArgument("Logger cannot be null"));
        }

        if (maxAttempts < 1)
        {
            return Result.Failure<SafeAuthenticationManager, SmartCardError>(
                SmartCardError.InvalidArgument("Maximum attempts must be at least 1"));
        }

        return Result.Success<SafeAuthenticationManager, SmartCardError>(
            new SafeAuthenticationManager(innerManager, logger, maxAttempts));
    }

    /// <inheritdoc />
    public async Task<Result<Security.SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        ICardChannel channel,
        IApduTransport transport,
        IKeySet keySet,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken = default
    )
    {
        if (channel is null)
            return Result.Failure<Security.SecureChannelState, SmartCardError>(
                SmartCardError.InvalidArgument("Channel cannot be null"));
        
        if (transport is null)
            return Result.Failure<Security.SecureChannelState, SmartCardError>(
                SmartCardError.InvalidArgument("Transport cannot be null"));
        
        if (keySet is null)
            return Result.Failure<Security.SecureChannelState, SmartCardError>(
                SmartCardError.InvalidArgument("Key set cannot be null"));

        // Generate a card identifier for attempt tracking
        var cardId = await GetCardIdentifierAsync(channel, transport, cancellationToken);
        var tracker = _attemptTrackers.GetOrAdd(cardId, _ => new AttemptTracker(0));

        // Check if we've exceeded the maximum attempts
        if (tracker.FailedAttempts >= _maxAttempts)
        {
            _logger.LogError(
                "Authentication blocked: {FailedAttempts} failed attempts for card {CardId}. " +
                "Card may be locked. Manual reset required.",
                tracker.FailedAttempts,
                cardId
            );

            return Result.Failure<Security.SecureChannelState, SmartCardError>(
                SmartCardError.AuthenticationBlocked(
                    $"Too many failed attempts ({tracker.FailedAttempts}/{_maxAttempts}). " +
                    "Card protection activated to prevent lockout."
                )
            );
        }

        return await AttemptSecureChannelEstablishmentAsync(
            channel, transport, keySet, securityLevel, cancellationToken, cardId, tracker);
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
        if (channel is null)
            return Result.Failure<Security.SecureChannelState, SmartCardError>(
                SmartCardError.InvalidArgument("Channel cannot be null"));
        
        if (transport is null)
            return Result.Failure<Security.SecureChannelState, SmartCardError>(
                SmartCardError.InvalidArgument("Transport cannot be null"));
        
        if (keySet is null)
            return Result.Failure<Security.SecureChannelState, SmartCardError>(
                SmartCardError.InvalidArgument("Key set cannot be null"));

        var cardId = await GetCardIdentifierAsync(channel, transport, cancellationToken);
        var tracker = _attemptTrackers.GetOrAdd(cardId, _ => new AttemptTracker(0));

        if (tracker.FailedAttempts >= _maxAttempts)
        {
            _logger.LogError(
                "Auto-detect authentication blocked: {FailedAttempts} failed attempts for card {CardId}",
                tracker.FailedAttempts,
                cardId
            );

            return Result.Failure<Security.SecureChannelState, SmartCardError>(
                SmartCardError.AuthenticationBlocked(
                    $"Too many failed attempts ({tracker.FailedAttempts}/{_maxAttempts}). " +
                    "Card protection activated."
                )
            );
        }

        return await AttemptAutoDetectEstablishmentAsync(
            channel, transport, keySet, securityLevel, cancellationToken, cardId, tracker);
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
    private static Task<string> GetCardIdentifierAsync(
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

    private async Task<Result<Security.SecureChannelState, SmartCardError>> AttemptSecureChannelEstablishmentAsync(
        ICardChannel channel,
        IApduTransport transport, 
        IKeySet keySet,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken,
        string cardId,
        AttemptTracker tracker)
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

        return sessionResult.IsSuccess
            ? HandleSuccessfulAuthentication(sessionResult.Value, cardId, tracker)
            : HandleFailedAuthentication(sessionResult, cardId, tracker);
    }

    private async Task<Result<Security.SecureChannelState, SmartCardError>> AttemptAutoDetectEstablishmentAsync(
        ICardChannel channel,
        IApduTransport transport,
        IKeySet keySet,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken,
        string cardId,
        AttemptTracker tracker)
    {
        var sessionResult = await _innerManager.EstablishAutoDetectAsync(
            channel,
            transport,
            keySet,
            securityLevel,
            cancellationToken
        );

        return sessionResult.IsSuccess
            ? HandleSuccessfulAutoDetect(sessionResult.Value, tracker)
            : HandleFailedAutoDetect(sessionResult, cardId, tracker);
    }

    private Result<Security.SecureChannelState, SmartCardError> HandleSuccessfulAuthentication(
        Security.SecureChannelState session,
        string cardId,
        AttemptTracker tracker)
    {
        // Success - reset attempt counter
        tracker.Reset();
            
        _logger.LogInformation(
            "Secure channel established successfully for card {CardId}. Attempt counter reset.",
            cardId
        );

        return Result.Success<Security.SecureChannelState, SmartCardError>(session);
    }

    private Result<Security.SecureChannelState, SmartCardError> HandleFailedAuthentication(
        Result<Security.SecureChannelState, SmartCardError> sessionResult,
        string cardId,
        AttemptTracker tracker)
    {
        // Check if this is an authentication failure that should increment the counter
        var errorMessage = sessionResult.Error.Message;
        
        if (IsExternalAuthenticateFailure(errorMessage))
        {
            // Authentication failed - increment counter
            tracker.IncrementFailedAttempts();
                
            _logger.LogWarning(
                "Authentication failed for card {CardId}. Failed attempts: {FailedAttempts}/{MaxAttempts}. " +
                "Error: {ErrorMessage}",
                cardId,
                tracker.FailedAttempts,
                _maxAttempts,
                errorMessage
            );

            if (tracker.FailedAttempts >= _maxAttempts)
            {
                _logger.LogError(
                    "Maximum authentication attempts reached for card {CardId}. " +
                    "Further attempts blocked to prevent card lockout.",
                    cardId
                );
            }

            return SmartCardError.AuthenticationFailed(
                $"Authentication failed ({tracker.FailedAttempts}/{_maxAttempts}): {errorMessage}"
            );
        }
        
        if (IsInitializeUpdateFailure(errorMessage))
        {
            // INITIALIZE UPDATE failed - this might not be a key issue, so don't increment counter
            _logger.LogWarning(
                "INITIALIZE UPDATE failed for card {CardId}: {ErrorMessage}",
                cardId,
                errorMessage
            );

            return SmartCardError.InitializationFailed(errorMessage);
        }

        // Other failures - don't increment counter
        _logger.LogError("Unexpected error during secure channel establishment for card {CardId}: {Error}", cardId, errorMessage);
        return SmartCardError.UnexpectedError($"Secure channel establishment failed: {errorMessage}");
    }

    private Result<Security.SecureChannelState, SmartCardError> HandleSuccessfulAutoDetect(
        Security.SecureChannelState session,
        AttemptTracker tracker)
    {
        tracker.Reset();
        return Result.Success<Security.SecureChannelState, SmartCardError>(session);
    }

    private Result<Security.SecureChannelState, SmartCardError> HandleFailedAutoDetect(
        Result<Security.SecureChannelState, SmartCardError> sessionResult,
        string cardId,
        AttemptTracker tracker)
    {
        var errorMessage = sessionResult.Error.Message;
        
        if (IsExternalAuthenticateFailure(errorMessage))
        {
            tracker.IncrementFailedAttempts();
                
            return SmartCardError.AuthenticationFailed(
                $"Auto-detect authentication failed ({tracker.FailedAttempts}/{_maxAttempts}): {errorMessage}"
            );
        }

        return SmartCardError.UnexpectedError($"Auto-detect authentication failed: {errorMessage}");
    }

    private static bool IsExternalAuthenticateFailure(string errorMessage) =>
        errorMessage?.Contains("EXTERNAL AUTHENTICATE failed") == true;

    private static bool IsInitializeUpdateFailure(string errorMessage) =>
        errorMessage?.Contains("INITIALIZE UPDATE failed") == true;

    /// <summary>
    /// Immutable record for tracking authentication attempts for a specific card.
    /// </summary>
    private record AttemptTracker(int FailedAttempts)
    {
        public static AttemptTracker Empty => new(0);

        public AttemptTracker IncrementFailedAttempts() => this with { FailedAttempts = FailedAttempts + 1 };

        public AttemptTracker Reset() => Empty;
    }
}