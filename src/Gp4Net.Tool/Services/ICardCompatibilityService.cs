using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Service for checking card compatibility with operations to prevent damage or lockout.
/// Provides comprehensive safety checks for real card testing.
/// </summary>
[PublicAPI]
public interface ICardCompatibilityService
{
    /// <summary>
    /// Checks if a card is compatible with a specific operation using the given keyset.
    /// Prevents operations that could damage or lock the card.
    /// </summary>
    /// <param name="operation">The operation being attempted.</param>
    /// <param name="keySet">The keyset to be used.</param>
    /// <param name="channel">The card channel.</param>
    /// <param name="transport">The transport layer.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A result indicating compatibility and any warnings.</returns>
    Task<Result<CardCompatibilityResult, SmartCardError>> CheckCompatibilityAsync(
        CardOperation operation,
        IKeySet keySet,
        ICardChannel channel,
        IApduTransport transport,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Detects the card type based on ATR and CPLC data.
    /// </summary>
    /// <param name="channel">The card channel.</param>
    /// <param name="transport">The transport layer.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A result containing the detected card type.</returns>
    Task<Result<CardTypeInfo, SmartCardError>> DetectCardTypeAsync(
        ICardChannel channel,
        IApduTransport transport,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Gets the authentication attempt count for a card if available.
    /// </summary>
    /// <param name="channel">The card channel.</param>
    /// <param name="transport">The transport layer.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A result containing the current attempt count or null if unavailable.</returns>
    Task<Result<int?, SmartCardError>> GetAuthenticationAttemptCountAsync(
        ICardChannel channel,
        IApduTransport transport,
        CancellationToken cancellationToken = default
    );
}

/// <summary>
/// Represents the result of card compatibility checking.
/// </summary>
[PublicAPI]
public class CardCompatibilityResult
{
    /// <summary>
    /// Gets whether the operation is compatible and safe.
    /// </summary>
    public bool IsCompatible { get; }

    /// <summary>
    /// Gets whether the operation is safe (won't cause permanent damage).
    /// </summary>
    public bool IsSafe { get; }

    /// <summary>
    /// Gets the detected card type.
    /// </summary>
    public CardTypeInfo CardType { get; }

    /// <summary>
    /// Gets the compatibility message.
    /// </summary>
    public string Message { get; }

    /// <summary>
    /// Gets warnings about the operation.
    /// </summary>
    public string[] Warnings { get; }

    /// <summary>
    /// Gets recommendations for safe operation.
    /// </summary>
    public string[] Recommendations { get; }

    /// <summary>
    /// Initializes a new instance of CardCompatibilityResult.
    /// </summary>
    public CardCompatibilityResult(
        bool isCompatible,
        bool isSafe,
        CardTypeInfo cardType,
        string message,
        string[] warnings,
        string[] recommendations
    )
    {
        IsCompatible = isCompatible;
        IsSafe = isSafe;
        CardType = cardType;
        Message = message;
        Warnings = warnings ?? [];
        Recommendations = recommendations ?? [];
    }
}

/// <summary>
/// Represents detected card type information.
/// </summary>
[PublicAPI]
public class CardTypeInfo
{
    /// <summary>
    /// Gets the card manufacturer.
    /// </summary>
    public string Manufacturer { get; }

    /// <summary>
    /// Gets the card family or series.
    /// </summary>
    public string Family { get; }

    /// <summary>
    /// Gets the specific card model if detected.
    /// </summary>
    public string Model { get; }

    /// <summary>
    /// Gets whether this is a production card.
    /// </summary>
    public bool IsProduction { get; }

    /// <summary>
    /// Gets the maximum authentication attempts before lockout.
    /// </summary>
    public int? MaxAuthenticationAttempts { get; }

    /// <summary>
    /// Gets supported secure channel protocols.
    /// </summary>
    public string[] SupportedProtocols { get; }

    /// <summary>
    /// Gets known limitations or risks for this card type.
    /// </summary>
    public string[] KnownLimitations { get; }

    /// <summary>
    /// Initializes a new instance of CardTypeInfo.
    /// </summary>
    public CardTypeInfo(
        string manufacturer,
        string family,
        string model,
        bool isProduction,
        int? maxAuthenticationAttempts,
        string[] supportedProtocols,
        string[] knownLimitations
    )
    {
        Manufacturer = manufacturer;
        Family = family;
        Model = model;
        IsProduction = isProduction;
        MaxAuthenticationAttempts = maxAuthenticationAttempts;
        SupportedProtocols = supportedProtocols ?? [];
        KnownLimitations = knownLimitations ?? [];
    }

    /// <summary>
    /// Gets a descriptive name for this card type.
    /// </summary>
    public string DisplayName
    {
        get
        {
            return Model != null ? $"{Manufacturer} {Family} {Model}" : $"{Manufacturer} {Family}";
        }
    }
}

/// <summary>
/// Represents the type of operation being checked for compatibility.
/// </summary>
[PublicAPI]
public enum CardOperation
{
    /// <summary>
    /// Authentication operation (secure channel establishment).
    /// </summary>
    Authentication,

    /// <summary>
    /// Key installation or replacement.
    /// </summary>
    KeyInstallation,

    /// <summary>
    /// Application installation.
    /// </summary>
    ApplicationInstallation,

    /// <summary>
    /// Application deletion.
    /// </summary>
    ApplicationDeletion,

    /// <summary>
    /// Card personalization.
    /// </summary>
    Personalization,

    /// <summary>
    /// Read-only operations (safe).
    /// </summary>
    ReadOnly
}