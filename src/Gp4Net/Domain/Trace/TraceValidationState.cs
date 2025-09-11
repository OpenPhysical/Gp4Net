using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using static Gp4Net.Cryptography.CryptoService;

namespace Gp4Net.Domain.Trace;

/// <summary>
/// Immutable state for trace validation, tracking session keys and cryptographic state.
/// </summary>
[PublicAPI]
public record TraceValidationState(
    IKeySet BaseKeys,
    Maybe<SessionKeys> SessionKeys,
    Maybe<byte[]> CommandIcv,
    Maybe<byte[]> ResponseIcv,
    byte[] SequenceCounter,
    byte[] CardChallenge,
    byte[] HostChallenge,
    ScpVersion ScpVersion,
    ImmutableList<ValidationResult> Results
)
{
    /// <summary>
    /// Creates an initial validation state with base keys.
    /// </summary>
    /// <param name="baseKeys">The master keys for validation.</param>
    /// <returns>A new validation state initialized with the base keys.</returns>
    public static TraceValidationState Create(IKeySet baseKeys) =>
        new(
            baseKeys,
            Maybe<SessionKeys>.None,
            Maybe<byte[]>.None,
            Maybe<byte[]>.None,
            new byte[2] { 0x00, 0x00 },
            new byte[0],
            new byte[0],
            ScpVersion.Scp02,
            ImmutableList<ValidationResult>.Empty
        );

    /// <summary>
    /// Updates the state with derived session keys.
    /// </summary>
    /// <param name="keys">The session keys to set.</param>
    /// <returns>A new state with the session keys.</returns>
    public TraceValidationState WithSessionKeys(SessionKeys keys) =>
        this with { SessionKeys = Maybe<SessionKeys>.From(keys) };

    /// <summary>
    /// Updates the command ICV for MAC chaining.
    /// </summary>
    /// <param name="icv">The new command ICV.</param>
    /// <returns>A new state with the updated command ICV.</returns>
    public TraceValidationState WithCommandIcv(byte[] icv) =>
        this with { CommandIcv = Maybe<byte[]>.From(icv) };

    /// <summary>
    /// Updates the response ICV for R-MAC verification.
    /// </summary>
    /// <param name="icv">The new response ICV.</param>
    /// <returns>A new state with the updated response ICV.</returns>
    public TraceValidationState WithResponseIcv(byte[] icv) =>
        this with { ResponseIcv = Maybe<byte[]>.From(icv) };

    /// <summary>
    /// Updates the sequence counter.
    /// </summary>
    /// <param name="counter">The new sequence counter.</param>
    /// <returns>A new state with the updated sequence counter.</returns>
    public TraceValidationState WithSequenceCounter(byte[] counter) =>
        this with { SequenceCounter = (byte[])counter.Clone() };

    /// <summary>
    /// Updates the SCP version.
    /// </summary>
    /// <param name="version">The SCP version.</param>
    /// <returns>A new state with the updated version.</returns>
    public TraceValidationState WithScpVersion(ScpVersion version) =>
        this with { ScpVersion = version };

    /// <summary>
    /// Updates the card challenge.
    /// </summary>
    /// <param name="challenge">The card challenge.</param>
    /// <returns>A new state with the updated card challenge.</returns>
    public TraceValidationState WithCardChallenge(byte[] challenge) =>
        this with { CardChallenge = (byte[])challenge.Clone() };

    /// <summary>
    /// Updates the host challenge.
    /// </summary>
    /// <param name="challenge">The host challenge.</param>
    /// <returns>A new state with the updated host challenge.</returns>
    public TraceValidationState WithHostChallenge(byte[] challenge) =>
        this with { HostChallenge = (byte[])challenge.Clone() };

    /// <summary>
    /// Adds a validation result to the state.
    /// </summary>
    /// <param name="result">The validation result to add.</param>
    /// <returns>A new state with the added result.</returns>
    public TraceValidationState AddResult(ValidationResult result) =>
        this with { Results = Results.Add(result) };
}

/// <summary>
/// Represents the result of validating a single exchange.
/// </summary>
[PublicAPI]
public record ValidationResult(
    int ExchangeIndex,
    string ValidationType,
    bool IsValid,
    string Details,
    Maybe<string> Error = default
)
{
    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    public static ValidationResult Success(int exchangeIndex, string validationType, string details) =>
        new(exchangeIndex, validationType, true, details, Maybe<string>.None);

    /// <summary>
    /// Creates a failed validation result.
    /// </summary>
    public static ValidationResult Failure(int exchangeIndex, string validationType, string details, string error) =>
        new(exchangeIndex, validationType, false, details, Maybe<string>.From(error));
}