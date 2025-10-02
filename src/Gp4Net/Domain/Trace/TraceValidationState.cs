using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using static Gp4Net.Cryptography.CryptoService;

namespace Gp4Net.Domain.Trace;

/// <summary>
/// Holds master and derived key material for trace validation.
/// </summary>
[PublicAPI]
public record TraceKeyMaterial(
    IKeySet MasterKeys,
    IKeySet CurrentKeys,
    Maybe<KeyDiversificationSpec> Diversification,
    Maybe<byte[]> LastDiversificationData
)
{
    public TraceKeyMaterial WithCurrentKeys(IKeySet newKeys, byte[] appliedKdd)
    {
        var cloned = (byte[])appliedKdd.Clone();
        return this with
        {
            CurrentKeys = newKeys,
            LastDiversificationData = Maybe<byte[]>.From(cloned)
        };
    }
}

/// <summary>
/// Immutable state for trace validation, tracking session keys and cryptographic state.
/// </summary>
[PublicAPI]
public record TraceValidationState(
    TraceKeyMaterial KeyMaterial,
    Maybe<SessionKeys> SessionKeys,
    Maybe<byte[]> CommandIcv,
    Maybe<byte[]> ResponseIcv,
    byte[] SequenceCounter,
    byte[] CardChallenge,
    byte[] HostChallenge,
    ScpVersion ScpVersion,
    ScpImplementation ScpImplementation,
    byte SecurityLevel,
    ImmutableList<ValidationResult> Results,
    Maybe<MacChainingState> MacChainingState,
    uint EncryptionCounter
)
{
    /// <summary>
    /// Creates an initial validation state with base keys.
    /// </summary>
    /// <param name="baseKeys">The master keys for validation.</param>
    /// <param name="diversification">Optional diversification scheme.</param>
    /// <returns>A new validation state initialized with the base keys.</returns>
    public static TraceValidationState Create(
        IKeySet baseKeys,
        Maybe<KeyDiversificationSpec> diversification = default
    ) =>
        new(
            new TraceKeyMaterial(baseKeys, baseKeys, diversification, Maybe<byte[]>.None),
            Maybe<SessionKeys>.None,
            Maybe<byte[]>.None,
            Maybe<byte[]>.None,
            [0x00, 0x00],
            [],
            [],
            ScpVersion.Scp02,
            ScpImplementation.Scp02I00,
            0x00,
            ImmutableList<ValidationResult>.Empty,
            Maybe<MacChainingState>.None,
            0
        );

    public TraceValidationState WithSessionKeys(SessionKeys keys) =>
        this with
        {
            SessionKeys = Maybe<SessionKeys>.From(keys)
        };

    public TraceValidationState WithCommandIcv(byte[] icv) =>
        this with
        {
            CommandIcv = Maybe<byte[]>.From(icv)
        };

    public TraceValidationState WithResponseIcv(byte[] icv) =>
        this with
        {
            ResponseIcv = Maybe<byte[]>.From(icv)
        };

    public TraceValidationState WithSequenceCounter(byte[] counter) =>
        this with
        {
            SequenceCounter = (byte[])counter.Clone()
        };

    public TraceValidationState WithScpVersion(ScpVersion version) =>
        this with
        {
            ScpVersion = version
        };

    public TraceValidationState WithScpImplementation(ScpImplementation implementation) =>
        this with
        {
            ScpImplementation = implementation
        };

    public TraceValidationState WithSecurityLevel(byte level) =>
        this with
        {
            SecurityLevel = level
        };

    public TraceValidationState WithCardChallenge(byte[] challenge) =>
        this with
        {
            CardChallenge = (byte[])challenge.Clone()
        };

    public TraceValidationState WithHostChallenge(byte[] challenge) =>
        this with
        {
            HostChallenge = (byte[])challenge.Clone()
        };

    public TraceValidationState AddResult(ValidationResult result) =>
        this with
        {
            Results = Results.Add(result)
        };

    public TraceValidationState WithEncryptionCounter(uint counter) =>
        this with
        {
            EncryptionCounter = counter
        };

    public TraceValidationState WithKeyMaterial(TraceKeyMaterial material) =>
        this with
        {
            KeyMaterial = material
        };
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
    public static ValidationResult Success(
        int exchangeIndex,
        string validationType,
        string details
    ) => new(exchangeIndex, validationType, true, details, Maybe<string>.None);

    public static ValidationResult Failure(
        int exchangeIndex,
        string validationType,
        string details,
        string error
    ) => new(exchangeIndex, validationType, false, details, Maybe<string>.From(error));
}
