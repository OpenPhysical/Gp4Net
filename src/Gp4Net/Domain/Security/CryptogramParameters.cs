using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;

namespace Gp4Net.Domain.Security;


/// <summary>
/// Protocol-specific parameters for SCP02 cryptogram calculations.
/// Makes invalid states unrepresentable - sequence counter is always present and validated.
/// Card challenge is always 6 bytes as required by SCP02 specification.
/// All byte arrays are guaranteed to be the correct length through validated construction.
/// </summary>
public sealed record Scp02CryptogramParameters(
    byte[] HostChallenge,        // Always 8 bytes, validated at construction
    byte[] CardChallenge,        // Always 6 bytes, validated at construction  
    byte[] SequenceCounter,      // Always 2 bytes, validated at construction
    Scp02KeySet Keys
)
{
    /// <summary>
    /// Creates SCP02 cryptogram parameters with validation.
    /// Per GP Card Specification v2.3.1 Section E.4.2, SCP02 cryptograms use S-ENC session key.
    /// </summary>
    /// <param name="hostChallenge">8-byte host challenge.</param>
    /// <param name="cardChallenge">6-byte card challenge (random part).</param>
    /// <param name="sequenceCounter">2-byte sequence counter.</param>
    /// <param name="keys">SCP02 key set containing S-ENC key for cryptogram calculation.</param>
    /// <returns>Validated SCP02 parameters or an error.</returns>
    public static Result<Scp02CryptogramParameters, SmartCardError> Create(
        byte[] hostChallenge,
        byte[] cardChallenge,
        byte[] sequenceCounter,
        Maybe<Scp02KeySet> keys) =>
        keys.ToResult(SmartCardError.InvalidArgument("SCP02 key set cannot be empty"))
            .Bind(keySet => ValidateHostChallenge(hostChallenge)
                .Bind(validHost => ValidateScp02CardChallenge(cardChallenge)
                    .Bind(validCard => ValidateSequenceCounter(sequenceCounter)
                        .Map(validSeq => new Scp02CryptogramParameters(validHost, validCard, validSeq, keySet)))));

    private static Result<byte[], SmartCardError> ValidateHostChallenge(Maybe<byte[]> hostChallenge) =>
        hostChallenge.ToResult(SmartCardError.InvalidArgument("Host challenge cannot be empty"))
            .Bind(bytes => bytes.Length == 8
                ? Result.Success<byte[], SmartCardError>((byte[])bytes.Clone())
                : Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument($"Host challenge must be 8 bytes, got {bytes.Length}")));

    private static Result<byte[], SmartCardError> ValidateHostChallenge(byte[] hostChallenge) =>
        ValidateHostChallenge(Maybe<byte[]>.From(hostChallenge));

    private static Result<byte[], SmartCardError> ValidateScp02CardChallenge(Maybe<byte[]> cardChallenge) =>
        cardChallenge.ToResult(SmartCardError.InvalidArgument("SCP02 card challenge cannot be empty"))
            .Bind(bytes => bytes.Length == 6
                ? Result.Success<byte[], SmartCardError>((byte[])bytes.Clone())
                : Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument($"SCP02 card challenge must be 6 bytes, got {bytes.Length}")));

    private static Result<byte[], SmartCardError> ValidateScp02CardChallenge(byte[] cardChallenge) =>
        ValidateScp02CardChallenge(Maybe<byte[]>.From(cardChallenge));

    private static Result<byte[], SmartCardError> ValidateSequenceCounter(Maybe<byte[]> sequenceCounter) =>
        sequenceCounter.ToResult(SmartCardError.InvalidArgument("Sequence counter cannot be empty"))
            .Bind(bytes => bytes.Length == 2
                ? Result.Success<byte[], SmartCardError>((byte[])bytes.Clone())
                : Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument($"Sequence counter must be 2 bytes, got {bytes.Length}")));

    private static Result<byte[], SmartCardError> ValidateSequenceCounter(byte[] sequenceCounter) =>
        ValidateSequenceCounter(Maybe<byte[]>.From(sequenceCounter));
}

/// <summary>
/// Protocol-specific parameters for SCP03 cryptogram calculations.
/// Makes invalid states unrepresentable - no sequence counter can be passed.
/// Card challenge is always 8 bytes as required by SCP03 specification.
/// All byte arrays are guaranteed to be the correct length through validated construction.
/// </summary>
public sealed record Scp03CryptogramParameters(
    byte[] HostChallenge,        // Always 8 bytes, validated at construction
    byte[] CardChallenge,        // Always 8 bytes, validated at construction
    Scp03KeySet Keys
)
{
    /// <summary>
    /// Creates SCP03 cryptogram parameters with validation.
    /// Per GP SCP03 v1.1.1 Section 6.2.2.2, SCP03 cryptograms use S-MAC session key.
    /// </summary>
    /// <param name="hostChallenge">8-byte host challenge.</param>
    /// <param name="cardChallenge">8-byte card challenge.</param>
    /// <param name="keys">SCP03 key set containing S-MAC key for cryptogram calculation.</param>
    /// <returns>Validated SCP03 parameters or an error.</returns>
    public static Result<Scp03CryptogramParameters, SmartCardError> Create(
        byte[] hostChallenge,
        byte[] cardChallenge,
        Maybe<Scp03KeySet> keys) =>
        keys.ToResult(SmartCardError.InvalidArgument("SCP03 key set cannot be empty"))
            .Bind(keySet => ValidateHostChallenge(hostChallenge)
                .Bind(validHost => ValidateScp03CardChallenge(cardChallenge)
                    .Map(validCard => new Scp03CryptogramParameters(validHost, validCard, keySet))));

    private static Result<byte[], SmartCardError> ValidateHostChallenge(Maybe<byte[]> hostChallenge) =>
        hostChallenge.ToResult(SmartCardError.InvalidArgument("Host challenge cannot be empty"))
            .Bind(bytes => bytes.Length == 8
                ? Result.Success<byte[], SmartCardError>((byte[])bytes.Clone())
                : Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument($"Host challenge must be 8 bytes, got {bytes.Length}")));

    private static Result<byte[], SmartCardError> ValidateHostChallenge(byte[] hostChallenge) =>
        ValidateHostChallenge(Maybe<byte[]>.From(hostChallenge));

    private static Result<byte[], SmartCardError> ValidateScp03CardChallenge(Maybe<byte[]> cardChallenge) =>
        cardChallenge.ToResult(SmartCardError.InvalidArgument("SCP03 card challenge cannot be empty"))
            .Bind(bytes => bytes.Length == 8
                ? Result.Success<byte[], SmartCardError>((byte[])bytes.Clone())
                : Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidArgument($"SCP03 card challenge must be 8 bytes, got {bytes.Length}")));

    private static Result<byte[], SmartCardError> ValidateScp03CardChallenge(byte[] cardChallenge) =>
        ValidateScp03CardChallenge(Maybe<byte[]>.From(cardChallenge));
}

/// <summary>
/// Factory methods for creating cryptogram parameters with validation.
/// Provides convenient API while maintaining type safety.
/// </summary>
public static class CryptogramParameters
{
    /// <summary>
    /// Creates SCP02 cryptogram parameters with full validation.
    /// </summary>
    /// <param name="hostChallenge">8-byte host challenge.</param>
    /// <param name="cardChallenge">6-byte SCP02 card challenge.</param>
    /// <param name="sequenceCounter">2-byte sequence counter.</param>
    /// <param name="keys">SCP02 key set.</param>
    /// <returns>Validated SCP02 parameters or an error.</returns>
    public static Result<Scp02CryptogramParameters, SmartCardError> ForScp02(
        byte[] hostChallenge,
        byte[] cardChallenge,
        byte[] sequenceCounter,
        Scp02KeySet keys) =>
        Scp02CryptogramParameters.Create(hostChallenge, cardChallenge, sequenceCounter, Maybe<Scp02KeySet>.From(keys));

    /// <summary>
    /// Creates SCP03 cryptogram parameters with full validation.
    /// </summary>
    /// <param name="hostChallenge">8-byte host challenge.</param>
    /// <param name="cardChallenge">8-byte SCP03 card challenge.</param>
    /// <param name="keys">SCP03 key set.</param>
    /// <returns>Validated SCP03 parameters or an error.</returns>
    public static Result<Scp03CryptogramParameters, SmartCardError> ForScp03(
        byte[] hostChallenge,
        byte[] cardChallenge,
        Scp03KeySet keys) =>
        Scp03CryptogramParameters.Create(hostChallenge, cardChallenge, Maybe<Scp03KeySet>.From(keys));
}