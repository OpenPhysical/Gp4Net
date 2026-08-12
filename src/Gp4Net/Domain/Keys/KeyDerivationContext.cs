using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using JetBrains.Annotations;
using static Gp4Net.Cryptography.CryptoOperations;

namespace Gp4Net.Domain.Keys;

/// <summary>
/// Immutable context for key derivation operations.
/// Supports both SCP02 and SCP03 protocols with appropriate validation.
/// Uses Maybe&lt;T&gt; for optional values to avoid nulls.
/// </summary>
/// <param name="Protocol">The secure channel protocol version (SCP02 or SCP03).</param>
/// <param name="KeySet">The static key set for derivation.</param>
/// <param name="HostChallenge">The host challenge (8 bytes).</param>
/// <param name="CardChallenge">The card challenge (6 bytes for SCP02, 8 bytes for SCP03).</param>
/// <param name="SequenceCounter">The sequence counter (required for SCP02, optional for SCP03).</param>
/// <param name="Implementation">The SCP implementation details (optional).</param>
[PublicAPI]
public sealed record KeyDerivationContext(
    ScpVersion Protocol,
    IKeySet KeySet,
    byte[] HostChallenge,
    byte[] CardChallenge,
    Maybe<byte[]> SequenceCounter,
    Maybe<ScpImplementation> Implementation
)
{
    /// <summary>
    /// Gets the base keyset as object to match interface.
    /// </summary>
    public object BaseKeySet => KeySet;

    /// <summary>
    /// Creates a key derivation context for SCP02 with validation.
    /// Per GlobalPlatform Card Specification v2.3.1 Section E.4.2
    /// </summary>
    /// <param name="keySet">The static key set (must be Scp02KeySet).</param>
    /// <param name="hostChallenge">The host challenge (must be 8 bytes).</param>
    /// <param name="cardChallenge">The card challenge (must be 6 bytes for SCP02).</param>
    /// <param name="sequenceCounter">The sequence counter (must be at least 2 bytes).</param>
    /// <param name="implementation">The SCP02 implementation option. Defaults to SCP02 i=15.</param>
    /// <returns>A result containing the context or an error.</returns>
    public static Result<KeyDerivationContext, SmartCardError> CreateForScp02(
        IKeySet keySet,
        byte[] hostChallenge,
        byte[] cardChallenge,
        byte[] sequenceCounter,
        ScpImplementation implementation = ScpImplementation.Scp02I15
    )
    {
        // Validate key set type
        if (keySet is not Scp02KeySet)
        {
            return Result.Failure<KeyDerivationContext, SmartCardError>(
                SmartCardError.InvalidArgument("SCP02 requires Scp02KeySet")
            );
        }

        // Validate host challenge (8 bytes for all protocols)
        if (hostChallenge?.Length != 8)
        {
            return Result.Failure<KeyDerivationContext, SmartCardError>(
                new InvalidLengthError("hostChallenge", 8, hostChallenge?.Length ?? 0)
            );
        }

        // Validate card challenge (6 bytes for SCP02)
        if (cardChallenge.Length != 6)
        {
            return Result.Failure<KeyDerivationContext, SmartCardError>(
                new InvalidLengthError("cardChallenge", 6, cardChallenge.Length)
            );
        }

        // Validate sequence counter (required for SCP02, must be exactly 2 bytes)
        if (sequenceCounter.Length != 2)
        {
            return Result.Failure<KeyDerivationContext, SmartCardError>(
                new InvalidLengthError("sequenceCounter", 2, sequenceCounter.Length)
            );
        }

        // Implementation parameter is provided - no validation needed since
        // the method name explicitly indicates this is for SCP02

        return Result.Success<KeyDerivationContext, SmartCardError>(
            new KeyDerivationContext(
                ScpVersion.Scp02,
                keySet,
                CloneArray(hostChallenge),
                CloneArray(cardChallenge),
                Maybe<byte[]>.From(CloneArray(sequenceCounter)),
                Maybe<ScpImplementation>.From(implementation)
            )
        );
    }

    /// <summary>
    /// Creates a key derivation context for SCP03 with validation.
    /// Per GlobalPlatform Card Specification v2.3.1 Amendment D
    /// </summary>
    /// <param name="keySet">The static key set (must be Scp03KeySet).</param>
    /// <param name="hostChallenge">The host challenge (must be 8 bytes).</param>
    /// <param name="cardChallenge">The card challenge (must be 8 bytes for SCP03).</param>
    /// <param name="implementation">The SCP03 implementation option. Defaults to SCP03 i=70.</param>
    /// <returns>A result containing the context or an error.</returns>
    public static Result<KeyDerivationContext, SmartCardError> CreateForScp03(
        IKeySet keySet,
        byte[] hostChallenge,
        byte[] cardChallenge,
        Maybe<ScpImplementation> implementation = default
    )
    {
        // Validate key set type
        if (keySet is not Scp03KeySet)
        {
            return Result.Failure<KeyDerivationContext, SmartCardError>(
                SmartCardError.InvalidArgument("SCP03 requires Scp03KeySet")
            );
        }

        // Validate host challenge (8 bytes for all protocols)
        if (hostChallenge?.Length != 8)
        {
            return Result.Failure<KeyDerivationContext, SmartCardError>(
                new InvalidLengthError("hostChallenge", 8, hostChallenge?.Length ?? 0)
            );
        }

        // Validate card challenge (8 bytes for SCP03)
        if (cardChallenge.Length != 8)
        {
            return Result.Failure<KeyDerivationContext, SmartCardError>(
                SmartCardError.InvalidData(
                    $"SCP03 card challenge must be 8 bytes, got {cardChallenge.Length}"
                )
            );
        }

        // Use default implementation if not provided
        var actualImplementation = implementation.HasNoValue
            ? Maybe<ScpImplementation>.From(ScpImplementation.Scp03I70)
            : implementation;

        // Implementation parameter is provided - no validation needed since
        // the method name explicitly indicates this is for SCP03

        return Result.Success<KeyDerivationContext, SmartCardError>(
            new KeyDerivationContext(
                ScpVersion.Scp03,
                keySet,
                CloneArray(hostChallenge),
                CloneArray(cardChallenge),
                Maybe<byte[]>.None, // SCP03 doesn't use sequence counter
                actualImplementation
            )
        );
    }

    /// <summary>
    /// Creates a key derivation context with automatic protocol detection from the key set.
    /// </summary>
    /// <param name="keySet">The static key set.</param>
    /// <param name="hostChallenge">The host challenge (must be 8 bytes).</param>
    /// <param name="cardChallenge">The card challenge.</param>
    /// <param name="sequenceCounter">The sequence counter (required for SCP02).</param>
    /// <param name="implementation">The SCP implementation option.</param>
    /// <returns>A result containing the context or an error.</returns>
    public static Result<KeyDerivationContext, SmartCardError> Create(
        IKeySet keySet,
        byte[] hostChallenge,
        byte[] cardChallenge,
        Maybe<byte[]> sequenceCounter = default,
        Maybe<ScpImplementation> implementation = default
    )
    {
        return keySet switch
        {
            Scp02KeySet
                => sequenceCounter.HasValue
                    ? CreateForScp02(
                        keySet,
                        hostChallenge,
                        cardChallenge,
                        sequenceCounter.Value,
                        implementation.GetValueOrDefault(ScpImplementation.Scp02I15)
                    )
                    : Result.Failure<KeyDerivationContext, SmartCardError>(
                        SmartCardError.InvalidArgument("SCP02 requires sequence counter")
                    ),

            Scp03KeySet => CreateForScp03(keySet, hostChallenge, cardChallenge, implementation),

            _
                => Result.Failure<KeyDerivationContext, SmartCardError>(
                    SmartCardError.InvalidArgument(
                        $"Unsupported key set type: {keySet.GetType().Name}"
                    )
                ),
        };
    }

    /// <summary>
    /// Gets the implementation parameter value for use in derivation.
    /// </summary>
    /// <returns>The implementation parameter byte value.</returns>
    public byte GetImplementationParameter()
    {
        // For the new bitmap-based enum, the byte value IS the implementation parameter
        return (byte)
            Implementation.GetValueOrDefault(
                Protocol == ScpVersion.Scp02
                    ? ScpImplementation.Scp02I15
                    : ScpImplementation.Scp03I70
            );
    }

    /// <summary>
    /// Safely clones an array.
    /// </summary>
    private static byte[] CloneArray(byte[] array)
    {
        return (byte[])array.Clone();
    }
}
