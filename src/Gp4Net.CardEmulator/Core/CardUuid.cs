using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Core;

/// <summary>
/// Immutable value object representing a unique virtual card identifier.
/// Generated using cryptographically secure random number generation.
/// Used for card identity binding in persistence encryption and AEAD operations.
/// </summary>
[PublicAPI]
public readonly record struct CardUuid(Guid Value)
{
    /// <summary>
    /// Generates a new cryptographically secure card UUID.
    /// Uses the system's cryptographically secure random number generator.
    /// </summary>
    /// <returns>A new CardUuid or an error if generation fails.</returns>
    public static Result<CardUuid, SmartCardError> Generate()
    {
        return Result.Try(
            () =>
            {
                // Guid.NewGuid() uses cryptographically secure random generation
                var uuid = Guid.NewGuid();
                return new CardUuid(uuid);
            },
            ex => SmartCardError.CryptographicError($"Failed to generate card UUID: {ex.Message}")
        );
    }

    /// <summary>
    /// Creates a CardUuid from an existing Guid value with validation.
    /// Used when deserializing persisted card state.
    /// </summary>
    /// <param name="guid">The GUID value to wrap.</param>
    /// <returns>A new CardUuid or an error if the GUID is invalid.</returns>
    public static Result<CardUuid, SmartCardError> FromGuid(Guid guid)
    {
        if (guid == Guid.Empty)
        {
            return Result.Failure<CardUuid, SmartCardError>(
                SmartCardError.InvalidArgument("Card UUID cannot be empty")
            );
        }

        return Result.Success<CardUuid, SmartCardError>(new CardUuid(guid));
    }

    /// <summary>
    /// Creates a CardUuid from a byte array representation.
    /// Used when deserializing from CBOR or other binary formats.
    /// </summary>
    /// <param name="bytes">The byte array containing the UUID (must be 16 bytes).</param>
    /// <returns>A new CardUuid or an error if the byte array is invalid.</returns>
    public static Result<CardUuid, SmartCardError> FromBytes(Maybe<byte[]> bytes)
    {
        return bytes
            .ToResult(SmartCardError.InvalidArgument("UUID byte array cannot be null"))
            .Bind(ValidateByteArrayLength)
            .Bind(CreateGuidFromBytes)
            .Bind(FromGuid);
    }

    /// <summary>
    /// Overload that takes byte array directly for convenience.
    /// </summary>
    /// <param name="bytes">The byte array containing the UUID.</param>
    /// <returns>A new CardUuid or an error if the byte array is invalid.</returns>
    public static Result<CardUuid, SmartCardError> FromBytes(byte[] bytes)
    {
        return FromBytes(Maybe<byte[]>.From(bytes));
    }

    private static Result<byte[], SmartCardError> ValidateByteArrayLength(byte[] bytes)
    {
        return bytes.Length == 16
            ? Result.Success<byte[], SmartCardError>(bytes)
            : Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument(
                    $"UUID byte array must be 16 bytes, got {bytes.Length}"
                )
            );
    }

    private static Result<Guid, SmartCardError> CreateGuidFromBytes(byte[] bytes)
    {
        return Result.Try(
            () => new Guid(bytes),
            ex => SmartCardError.InvalidArgument($"Invalid UUID byte array: {ex.Message}")
        );
    }

    /// <summary>
    /// Converts the UUID to a byte array for cryptographic operations.
    /// Returns exactly 16 bytes in the standard GUID byte format.
    /// </summary>
    /// <returns>16-byte array representing the UUID.</returns>
    public byte[] ToByteArray() => Value.ToByteArray();

    /// <summary>
    /// Converts the UUID to a string representation.
    /// Uses the standard GUID string format.
    /// </summary>
    /// <returns>String representation of the UUID.</returns>
    public override string ToString() => Value.ToString();

    /// <summary>
    /// Converts the UUID to a string representation with specified format.
    /// </summary>
    /// <param name="format">The format string ("N", "D", "B", "P", or "X").</param>
    /// <returns>Formatted string representation of the UUID.</returns>
    public string ToString(string format) => Value.ToString(format);

    /// <summary>
    /// Gets the underlying Guid value.
    /// Used for interoperability with code that expects Guid directly.
    /// </summary>
    public Guid ToGuid() => Value;

    /// <summary>
    /// Checks if this CardUuid is empty (all zeros).
    /// </summary>
    public bool IsEmpty => Value == Guid.Empty;

    /// <summary>
    /// Creates an empty CardUuid for testing purposes only.
    /// Should not be used in production code.
    /// </summary>
    /// <returns>An empty CardUuid.</returns>
    public static CardUuid Empty => new(Guid.Empty);
}
