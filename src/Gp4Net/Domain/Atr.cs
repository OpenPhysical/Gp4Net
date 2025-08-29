using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using JetBrains.Annotations;

namespace Gp4Net.Domain;

/// <summary>
/// Answer-To-Reset (ATR) value object representing the response from a smart card during the reset process.
/// </summary>
/// <remarks>
/// The ATR is defined by ISO/IEC 7816-3 and provides information about the card's capabilities,
/// supported protocols, and historical bytes. This immutable value object ensures ATR data
/// integrity and provides functional methods for parsing and validation.
/// 
/// ATR structure per ISO 7816-3:
/// - Initial character (TS): Indicates bit order and voltage convention
/// - Format character (T0): Encodes interface characters presence
/// - Interface characters (TAi, TBi, TCi, TDi): Protocol parameters
/// - Historical bytes: Card-specific information
/// - Check character (TCK): Checksum for certain protocol types
/// 
/// Valid ATR length: 2 to 33 bytes per specification.
/// </remarks>
[PublicAPI]
public sealed record Atr
{
    /// <summary>
    /// The raw ATR bytes as an immutable array.
    /// </summary>
    public ImmutableArray<byte> Value { get; }

    /// <summary>
    /// Gets the length of the ATR in bytes.
    /// </summary>
    public int Length => Value.Length;

    /// <summary>
    /// Gets the initial character (TS) which indicates bit order and voltage.
    /// </summary>
    public byte InitialCharacter => Value.Length > 0 ? Value[0] : (byte)0;

    /// <summary>
    /// Gets the format character (T0) which encodes the presence of interface characters.
    /// </summary>
    public Maybe<byte> FormatCharacter => Value.Length > 1 ? Maybe<byte>.From(Value[1]) : Maybe<byte>.None;

    /// <summary>
    /// Gets whether this is a direct convention ATR (TS = 0x3B).
    /// </summary>
    public bool IsDirectConvention => InitialCharacter == 0x3B;

    /// <summary>
    /// Gets whether this is an inverse convention ATR (TS = 0x3F).
    /// </summary>
    public bool IsInverseConvention => InitialCharacter == 0x3F;

    /// <summary>
    /// Private constructor to ensure validation through factory methods.
    /// </summary>
    /// <param name="value">The validated ATR bytes.</param>
    private Atr(ImmutableArray<byte> value)
    {
        Value = value;
    }

    /// <summary>
    /// Creates an ATR from a byte array with validation.
    /// </summary>
    /// <param name="bytes">The ATR bytes to validate and wrap.</param>
    /// <returns>Success with ATR if valid, or failure with validation error.</returns>
    public static Result<Atr, string> FromBytes(byte[] bytes)
    {
        return Maybe<byte[]>.From(bytes)
            .Map(ValidateAtrBytes)
            .GetValueOrDefault(Result.Failure<byte[], string>("ATR bytes cannot be null"))
            .Map(validBytes => new Atr([..validBytes]));
    }

    /// <summary>
    /// Creates an ATR from an immutable array with validation.
    /// </summary>
    /// <param name="bytes">The ATR bytes to validate and wrap.</param>
    /// <returns>Success with ATR if valid, or failure with validation error.</returns>
    public static Result<Atr, string> FromImmutableArray(ImmutableArray<byte> bytes)
    {
        return ValidateAtrBytes(bytes.ToArray())
            .Map(validBytes => new Atr(bytes));
    }

    /// <summary>
    /// Validates ATR bytes according to ISO 7816-3 specification.
    /// </summary>
    /// <param name="bytes">The bytes to validate.</param>
    /// <returns>Success with validated bytes, or failure with validation error.</returns>
    private static Result<byte[], string> ValidateAtrBytes(byte[] bytes)
    {
        // Check minimum length (2 bytes: TS + T0)
        if (bytes.Length < 2)
        {
            return Result.Failure<byte[], string>("ATR must be at least 2 bytes (TS + T0)");
        }

        // Check maximum length per ISO 7816-3
        if (bytes.Length > 33)
        {
            return Result.Failure<byte[], string>("ATR cannot exceed 33 bytes per ISO 7816-3");
        }

        // Validate initial character (TS)
        byte ts = bytes[0];
        if (ts != 0x3B && ts != 0x3F)
        {
            return Result.Failure<byte[], string>($"Invalid initial character: 0x{ts:X2}. Must be 0x3B (direct) or 0x3F (inverse)");
        }

        // Additional validation could be added here for:
        // - Interface character consistency
        // - Check character (TCK) validation for T=1 protocols
        // - Historical bytes length validation

        return Result.Success<byte[], string>(bytes);
    }

    /// <summary>
    /// Converts the ATR to a hexadecimal string representation.
    /// </summary>
    /// <returns>Hexadecimal string representation of the ATR.</returns>
    public override string ToString()
    {
        return Value.Length == 0
            ? "Empty ATR"
            : Convert.ToHexString(Value.ToArray());
    }

    /// <summary>
    /// Gets a formatted representation of the ATR with spaces between bytes.
    /// </summary>
    /// <returns>Formatted hexadecimal string with spaces.</returns>
    public string ToFormattedString()
    {
        return Value.Length == 0
            ? "Empty ATR"
            : string.Join(" ", Value.Select(b => $"{b:X2}"));
    }

    /// <summary>
    /// Converts the ATR back to a byte array.
    /// </summary>
    /// <returns>Copy of the ATR bytes as a byte array.</returns>
    public byte[] ToByteArray()
    {
        return Value.ToArray();
    }

    /// <summary>
    /// Gets historical bytes from the ATR if present.
    /// </summary>
    /// <returns>Historical bytes if present, or None if not available.</returns>
    public Maybe<ImmutableArray<byte>> GetHistoricalBytes()
    {
        if (Value.Length < 2)
        {
            return Maybe<ImmutableArray<byte>>.None;
        }

        byte t0 = Value[1];
        int interfaceCharacterCount = CountInterfaceCharacters(t0);
        int historicalBytesStart = 2 + interfaceCharacterCount;

        // Historical bytes count is lower nibble of T0
        int historicalBytesCount = t0 & 0x0F;

        if (historicalBytesStart + historicalBytesCount > Value.Length)
        {
            return Maybe<ImmutableArray<byte>>.None;
        }

        if (historicalBytesCount == 0)
        {
            return Maybe<ImmutableArray<byte>>.From(ImmutableArray<byte>.Empty);
        }

        ImmutableArray<byte> historicalBytes = [
            ..Value
                .Skip(historicalBytesStart)
                .Take(historicalBytesCount)
        ];

        return Maybe<ImmutableArray<byte>>.From(historicalBytes);
    }

    /// <summary>
    /// Counts the number of interface characters based on T0 and subsequent TDi characters.
    /// This is a simplified implementation - full ATR parsing would require more complex logic.
    /// </summary>
    /// <param name="t0">The format character T0.</param>
    /// <returns>Estimated count of interface characters.</returns>
    private static int CountInterfaceCharacters(byte t0)
    {
        int count = 0;

        // Count TAi, TBi, TCi, TDi based on high nibble of T0
        int interfaceIndicator = (t0 & 0xF0) >> 4;

        if ((interfaceIndicator & 0x1) != 0) count++; // TAi present
        if ((interfaceIndicator & 0x2) != 0) count++; // TBi present
        if ((interfaceIndicator & 0x4) != 0) count++; // TCi present
        if ((interfaceIndicator & 0x8) != 0) count++; // TDi present

        // Note: This is simplified. In reality, TDi can indicate additional interface characters
        // A full implementation would need to parse the entire chain of TDi characters

        return count;
    }
}