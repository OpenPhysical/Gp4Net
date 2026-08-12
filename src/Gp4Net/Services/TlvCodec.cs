using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.Services;

/// <summary>
/// TLV (Tag-Length-Value) service for parsing and encoding TLV data structures.
/// Handles both ASN.1 and non-ASN.1 TLV formats.
/// All operations are static, pure functional, and return Result&lt;T, SmartCardError&gt;.
/// NO NULLS - all byte arrays are wrapped in ImmutableArray&lt;byte&gt;.
/// </summary>
[PublicAPI]
public static partial class TlvCodec
{
    /// <summary>
    /// Immutable TLV tag representation.
    /// Guarantees non-null byte array through ImmutableArray.
    /// </summary>
    public readonly record struct TlvTag
    {
        /// <summary>
        /// The tag bytes. Never null due to ImmutableArray.
        /// </summary>
        public ImmutableArray<byte> Bytes { get; }

        /// <summary>
        /// Creates a new TlvTag from bytes.
        /// </summary>
        /// <param name="bytes">Tag bytes to wrap.</param>
        public TlvTag(ImmutableArray<byte> bytes)
        {
            if (bytes.IsDefault)
            {
                Bytes = ImmutableArray<byte>.Empty;
            }
            else
            {
                Bytes = bytes;
            }
        }

        /// <summary>
        /// Creates a TlvTag from a single byte.
        /// </summary>
        /// <param name="tag">Single byte tag.</param>
        /// <returns>A new TlvTag.</returns>
        public static TlvTag FromByte(byte tag) => new([tag]);

        /// <summary>
        /// Creates a TlvTag from a ushort (2 bytes).
        /// </summary>
        /// <param name="tag">Two byte tag.</param>
        /// <returns>A new TlvTag.</returns>
        public static TlvTag FromUShort(ushort tag) => new([(byte)(tag >> 8), (byte)(tag & 0xFF)]);

        /// <summary>
        /// Converts the tag to a numeric value if possible.
        /// </summary>
        /// <returns>The numeric tag value or error.</returns>
        public Result<uint, SmartCardError> ToNumber()
        {
            if (Bytes.Length == 0 || Bytes.Length > 4)
            {
                return Result.Failure<uint, SmartCardError>(
                    SmartCardError.InvalidArgument($"Tag must be 1-4 bytes, got {Bytes.Length}")
                );
            }

            uint result = Bytes.Aggregate(0u, (acc, b) => (acc << 8) | b);
            return Result.Success<uint, SmartCardError>(result);
        }

        /// <summary>
        /// Gets the hex string representation of the tag.
        /// </summary>
        /// <returns>Hex string representation.</returns>
        public string ToHexString() => Convert.ToHexString(Bytes.ToArray());
    }

    /// <summary>
    /// Immutable TLV value representation.
    /// Guarantees non-null byte array through ImmutableArray.
    /// </summary>
    public readonly record struct TlvValue
    {
        /// <summary>
        /// The value bytes. Never null due to ImmutableArray.
        /// </summary>
        public ImmutableArray<byte> Bytes { get; }

        /// <summary>
        /// Creates a new TlvValue from bytes.
        /// </summary>
        /// <param name="bytes">Value bytes to wrap.</param>
        public TlvValue(ImmutableArray<byte> bytes)
        {
            if (bytes.IsDefault)
            {
                Bytes = ImmutableArray<byte>.Empty;
            }
            else
            {
                Bytes = bytes;
            }
        }

        /// <summary>
        /// Gets the length of the value.
        /// </summary>
        public int Length => Bytes.Length;

        /// <summary>
        /// Gets the hex string representation of the value.
        /// </summary>
        /// <returns>Hex string representation.</returns>
        public string ToHexString() => Convert.ToHexString(Bytes.ToArray());

        /// <summary>
        /// Creates an empty TlvValue.
        /// </summary>
        public static TlvValue Empty => new(ImmutableArray<byte>.Empty);
    }

    /// <summary>
    /// Immutable TLV length representation with validation.
    /// </summary>
    public readonly record struct TlvLength
    {
        /// <summary>
        /// The length value.
        /// </summary>
        public int LengthValue { get; }

        /// <summary>
        /// Creates a new TlvLength.
        /// Private constructor assumes validation has been done.
        /// </summary>
        /// <param name="value">Length value.</param>
        private TlvLength(int value)
        {
            LengthValue = value;
        }

        /// <summary>
        /// Creates a TlvLength with validation.
        /// </summary>
        /// <param name="value">The length value.</param>
        /// <returns>A Result containing the TlvLength or an error.</returns>
        public static Result<TlvLength, SmartCardError> Create(int value)
        {
            if (value < 0)
            {
                return Result.Failure<TlvLength, SmartCardError>(
                    SmartCardError.InvalidArgument($"Length cannot be negative: {value}")
                );
            }

            return Result.Success<TlvLength, SmartCardError>(new TlvLength(value));
        }

        /// <summary>
        /// Creates a TlvLength from a TlvValue.
        /// </summary>
        /// <param name="value">The TLV value.</param>
        /// <returns>A Result containing the TlvLength.</returns>
        public static Result<TlvLength, SmartCardError> FromValue(TlvValue value)
        {
            return Create(value.Length);
        }

        /// <summary>
        /// Returns string representation of the length.
        /// </summary>
        /// <returns>String representation.</returns>
        public override string ToString() => LengthValue.ToString();
    }

    /// <summary>
    /// Immutable TLV object containing tag, value, and computed length.
    /// All fields are guaranteed non-null through value types.
    /// </summary>
    public readonly record struct TlvObject
    {
        /// <summary>
        /// The TLV tag. Never null.
        /// </summary>
        public TlvTag Tag { get; }

        /// <summary>
        /// The TLV value. Never null.
        /// </summary>
        public TlvValue TlvData { get; }

        /// <summary>
        /// The computed length. Never null.
        /// </summary>
        public TlvLength Length { get; }

        /// <summary>
        /// Creates a new TlvObject.
        /// </summary>
        /// <param name="tag">The tag.</param>
        /// <param name="value">The value.</param>
        /// <param name="length">The length.</param>
        private TlvObject(TlvTag tag, TlvValue value, TlvLength length)
        {
            Tag = tag;
            TlvData = value;
            Length = length;
        }

        /// <summary>
        /// Creates a TlvObject with validation.
        /// </summary>
        /// <param name="tag">The tag.</param>
        /// <param name="value">The value.</param>
        /// <returns>A Result containing the TlvObject or an error.</returns>
        public static Result<TlvObject, SmartCardError> Create(TlvTag tag, TlvValue value)
        {
            return TlvLength.FromValue(value).Map(length => new TlvObject(tag, value, length));
        }

        /// <summary>
        /// Creates a TlvObject from byte arrays.
        /// </summary>
        /// <param name="tagBytes">Tag bytes.</param>
        /// <param name="valueBytes">Value bytes.</param>
        /// <returns>A Result containing the TlvObject or an error.</returns>
        public static Result<TlvObject, SmartCardError> Create(byte[] tagBytes, byte[] valueBytes)
        {
            // Convert nullable byte arrays to ImmutableArrays with NO NULLS
            var tag = new TlvTag(tagBytes?.ToImmutableArray() ?? ImmutableArray<byte>.Empty);
            var value = new TlvValue(valueBytes?.ToImmutableArray() ?? ImmutableArray<byte>.Empty);

            if (tag.Bytes.Length == 0)
            {
                return Result.Failure<TlvObject, SmartCardError>(
                    SmartCardError.InvalidArgument("Tag cannot be empty")
                );
            }

            return Create(tag, value);
        }

        /// <summary>
        /// Returns a string representation of this TLV object.
        /// </summary>
        /// <returns>String representation.</returns>
        public override string ToString() =>
            $"Tag: {Tag.ToHexString()}, Length: {Length.ToString()}, Data: {TlvData.ToHexString()}";
    }

    /// <summary>
    /// Result of parsing TLV data.
    /// </summary>
    public readonly record struct ParseResult
    {
        /// <summary>
        /// The parsed TLV objects. Never null.
        /// </summary>
        public ImmutableArray<TlvObject> Objects { get; }

        /// <summary>
        /// Number of bytes consumed during parsing.
        /// </summary>
        public int BytesConsumed { get; }

        /// <summary>
        /// Creates a new ParseResult.
        /// </summary>
        /// <param name="objects">Parsed objects.</param>
        /// <param name="bytesConsumed">Bytes consumed.</param>
        public ParseResult(ImmutableArray<TlvObject> objects, int bytesConsumed)
        {
            Objects = objects.IsDefault ? ImmutableArray<TlvObject>.Empty : objects;
            BytesConsumed = bytesConsumed;
        }

        /// <summary>
        /// Creates an empty ParseResult.
        /// </summary>
        public static ParseResult Empty => new(ImmutableArray<TlvObject>.Empty, 0);
    }

    /// <summary>
    /// Options for encoding TLV data.
    /// </summary>
    public readonly record struct EncodingOptions
    {
        /// <summary>
        /// Whether to use long form for length encoding.
        /// </summary>
        public bool UseLongForm { get; }

        /// <summary>
        /// Optional padding to block size.
        /// </summary>
        public Maybe<int> PadToBlockSize { get; }

        /// <summary>
        /// Maximum allowed length for encoding.
        /// </summary>
        public Maybe<int> MaxLength { get; }

        /// <summary>
        /// Creates new encoding options.
        /// </summary>
        /// <param name="useLongForm">Use long form encoding.</param>
        /// <param name="padToBlockSize">Optional block size for padding.</param>
        /// <param name="maxLength">Optional maximum length.</param>
        public EncodingOptions(
            bool useLongForm = false,
            Maybe<int> padToBlockSize = default,
            Maybe<int> maxLength = default
        )
        {
            UseLongForm = useLongForm;
            PadToBlockSize = padToBlockSize;
            MaxLength = maxLength;
        }

        /// <summary>
        /// Default encoding options.
        /// </summary>
        public static EncodingOptions Default => new(false, Maybe<int>.None, Maybe<int>.None);
    }
}
