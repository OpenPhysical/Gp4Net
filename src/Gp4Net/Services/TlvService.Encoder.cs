using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Services;

public static partial class TlvService
{
    /// <summary>
    /// TLV encoding operations.
    /// Encodes TLV objects to byte arrays.
    /// </summary>
    public static class TlvEncoder
    {
        /// <summary>
        /// Encodes a single TLV object to bytes.
        /// </summary>
        /// <param name="tlv">The TLV object to encode.</param>
        /// <returns>A Result containing the encoded bytes or an error.</returns>
        public static Result<ImmutableArray<byte>, SmartCardError> Encode(TlvObject tlv)
        {
            return EncodeTag(tlv.Tag)
                .Bind(tagBytes =>
                    EncodeLength(tlv.Length)
                        .Map(lengthBytes =>
                            tagBytes.AddRange(lengthBytes).AddRange(tlv.TlvData.Bytes)
                        )
                );
        }

        /// <summary>
        /// Encodes multiple TLV objects to bytes.
        /// </summary>
        /// <param name="objects">The TLV objects to encode.</param>
        /// <returns>A Result containing the encoded bytes or an error.</returns>
        public static Result<ImmutableArray<byte>, SmartCardError> EncodeMultiple(
            ImmutableArray<TlvObject> objects
        )
        {
            if (objects.IsDefault || objects.Length == 0)
            {
                return Result.Success<ImmutableArray<byte>, SmartCardError>(
                    ImmutableArray<byte>.Empty
                );
            }

            // Use LINQ to encode all objects and aggregate results
            var encodedResults = objects.Select(obj => Encode(obj)).ToImmutableArray();

            // Check if any encoding failed using pattern matching
            var failures = encodedResults.Where(r => r.IsFailure).ToImmutableArray();
            if (failures.Length > 0)
            {
                return Result.Failure<ImmutableArray<byte>, SmartCardError>(failures[0].Error);
            }

            // Aggregate all successful results using Match
            var aggregated = encodedResults
                .SelectMany(r => r.Match(bytes => bytes, _ => ImmutableArray<byte>.Empty))
                .ToImmutableArray();

            return Result.Success<ImmutableArray<byte>, SmartCardError>(aggregated);
        }

        /// <summary>
        /// Encodes a TLV object with specific encoding options.
        /// </summary>
        /// <param name="tlv">The TLV object to encode.</param>
        /// <param name="options">Encoding options.</param>
        /// <returns>A Result containing the encoded bytes or an error.</returns>
        public static Result<ImmutableArray<byte>, SmartCardError> EncodeWithOptions(
            TlvObject tlv,
            EncodingOptions options
        )
        {
            return options.MaxLength.Match(
                maxLength =>
                {
                    var valueLength = tlv.TlvData.Bytes.Length;
                    if (valueLength > maxLength)
                    {
                        return Result.Failure<ImmutableArray<byte>, SmartCardError>(
                            SmartCardError.InvalidArgument(
                                $"Value length {valueLength} exceeds maximum {maxLength}"
                            )
                        );
                    }
                    return EncodeWithOptionsInternal(tlv, options);
                },
                () => EncodeWithOptionsInternal(tlv, options)
            );
        }

        /// <summary>
        /// Internal method to encode with options.
        /// </summary>
        private static Result<ImmutableArray<byte>, SmartCardError> EncodeWithOptionsInternal(
            TlvObject tlv,
            EncodingOptions options
        )
        {
            return EncodeTag(tlv.Tag)
                .Bind(tagBytes =>
                    EncodeLengthWithOptions(tlv.Length, options.UseLongForm)
                        .Bind(lengthBytes =>
                        {
                            var baseEncoded = tagBytes
                                .AddRange(lengthBytes)
                                .AddRange(tlv.TlvData.Bytes);

                            return options.PadToBlockSize.Match(
                                blockSize => ApplyPadding(baseEncoded, blockSize),
                                () =>
                                    Result.Success<ImmutableArray<byte>, SmartCardError>(
                                        baseEncoded
                                    )
                            );
                        })
                );
        }

        /// <summary>
        /// Encodes a TLV tag to bytes.
        /// </summary>
        /// <param name="tag">The tag to encode.</param>
        /// <returns>A Result containing the encoded tag bytes or an error.</returns>
        public static Result<ImmutableArray<byte>, SmartCardError> EncodeTag(TlvTag tag)
        {
            if (tag.Bytes.Length == 0)
            {
                return Result.Failure<ImmutableArray<byte>, SmartCardError>(
                    SmartCardError.InvalidArgument("Cannot encode empty tag")
                );
            }

            return Result.Success<ImmutableArray<byte>, SmartCardError>(tag.Bytes);
        }

        /// <summary>
        /// Encodes a TLV length to bytes.
        /// </summary>
        /// <param name="length">The length to encode.</param>
        /// <returns>A Result containing the encoded length bytes or an error.</returns>
        public static Result<ImmutableArray<byte>, SmartCardError> EncodeLength(TlvLength length)
        {
            return EncodeLengthWithOptions(length, false);
        }

        /// <summary>
        /// Encodes a TLV length with options for long form.
        /// </summary>
        /// <param name="length">The length to encode.</param>
        /// <param name="useLongForm">Whether to force long form encoding.</param>
        /// <returns>A Result containing the encoded length bytes or an error.</returns>
        private static Result<ImmutableArray<byte>, SmartCardError> EncodeLengthWithOptions(
            TlvLength length,
            bool useLongForm
        )
        {
            var lengthValue = length.LengthValue;

            // Check for GP-specific encoding: length 128 as 0x80
            if (lengthValue == 128 && !useLongForm)
            {
                return Result.Success<ImmutableArray<byte>, SmartCardError>(
                    ImmutableArray.Create<byte>(0x80)
                );
            }

            // Short form (if length <= 127 and not forcing long form)
            if (lengthValue <= Constants.Constants.Tlv.Parsing.MAX_SHORT_FORM_LENGTH && !useLongForm)
            {
                return Result.Success<ImmutableArray<byte>, SmartCardError>(
                    ImmutableArray.Create((byte)lengthValue)
                );
            }

            // Long form
            return EncodeLongFormLength(lengthValue);
        }

        /// <summary>
        /// Encodes a length value in long form.
        /// </summary>
        /// <param name="value">The length value.</param>
        /// <returns>A Result containing the encoded bytes or an error.</returns>
        private static Result<ImmutableArray<byte>, SmartCardError> EncodeLongFormLength(int value)
        {
            // Determine number of bytes needed
            var bytesNeeded = value switch
            {
                <= 0xFF => 1,
                <= 0xFFFF => 2,
                <= 0xFFFFFF => 3,
                _ => 4,
            };

            // Build the length bytes
            var builder = ImmutableArray.CreateBuilder<byte>(bytesNeeded + 1);

            // First byte: 0x80 | number of length bytes
            builder.Add((byte)(Constants.Constants.Tlv.Parsing.LONG_FORM_LENGTH_MASK | bytesNeeded));

            // Add length bytes in big-endian order
            var lengthBytes = Enumerable
                .Range(0, bytesNeeded)
                .Select(i => (byte)(value >> ((bytesNeeded - 1 - i) * 8)))
                .ToImmutableArray();

            builder.AddRange(lengthBytes);

            return Result.Success<ImmutableArray<byte>, SmartCardError>(builder.ToImmutable());
        }

        /// <summary>
        /// Applies padding to encoded data.
        /// </summary>
        /// <param name="data">The data to pad.</param>
        /// <param name="blockSize">The block size to pad to.</param>
        /// <returns>A Result containing the padded data or an error.</returns>
        private static Result<ImmutableArray<byte>, SmartCardError> ApplyPadding(
            ImmutableArray<byte> data,
            int blockSize
        )
        {
            if (blockSize <= 0)
            {
                return Result.Failure<ImmutableArray<byte>, SmartCardError>(
                    SmartCardError.InvalidArgument($"Invalid block size: {blockSize}")
                );
            }

            var remainder = data.Length % blockSize;
            if (remainder == 0)
            {
                return Result.Success<ImmutableArray<byte>, SmartCardError>(data);
            }

            var paddingNeeded = blockSize - remainder;
            var padding = Enumerable.Repeat((byte)0x00, paddingNeeded).ToImmutableArray();

            return Result.Success<ImmutableArray<byte>, SmartCardError>(data.AddRange(padding));
        }

        /// <summary>
        /// Creates a TLV object from tag number and value, then encodes it.
        /// </summary>
        /// <param name="tagNumber">The tag number.</param>
        /// <param name="value">The value bytes.</param>
        /// <returns>A Result containing the encoded TLV or an error.</returns>
        public static Result<ImmutableArray<byte>, SmartCardError> EncodeSimple(
            uint tagNumber,
            ImmutableArray<byte> value
        )
        {
            var tag = tagNumber switch
            {
                <= 0xFF => TlvTag.FromByte((byte)tagNumber),
                <= 0xFFFF => TlvTag.FromUShort((ushort)tagNumber),
                _ => new TlvTag(
                    ImmutableArray.Create(
                        (byte)(tagNumber >> 24),
                        (byte)(tagNumber >> 16),
                        (byte)(tagNumber >> 8),
                        (byte)tagNumber
                    )
                ),
            };

            return TlvObject.Create(tag, new TlvValue(value)).Bind(Encode);
        }
    }
}
