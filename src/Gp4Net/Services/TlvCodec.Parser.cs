using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Services;

public static partial class TlvCodec
{
    /// <summary>
    /// TLV parsing operations.
    /// Handles both ASN.1 and non-ASN.1 TLV structures.
    /// </summary>
    public static class TlvParser
    {
        /// <summary>
        /// Parses a single TLV object from the given data.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <returns>A Result containing the parsed TLV object or an error.</returns>
        public static Result<TlvObject, SmartCardError> Parse(ImmutableArray<byte> data)
        {
            if (data.IsDefault || data.Length == 0)
            {
                return Result.Failure<TlvObject, SmartCardError>(
                    SmartCardError.InvalidArgument("Cannot parse empty data")
                );
            }

            return ParseAt(data, 0).Map(result => result.Object);
        }

        /// <summary>
        /// Parses a single TLV object starting at the specified offset.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <param name="offset">The starting offset.</param>
        /// <returns>A Result containing the parsed object and bytes consumed.</returns>
        private static Result<(TlvObject Object, int BytesConsumed), SmartCardError> ParseAt(
            ImmutableArray<byte> data,
            int offset
        )
        {
            if (offset >= data.Length)
            {
                return Result.Failure<(TlvObject, int), SmartCardError>(
                    SmartCardError.InvalidArgument("Offset beyond data length")
                );
            }

            return ParseTag(data, offset)
                .Bind(tagResult =>
                    ParseLength(data, tagResult.EndOffset)
                        .Bind(lengthResult =>
                            ExtractValue(data, lengthResult.EndOffset, lengthResult.Length)
                                .Bind(valueResult =>
                                    TlvObject
                                        .Create(tagResult.Tag, valueResult.Value)
                                        .Map(tlv => (tlv, valueResult.EndOffset - offset))
                                )
                        )
                );
        }

        /// <summary>
        /// Parses multiple TLV objects from the given data using functional recursion.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <returns>A Result containing the parse result or an error.</returns>
        public static Result<ParseResult, SmartCardError> ParseMultiple(ImmutableArray<byte> data)
        {
            if (data.IsDefault || data.Length == 0)
            {
                return Result.Success<ParseResult, SmartCardError>(ParseResult.Empty);
            }

            // Build list of parsed objects using a local builder
            var builder = ImmutableArray.CreateBuilder<TlvObject>();
            int bytesConsumed = 0;

            UnitResult<SmartCardError> ParseRemaining(int currentOffset)
            {
                if (currentOffset >= data.Length)
                {
                    bytesConsumed = currentOffset;
                    return UnitResult.Success<SmartCardError>();
                }

                return ParseAt(data, currentOffset)
                    .Match(
                        parseResult =>
                        {
                            builder.Add(parseResult.Object);
                            return ParseRemaining(currentOffset + parseResult.BytesConsumed);
                        },
                        error =>
                        {
                            bytesConsumed = currentOffset;
                            return builder.Count > 0
                                ? UnitResult.Success<SmartCardError>()
                                : UnitResult.Failure(error);
                        }
                    );
            }

            return ParseRemaining(0)
                .Match(
                    () =>
                        Result.Success<ParseResult, SmartCardError>(
                            new ParseResult(builder.ToImmutable(), bytesConsumed)
                        ),
                    error => Result.Failure<ParseResult, SmartCardError>(error)
                );
        }

        /// <summary>
        /// Finds a TLV object with the specified tag.
        /// </summary>
        /// <param name="data">The data to search.</param>
        /// <param name="tag">The tag to find.</param>
        /// <returns>A Result containing Maybe of the found object or an error.</returns>
        public static Result<Maybe<TlvObject>, SmartCardError> FindByTag(
            ImmutableArray<byte> data,
            uint tag
        )
        {
            return ParseMultiple(data)
                .Map(result =>
                {
                    var found = result
                        .Objects.Where(obj =>
                            obj.Tag.ToNumber().Match(tagNum => tagNum == tag, _ => false)
                        )
                        .ToImmutableArray();

                    return found.Length > 0
                        ? Maybe<TlvObject>.From(found[0])
                        : Maybe<TlvObject>.None;
                });
        }

        /// <summary>
        /// Finds a TLV object with the specified tag bytes.
        /// </summary>
        /// <param name="data">The data to search.</param>
        /// <param name="tag">The tag bytes to find.</param>
        /// <returns>A Result containing Maybe of the found object or an error.</returns>
        public static Result<Maybe<TlvObject>, SmartCardError> FindByTag(
            ImmutableArray<byte> data,
            ImmutableArray<byte> tag
        )
        {
            return ParseMultiple(data)
                .Map(result =>
                {
                    var found = result
                        .Objects.Where(obj => obj.Tag.Bytes.SequenceEqual(tag))
                        .ToImmutableArray();

                    return found.Length > 0
                        ? Maybe<TlvObject>.From(found[0])
                        : Maybe<TlvObject>.None;
                });
        }

        /// <summary>
        /// Parses a tag from the data.
        /// </summary>
        private static Result<(TlvTag Tag, int EndOffset), SmartCardError> ParseTag(
            ImmutableArray<byte> data,
            int offset
        )
        {
            if (offset >= data.Length)
            {
                return Result.Failure<(TlvTag, int), SmartCardError>(
                    SmartCardError.InvalidArgument("Offset beyond data length")
                );
            }

            var firstByte = data[offset];

            // Check if this is a multi-byte tag
            if (
                (firstByte & Constants.Constants.Tlv.Parsing.MULTI_BYTE_TAG_MASK)
                != Constants.Constants.Tlv.Parsing.MULTI_BYTE_TAG_MASK
            )
            {
                // Single byte tag
                return Result.Success<(TlvTag, int), SmartCardError>(
                    (new TlvTag([firstByte]), offset + 1)
                );
            }

            // Multi-byte tag - collect all tag bytes
            var tagBuilder = ImmutableArray.CreateBuilder<byte>();
            tagBuilder.Add(firstByte);

            var currentOffset = offset + 1;

            // Collect tag bytes using functional iteration
            Func<int, Result<(TlvTag, int), SmartCardError>> collectBytes = null!;
            collectBytes = pos =>
            {
                if (pos >= data.Length)
                {
                    return Result.Failure<(TlvTag, int), SmartCardError>(
                        SmartCardError.InvalidArgument("Incomplete multi-byte tag")
                    );
                }

                var currentByte = data[pos];
                tagBuilder.Add(currentByte);

                // Check if this is the last byte of the tag
                if ((currentByte & Constants.Constants.Tlv.Parsing.SUBSEQUENT_TAG_BYTE_MASK) == 0)
                {
                    return Result.Success<(TlvTag, int), SmartCardError>(
                        (new TlvTag(tagBuilder.ToImmutable()), pos + 1)
                    );
                }

                return collectBytes(pos + 1);
            };

            return collectBytes(currentOffset);
        }

        /// <summary>
        /// Parses a length from the data.
        /// </summary>
        private static Result<(int Length, int EndOffset), SmartCardError> ParseLength(
            ImmutableArray<byte> data,
            int offset
        )
        {
            if (offset >= data.Length)
            {
                return Result.Failure<(int, int), SmartCardError>(
                    SmartCardError.InvalidArgument("Offset beyond data length")
                );
            }

            var firstByte = data[offset];
            var currentOffset = offset + 1;

            // GP Card Specification v2.3.1: GP-specific extension where 0x80 alone means length 128
            if (firstByte == 0x80)
            {
                return Result.Success<(int, int), SmartCardError>((128, currentOffset));
            }

            // Short form
            if ((firstByte & Constants.Constants.Tlv.Parsing.LONG_FORM_LENGTH_MASK) == 0)
            {
                return Result.Success<(int, int), SmartCardError>((firstByte, currentOffset));
            }

            // Long form
            var lengthBytes = firstByte & Constants.Constants.Tlv.Parsing.LENGTH_BYTES_MASK;
            if (lengthBytes == 0 || currentOffset + lengthBytes > data.Length)
            {
                return Result.Failure<(int, int), SmartCardError>(
                    SmartCardError.InvalidArgument("Invalid long form length encoding")
                );
            }

            // Use LINQ to aggregate the length bytes
            var lengthData = data.Skip(currentOffset).Take(lengthBytes).ToImmutableArray();
            var length = lengthData.Aggregate(0, (acc, b) => (acc << 8) | b);

            // Security check: Detect overflow
            if (length < 0)
            {
                return Result.Failure<(int, int), SmartCardError>(
                    SmartCardError.SecurityError($"TLV length {length} is invalid")
                );
            }

            return Result.Success<(int, int), SmartCardError>(
                (length, currentOffset + lengthBytes)
            );
        }

        /// <summary>
        /// Extracts the value from the data.
        /// </summary>
        private static Result<(TlvValue Value, int EndOffset), SmartCardError> ExtractValue(
            ImmutableArray<byte> data,
            int offset,
            int length
        )
        {
            if (offset + length > data.Length)
            {
                return Result.Failure<(TlvValue, int), SmartCardError>(
                    SmartCardError.InvalidArgument("Value extends beyond data length")
                );
            }

            var valueBytes = data.Skip(offset).Take(length).ToImmutableArray();
            return Result.Success<(TlvValue, int), SmartCardError>(
                (new TlvValue(valueBytes), offset + length)
            );
        }
    }
}
