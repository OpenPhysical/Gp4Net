using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.Functional;
using Org.BouncyCastle.Asn1;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Services;

public static partial class TlvService
{
    /// <summary>
    /// TLV validation operations.
    /// Validates TLV structures and data integrity.
    /// </summary>
    public static class TlvValidator
    {
        /// <summary>
        /// Validates a TLV object.
        /// </summary>
        /// <param name="tlv">The TLV object to validate.</param>
        /// <returns>A Result indicating success or containing an error.</returns>
        public static UnitResult<SmartCardError> Validate(TlvObject tlv)
        {
            return ValidateTag(tlv.Tag)
                .Bind(_ => ValidateLength(tlv.Length, tlv.TlvData));
        }

        /// <summary>
        /// Validates multiple TLV objects.
        /// </summary>
        /// <param name="objects">The TLV objects to validate.</param>
        /// <returns>A Result indicating success or containing an error.</returns>
        public static UnitResult<SmartCardError> ValidateMultiple(ImmutableArray<TlvObject> objects)
        {
            if (objects.IsDefault)
            {
                return UnitResult.Success<SmartCardError>();
            }

            // Validate each object and check for failures
            var validationResults = objects
                .Select(obj => Validate(obj))
                .ToImmutableArray();

            // Check for any failures
            var failures = validationResults.Where(r => r.IsFailure).ToImmutableArray();
            return failures.Length > 0
                ? failures[0]
                : UnitResult.Success<SmartCardError>();
        }

        /// <summary>
        /// Validates a TLV tag.
        /// </summary>
        /// <param name="tag">The tag to validate.</param>
        /// <returns>A Result indicating success or containing an error.</returns>
        public static UnitResult<SmartCardError> ValidateTag(TlvTag tag)
        {
            if (tag.Bytes.Length == 0)
            {
                return UnitResult.Failure<SmartCardError>(
                    SmartCardError.InvalidArgument("Tag cannot be empty")
                );
            }

            if (tag.Bytes.Length > Tlv.Parsing.MaxReasonableTagBytes)
            {
                return UnitResult.Failure<SmartCardError>(
                    SmartCardError.InvalidArgument($"Tag length {tag.Bytes.Length} exceeds maximum allowed")
                );
            }

            // Check for multi-byte tag structure
            if ((tag.Bytes[0] & Tlv.Parsing.MultiByteTagMask) == Tlv.Parsing.MultiByteTagMask)
            {
                return ValidateMultiByteTag(tag);
            }

            return UnitResult.Success<SmartCardError>();
        }

        /// <summary>
        /// Validates a multi-byte tag structure.
        /// </summary>
        private static UnitResult<SmartCardError> ValidateMultiByteTag(TlvTag tag)
        {
            if (tag.Bytes.Length < 2)
            {
                return UnitResult.Failure<SmartCardError>(
                    SmartCardError.InvalidArgument("Multi-byte tag must have at least 2 bytes")
                );
            }

            // Validate subsequent bytes
            var subsequentBytes = tag.Bytes.Skip(1).Take(tag.Bytes.Length - 2).ToImmutableArray();
            var invalidBytes = subsequentBytes
                .Where(b => (b & Tlv.Parsing.SubsequentTagByteMask) == 0)
                .ToImmutableArray();

            if (invalidBytes.Length > 0)
            {
                return UnitResult.Failure<SmartCardError>(
                    SmartCardError.InvalidArgument("Invalid multi-byte tag structure")
                );
            }

            // Last byte should not have continuation bit
            var lastByte = tag.Bytes[tag.Bytes.Length - 1];
            if ((lastByte & Tlv.Parsing.SubsequentTagByteMask) != 0)
            {
                return UnitResult.Failure<SmartCardError>(
                    SmartCardError.InvalidArgument("Multi-byte tag not properly terminated")
                );
            }

            return UnitResult.Success<SmartCardError>();
        }

        /// <summary>
        /// Validates a TLV length against its value.
        /// </summary>
        /// <param name="length">The length to validate.</param>
        /// <param name="value">The value to validate against.</param>
        /// <returns>A Result indicating success or containing an error.</returns>
        public static UnitResult<SmartCardError> ValidateLength(TlvLength length, TlvValue value)
        {
            if (length.LengthValue != value.Bytes.Length)
            {
                return UnitResult.Failure<SmartCardError>(
                    SmartCardError.InvalidArgument(
                        $"Length mismatch: declared {length.LengthValue}, actual {value.Bytes.Length}"
                    )
                );
            }

            if (length.LengthValue > Tlv.SecurityLimits.MaxTlvValueSize)
            {
                return UnitResult.Failure<SmartCardError>(
                    SmartCardError.SecurityError(
                        $"Value length {length.LengthValue} exceeds security limit"
                    )
                );
            }

            return UnitResult.Success<SmartCardError>();
        }

        /// <summary>
        /// Validates if data contains valid ASN.1 structure.
        /// </summary>
        /// <param name="data">The data to validate.</param>
        /// <returns>A Result indicating if the data is valid ASN.1.</returns>
        public static Result<bool, SmartCardError> IsValidAsn1(ImmutableArray<byte> data)
        {
            if (data.IsDefault || data.Length == 0)
            {
                return Result.Success<bool, SmartCardError>(false);
            }

            return Result.Try(() =>
            {
                // Try to parse as ASN.1 - BouncyCastle will throw if invalid
                var _ = Asn1Object.FromByteArray(data.ToArray());
                return true;
            }, ex => SmartCardError.InvalidData($"ASN.1 validation failed: {ex.Message}"));
        }

        /// <summary>
        /// Validates TLV data for GlobalPlatform compliance.
        /// </summary>
        /// <param name="tlv">The TLV object to validate.</param>
        /// <returns>A Result indicating success or containing an error.</returns>
        public static UnitResult<SmartCardError> ValidateGpCompliance(TlvObject tlv)
        {
            return ValidateTag(tlv.Tag)
                .Bind(_ => ValidateGpLength(tlv.Length))
                .Bind(_ => ValidateLength(tlv.Length, tlv.TlvData));
        }

        /// <summary>
        /// Validates length for GlobalPlatform compliance.
        /// </summary>
        private static UnitResult<SmartCardError> ValidateGpLength(TlvLength length)
        {
            // GP allows special encoding where 0x80 means length 128
            // This is already handled in parser, just validate the value
            if (length.LengthValue < 0 || length.LengthValue > Tlv.SecurityLimits.MaxTlvValueSize)
            {
                return UnitResult.Failure<SmartCardError>(
                    SmartCardError.InvalidArgument($"Invalid GP length: {length.LengthValue}")
                );
            }

            return UnitResult.Success<SmartCardError>();
        }

        /// <summary>
        /// Validates if a TLV structure is properly nested.
        /// </summary>
        /// <param name="tlv">The TLV object to check.</param>
        /// <returns>A Result containing whether the value contains nested TLV.</returns>
        public static Result<bool, SmartCardError> ContainsNestedTlv(TlvObject tlv)
        {
            if (tlv.TlvData.Bytes.Length == 0)
            {
                return Result.Success<bool, SmartCardError>(false);
            }

            // Try to parse the value as TLV
            return TlvParser.ParseMultiple(tlv.TlvData.Bytes)
                .Map(result => result.Objects.Length > 0)
                .MapError(_ => SmartCardError.InvalidData("Failed to parse nested TLV")) // Convert parse error to false
                .Match(
                    hasNested => Result.Success<bool, SmartCardError>(hasNested),
                    _ => Result.Success<bool, SmartCardError>(false)
                );
        }

        /// <summary>
        /// Validates that TLV data matches expected tag class.
        /// </summary>
        /// <param name="tag">The tag to validate.</param>
        /// <param name="expectedClass">The expected tag class.</param>
        /// <returns>A Result indicating success or containing an error.</returns>
        public static UnitResult<SmartCardError> ValidateTagClass(TlvTag tag, byte expectedClass)
        {
            if (tag.Bytes.Length == 0)
            {
                return UnitResult.Failure<SmartCardError>(
                    SmartCardError.InvalidArgument("Cannot validate class of empty tag")
                );
            }

            var tagClass = (byte)(tag.Bytes[0] & Tlv.ContextSpecific.ClassMask);
            if (tagClass != expectedClass)
            {
                return UnitResult.Failure<SmartCardError>(
                    SmartCardError.InvalidArgument(
                        $"Tag class mismatch: expected {expectedClass:X2}, got {tagClass:X2}"
                    )
                );
            }

            return UnitResult.Success<SmartCardError>();
        }
    }
}