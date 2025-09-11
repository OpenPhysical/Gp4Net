// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants;
using static Gp4Net.Services.TlvService;

namespace Gp4Net.Services.GlobalPlatform;

/// <summary>
/// Data operations for GET DATA, PUT DATA, and TLV processing.
/// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.3
/// </summary>
[PublicAPI]
public static class DataOperations
{
    /// <summary>
    /// Parses TLV data into structured elements.
    /// Reference: ISO/IEC 7816-4 BER-TLV encoding rules
    /// </summary>
    /// <param name="data">The raw TLV data bytes.</param>
    /// <returns>The parsed TLV elements or an error.</returns>
    public static Result<ImmutableList<TlvObject>, SmartCardError> ParseTlvData(byte[] data)
    {
        return TlvParser.ParseMultiple(data.ToImmutableArray())
            .Map(parseResult => parseResult.Objects.ToImmutableList());
    }

    /// <summary>
    /// Finds a specific TLV element by tag.
    /// </summary>
    /// <param name="elements">The list of TLV elements to search.</param>
    /// <param name="tag">The tag to find.</param>
    /// <returns>The element value or None if not found.</returns>
    public static Maybe<byte[]> FindElementValue(ImmutableList<TlvObject> elements, int tag)
    {
        var foundElements = elements
            .Where(e =>
                e.Tag.ToNumber().Map(tagNum => tagNum == (uint)tag).GetValueOrDefault(false)
            )
            .Select(e => e.TlvData.Bytes.ToArray())
            .ToImmutableArray();

        return foundElements.Length > 0 ? Maybe<byte[]>.From(foundElements[0]) : Maybe<byte[]>.None;
    }

    /// <summary>
    /// Constructs TLV data from tag and value.
    /// </summary>
    /// <param name="tag">The TLV tag.</param>
    /// <param name="value">The value bytes.</param>
    /// <returns>The complete TLV structure.</returns>
    public static byte[] ConstructTlv(byte tag, byte[] value)
    {
        if (value is not { Length: > 0 })
        {
            return [tag, 0];
        }

        byte[] length = EncodeLength(value.Length);
        return CombineArrays([tag], length, value);
    }

    /// <summary>
    /// Constructs TLV data from a two-byte tag and value.
    /// </summary>
    /// <param name="tag">The two-byte TLV tag.</param>
    /// <param name="value">The value bytes.</param>
    /// <returns>The complete TLV structure.</returns>
    public static byte[] ConstructTlv(ushort tag, byte[] value)
    {
        byte[] tagBytes = [(byte)(tag >> 8), (byte)(tag & 0xFF)];

        if (value is not { Length: > 0 })
        {
            return CombineArrays(tagBytes, [0]);
        }

        byte[] length = EncodeLength(value.Length);
        return CombineArrays(tagBytes, length, value);
    }

    /// <summary>
    /// Encodes the length field according to TLV rules.
    /// Reference: ISO/IEC 7816-4 Section 5.2.2
    /// </summary>
    /// <param name="length">The length to encode.</param>
    /// <returns>The encoded length bytes.</returns>
    public static byte[] EncodeLength(int length)
    {
        return length switch
        {
            // Short form (0-127)
            <= 127 => [(byte)length],
            // Long form
            <= 255 => [0x81, (byte)length],
            <= 65535 => [0x82, (byte)(length >> 8), (byte)(length & 0xFF)],
            // For larger lengths (unlikely in smart card context)
            _ => [0x83, (byte)(length >> 16), (byte)(length >> 8), (byte)(length & 0xFF)],
        };
    }

    /// <summary>
    /// Parses FCI (File Control Information) template commonly returned by SELECT.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 9.2.2
    /// </summary>
    /// <param name="fciData">The FCI template data.</param>
    /// <returns>Parsed FCI elements or an error.</returns>
    public static Result<FciTemplate, SmartCardError> ParseFciTemplate(byte[] fciData)
    {
        var parseResult = ParseTlvData(fciData);

        if (parseResult.IsFailure)
        {
            return Result.Failure<FciTemplate, SmartCardError>(parseResult.Error);
        }

        var elements = parseResult.Value;

        // Look for FCI template tag
        var fciElements = elements
            .Where(e =>
                e.Tag.ToNumber()
                    .Map(tagNum => tagNum == Tlv.Iso7816Tags.FCI_TEMPLATE)
                    .GetValueOrDefault(false)
            )
            .ToImmutableArray();

        if (fciElements.Length == 0)
        {
            return Result.Failure<FciTemplate, SmartCardError>(
                SmartCardError.InvalidResponse("No FCI template found")
            );
        }

        var fciElement = fciElements[0];

        // Parse the FCI template contents
        var fciContentsResult = ParseTlvData(
            fciElement.TlvData.Bytes.ToArray()
        );

        if (fciContentsResult.IsFailure)
        {
            return Result.Failure<FciTemplate, SmartCardError>(fciContentsResult.Error);
        }

        var fciContents = fciContentsResult.Value;

        // Extract common FCI elements
        var aid = FindElementValue(fciContents, 0x84);
        var proprietaryInfo = FindElementValue(fciContents, 0xA5);
        var applicationLabel = FindElementValue(fciContents, 0x50);

        return Result.Success<FciTemplate, SmartCardError>(
            new FciTemplate(
                Aid: aid,
                ProprietaryInfo: proprietaryInfo,
                ApplicationLabel: applicationLabel,
                RawElements: fciContents
            )
        );
    }

    /// <summary>
    /// Constructs a status template for GET STATUS response.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.5
    /// </summary>
    /// <param name="subset">The status subset indicator.</param>
    /// <returns>The status template TLV structure.</returns>
    public static byte[] ConstructStatusTemplate(byte subset)
    {
        return ConstructTlv(0x4F, [subset]);
    }

    /// <summary>
    /// Parses key information template used in PUT KEY.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.7
    /// </summary>
    /// <param name="keyData">The key information data.</param>
    /// <returns>Parsed key components or an error.</returns>
    public static Result<KeyComponents, SmartCardError> ParseKeyInformation(byte[] keyData)
    {
        var parseResult = ParseTlvData(keyData);

        if (parseResult.IsFailure)
        {
            return Result.Failure<KeyComponents, SmartCardError>(parseResult.Error);
        }

        var elements = parseResult.Value;

        // Extract key components (typical structure varies by key type)
        var keyValue = FindElementValue(elements, 0x80); // Key value
        var kcv = FindElementValue(elements, 0x03); // Key Check Value
        var keyType = FindElementValue(elements, 0x01); // Key type identifier

        return keyValue.Match(
            kv =>
                Result.Success<KeyComponents, SmartCardError>(
                    new KeyComponents(KeyValue: kv, KeyCheckValue: kcv, KeyType: keyType)
                ),
            () =>
                Result.Failure<KeyComponents, SmartCardError>(
                    SmartCardError.InvalidResponse("No key value found in key information")
                )
        );
    }

    #region Private Helper Methods

    /// <summary>
    /// Combines multiple byte arrays into one.
    /// </summary>
    private static byte[] CombineArrays(params byte[][] arrays)
    {
        // Calculate total length without using null-coalescing
        int totalLength = arrays.Where(a => a is { Length: > 0 }).Sum(a => a.Length);

        byte[] result = new byte[totalLength];

        // Functional approach using Aggregate
        _ = arrays
            .Where(a => a is { Length: > 0 })
            .Aggregate(
                0,
                (offset, array) =>
                {
                    System.Buffer.BlockCopy(array, 0, result, offset, array.Length);
                    return offset + array.Length;
                }
            );

        return result;
    }

    #endregion

    #region Data Types

    /// <summary>
    /// Represents a parsed FCI template.
    /// </summary>
    public sealed record FciTemplate(
        Maybe<byte[]> Aid,
        Maybe<byte[]> ProprietaryInfo,
        Maybe<byte[]> ApplicationLabel,
        ImmutableList<TlvObject> RawElements
    );

    /// <summary>
    /// Represents parsed key components.
    /// </summary>
    public sealed record KeyComponents(
        byte[] KeyValue,
        Maybe<byte[]> KeyCheckValue,
        Maybe<byte[]> KeyType
    );

    #endregion
}
