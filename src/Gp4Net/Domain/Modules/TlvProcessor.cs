using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.Tlv;

namespace Gp4Net.Domain.Modules;

/// <summary>
/// Pure functional module for TLV (Tag-Length-Value) processing.
/// Handles parsing and construction of TLV structures used in GlobalPlatform.
/// </summary>
public static class TlvProcessor
{
    /// <summary>
    /// Parses TLV data into structured elements.
    /// </summary>
    /// <param name="data">The raw TLV data bytes.</param>
    /// <returns>The parsed TLV elements or an error.</returns>
    public static Result<ImmutableList<TlvObject>, SmartCardError> ParseTlvData(byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return Result.Success<ImmutableList<TlvObject>, SmartCardError>(
                ImmutableList<TlvObject>.Empty);
        }

        try
        {
            ImmutableList<TlvObject> elements = TlvParser.ParseAll(data).ToImmutableList();
            return Result.Success<ImmutableList<TlvObject>, SmartCardError>(elements);
        }
        catch (Exception ex)
        {
            return Result.Failure<ImmutableList<TlvObject>, SmartCardError>(
                SmartCardError.InvalidResponse($"Failed to parse TLV data: {ex.Message}"));
        }
    }

    /// <summary>
    /// Finds a specific TLV element by tag.
    /// </summary>
    /// <param name="elements">The list of TLV elements to search.</param>
    /// <param name="tag">The tag to find.</param>
    /// <returns>The element value or None if not found.</returns>
    public static Maybe<byte[]> FindElementValue(ImmutableList<TlvObject> elements, int tag) =>
        elements
            .Where(e => e.TagNumber == tag)
            .Select(e => e.Value)
            .FirstOrDefault()
            .AsMaybe();

    /// <summary>
    /// Constructs TLV data from tag and value.
    /// </summary>
    /// <param name="tag">The TLV tag.</param>
    /// <param name="value">The value bytes.</param>
    /// <returns>The complete TLV structure.</returns>
    public static byte[] ConstructTlv(byte tag, byte[] value)
    {
        if (value == null || value.Length == 0)
        {
            return new[] { tag, (byte)0 };
        }

        byte[] length = EncodeLength(value.Length);
        return CombineArrays(new[] { tag }, length, value);
    }

    /// <summary>
    /// Constructs TLV data from a two-byte tag and value.
    /// </summary>
    /// <param name="tag">The two-byte TLV tag.</param>
    /// <param name="value">The value bytes.</param>
    /// <returns>The complete TLV structure.</returns>
    public static byte[] ConstructTlv(ushort tag, byte[] value)
    {
        byte[] tagBytes = new[] { (byte)(tag >> 8), (byte)(tag & 0xFF) };
        
        if (value == null || value.Length == 0)
        {
            return CombineArrays(tagBytes, new byte[] { 0 });
        }

        byte[] length = EncodeLength(value.Length);
        return CombineArrays(tagBytes, length, value);
    }

    /// <summary>
    /// Encodes the length field according to TLV rules.
    /// </summary>
    /// <param name="length">The length to encode.</param>
    /// <returns>The encoded length bytes.</returns>
    public static byte[] EncodeLength(int length)
    {
        // Short form (0-127)
        if (length <= 127)
        {
            return new[] { (byte)length };
        }

        // Long form
        if (length <= 255)
        {
            return new byte[] { 0x81, (byte)length };
        }

        if (length <= 65535)
        {
            return new byte[] { 0x82, (byte)(length >> 8), (byte)(length & 0xFF) };
        }

        // For larger lengths (unlikely in smart card context)
        return new byte[] { 0x83, (byte)(length >> 16), (byte)(length >> 8), (byte)(length & 0xFF) };
    }

    /// <summary>
    /// Parses FCI (File Control Information) template commonly returned by SELECT.
    /// </summary>
    /// <param name="fciData">The FCI template data.</param>
    /// <returns>Parsed FCI elements or an error.</returns>
    public static Result<FciTemplate, SmartCardError> ParseFciTemplate(byte[] fciData)
    {
        Result<ImmutableList<TlvObject>, SmartCardError> parseResult = ParseTlvData(fciData);
        
        if (parseResult.IsFailure)
        {
            return Result.Failure<FciTemplate, SmartCardError>(parseResult.Error);
        }

        ImmutableList<TlvObject> elements = parseResult.Value;

        // Look for FCI template tag (0x6F)
        TlvObject fciElement = elements.FirstOrDefault(e => e.TagNumber == 0x6F);
        if (fciElement == null)
        {
            return Result.Failure<FciTemplate, SmartCardError>(
                SmartCardError.InvalidResponse("No FCI template found"));
        }

        // Parse the FCI template contents
        Result<ImmutableList<TlvObject>, SmartCardError> fciContentsResult = 
            ParseTlvData(fciElement.Value);
        
        if (fciContentsResult.IsFailure)
        {
            return Result.Failure<FciTemplate, SmartCardError>(fciContentsResult.Error);
        }

        ImmutableList<TlvObject> fciContents = fciContentsResult.Value;

        // Extract common FCI elements
        Maybe<byte[]> aid = FindElementValue(fciContents, 0x84);
        Maybe<byte[]> proprietaryInfo = FindElementValue(fciContents, 0xA5);
        Maybe<byte[]> applicationLabel = FindElementValue(fciContents, 0x50);

        return Result.Success<FciTemplate, SmartCardError>(
            new FciTemplate(
                Aid: aid,
                ProprietaryInfo: proprietaryInfo,
                ApplicationLabel: applicationLabel,
                RawElements: fciContents));
    }

    /// <summary>
    /// Constructs a status template for GET STATUS response.
    /// </summary>
    /// <param name="subset">The status subset indicator.</param>
    /// <returns>The status template TLV structure.</returns>
    public static byte[] ConstructStatusTemplate(byte subset) =>
        ConstructTlv(0x4F, new byte[] { subset });

    /// <summary>
    /// Parses key information template used in PUT KEY.
    /// </summary>
    /// <param name="keyData">The key information data.</param>
    /// <returns>Parsed key components or an error.</returns>
    public static Result<KeyComponents, SmartCardError> ParseKeyInformation(byte[] keyData)
    {
        Result<ImmutableList<TlvObject>, SmartCardError> parseResult = ParseTlvData(keyData);
        
        if (parseResult.IsFailure)
        {
            return Result.Failure<KeyComponents, SmartCardError>(parseResult.Error);
        }

        ImmutableList<TlvObject> elements = parseResult.Value;

        // Extract key components (typical structure varies by key type)
        Maybe<byte[]> keyValue = FindElementValue(elements, 0x80); // Key value
        Maybe<byte[]> kcv = FindElementValue(elements, 0x03); // Key Check Value
        Maybe<byte[]> keyType = FindElementValue(elements, 0x01); // Key type identifier

        if (keyValue.HasNoValue)
        {
            return Result.Failure<KeyComponents, SmartCardError>(
                SmartCardError.InvalidResponse("No key value found in key information"));
        }

        return Result.Success<KeyComponents, SmartCardError>(
            new KeyComponents(
                KeyValue: keyValue.Value,
                KeyCheckValue: kcv,
                KeyType: keyType));
    }

    /// <summary>
    /// Combines multiple byte arrays into one.
    /// </summary>
    private static byte[] CombineArrays(params byte[][] arrays)
    {
        int totalLength = arrays.Sum(a => a?.Length ?? 0);
        byte[] result = new byte[totalLength];
        
        // Functional approach using Aggregate
        arrays.Where(a => a != null && a.Length > 0)
            .Aggregate(0, (offset, array) =>
            {
                Buffer.BlockCopy(array, 0, result, offset, array.Length);
                return offset + array.Length;
            });

        return result;
    }

    /// <summary>
    /// Represents a parsed FCI template.
    /// </summary>
    public sealed record FciTemplate(
        Maybe<byte[]> Aid,
        Maybe<byte[]> ProprietaryInfo,
        Maybe<byte[]> ApplicationLabel,
        ImmutableList<TlvObject> RawElements);

    /// <summary>
    /// Represents parsed key components.
    /// </summary>
    public sealed record KeyComponents(
        byte[] KeyValue,
        Maybe<byte[]> KeyCheckValue,
        Maybe<byte[]> KeyType);
}