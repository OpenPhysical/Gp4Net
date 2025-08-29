// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.Tlv;
using JetBrains.Annotations;

namespace Gp4Net.Domain.DataObjects;

/// <summary>
/// Codec for GlobalPlatform Key Information Template (GET DATA tag 0x00E0).
/// Encodes and decodes key information according to GP Card Specification.
/// </summary>
[PublicAPI]
public static class KeyInfoTemplateCodec
{
    /// <summary>
    /// Encodes key information template into binary format.
    /// </summary>
    /// <param name="keyInfo">The key information to encode.</param>
    /// <returns>A Result containing the encoded key information data, or an error if keyInfo is null.</returns>
    public static Result<byte[], SmartCardError> Encode(KeyInfoTemplate keyInfo)
    {
        if (keyInfo is null)
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("KeyInfo cannot be null"));

        using MemoryStream stream = new MemoryStream();

        // Tag 0xE0 for key information template
        stream.WriteByte(0xE0);

        // Calculate content length
        MemoryStream contentStream = new MemoryStream();

        // Key version number (C0)
        if (keyInfo.KeyVersionNumber.HasValue)
        {
            WriteTlv(contentStream, 0xC0, [keyInfo.KeyVersionNumber.Value]);
        }

        // Key identifier (C1)
        if (keyInfo.KeyIdentifier.HasValue)
        {
            WriteTlv(contentStream, 0xC1, [keyInfo.KeyIdentifier.Value]);
        }

        // Key types and lengths (C2)
        if (keyInfo.KeyTypesAndLengths.Count > 0)
        {
            byte[] keyData = new byte[keyInfo.KeyTypesAndLengths.Count * 2];
            int index = 0;
            foreach (KeyTypeAndLength keyType in keyInfo.KeyTypesAndLengths)
            {
                keyData[index++] = keyType.Type;
                keyData[index++] = keyType.Length;
            }
            WriteTlv(contentStream, 0xC2, keyData);
        }

        byte[] content = contentStream.ToArray();

        switch (content.Length)
        {
            // Write length
            case <= 127:
                stream.WriteByte((byte)content.Length);
                break;
            case <= 255:
                stream.WriteByte(0x81);
                stream.WriteByte((byte)content.Length);
                break;
            default:
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidData("Key information template too large for encoding"));
        }

        // Write content
        stream.Write(content, 0, content.Length);

        return Result.Success<byte[], SmartCardError>(stream.ToArray());
    }

    /// <summary>
    /// Decodes key information template from binary format.
    /// </summary>
    /// <param name="data">The encoded key information data.</param>
    /// <returns>A Result containing the decoded key information template, or an error if data is invalid.</returns>
    public static Result<KeyInfoTemplate, SmartCardError> Decode(byte[] data)
    {
        if (data is null)
            return Result.Failure<KeyInfoTemplate, SmartCardError>(
                SmartCardError.InvalidArgument("Data cannot be null"));

        // Parse the outer TLV structure
        Maybe<TlvObject> outerTlvMaybe = TlvParser.ParseSingle(data);
        if (!outerTlvMaybe.HasValue)
        {
            return SmartCardError.InvalidData("Invalid key information template format - no outer TLV found");
        }

        Result<uint, SmartCardError> tagResult = outerTlvMaybe.Value.GetTagNumber();
        if (tagResult.IsFailure || tagResult.Value != 0xE0)
        {
            return SmartCardError.InvalidData("Invalid key information template format - expected tag 0xE0");
        }

        TlvObject outerTlv = outerTlvMaybe.Value;

        try
        {
            KeyInfoTemplate keyInfo = new KeyInfoTemplate();

            // Parse all TLV elements within the key information data
            IReadOnlyList<TlvObject> elements = TlvParser.ParseAll(outerTlv.Value);

            foreach (TlvObject element in elements)
            {
                Result<uint, SmartCardError> tagNumberResult = element.GetTagNumber();
                if (tagNumberResult.IsFailure) continue;

                switch (tagNumberResult.Value)
                {
                    case 0xC0: // Key version number
                        if (element.Length == 1)
                        {
                            keyInfo.KeyVersionNumber = element.Value[0];
                        }
                        break;

                    case 0xC1: // Key identifier
                        if (element.Length == 1)
                        {
                            keyInfo.KeyIdentifier = element.Value[0];
                        }
                        break;

                    case 0xC2: // Key types and lengths
                        if (element.Value is { Length: >= 2 })
                        {
                            for (int i = 0; i < element.Value.Length; i += 2)
                            {
                                if (i + 1 < element.Value.Length)
                                {
                                    keyInfo.KeyTypesAndLengths.Add(new KeyTypeAndLength
                                    {
                                        Type = element.Value[i],
                                        Length = element.Value[i + 1]
                                    });
                                }
                            }
                        }
                        break;

                    default:
                        // Unknown tags are ignored for forward compatibility
                        break;
                }
            }

            return keyInfo;
        }
        catch (Exception ex)
        {
            return SmartCardError.InvalidData($"Failed to parse key information template: {ex.Message}");
        }
    }

    private static void WriteTlv(Stream stream, byte tag, byte[] value)
    {
        stream.WriteByte(tag);

        switch (value.Length)
        {
            // Write length
            case <= 127:
                stream.WriteByte((byte)value.Length);
                break;
            case <= 255:
                stream.WriteByte(0x81);
                stream.WriteByte((byte)value.Length);
                break;
            default:
                throw new ArgumentException($"Value too long for simple TLV encoding: {value.Length} bytes");
        }

        stream.Write(value, 0, value.Length);
    }
}

/// <summary>
/// Represents GlobalPlatform key information template.
/// </summary>
[PublicAPI]
public class KeyInfoTemplate
{
    /// <summary>
    /// Key version number.
    /// </summary>
    public Maybe<byte> KeyVersionNumber { get; set; } = Maybe<byte>.None;

    /// <summary>
    /// Key identifier.
    /// </summary>
    public Maybe<byte> KeyIdentifier { get; set; } = Maybe<byte>.None;

    /// <summary>
    /// Key types and their lengths.
    /// </summary>
    public List<KeyTypeAndLength> KeyTypesAndLengths { get; set; } = [];
}

/// <summary>
/// Represents a key type and its length.
/// </summary>
[PublicAPI]
public class KeyTypeAndLength
{
    /// <summary>
    /// Key type identifier.
    /// </summary>
    public byte Type { get; set; }

    /// <summary>
    /// Key length in bytes.
    /// </summary>
    public byte Length { get; set; }
}