// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System.Collections.Immutable;
using System.IO;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;
using static Gp4Net.Services.TlvService;

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
                SmartCardError.InvalidArgument("KeyInfo cannot be null")
            );

        using var stream = new MemoryStream();

        // Tag 0xE0 for key information template
        stream.WriteByte(0xE0);

        // Calculate content length
        var contentStream = new MemoryStream();

        // Key version number (C0)
        var versionResult = keyInfo.KeyVersionNumber.Match(
            version => WriteTlv(contentStream, 0xC0, [version]),
            () => Result.Success()
        );
        if (versionResult.IsFailure)
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidData(versionResult.Error)
            );

        // Key identifier (C1)
        var identifierResult = keyInfo.KeyIdentifier.Match(
            identifier => WriteTlv(contentStream, 0xC1, [identifier]),
            () => Result.Success()
        );
        if (identifierResult.IsFailure)
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidData(identifierResult.Error)
            );

        // Key types and lengths (C2)
        if (keyInfo.KeyTypesAndLengths.Length > 0)
        {
            byte[] keyData = keyInfo
                .KeyTypesAndLengths.SelectMany(keyType => new[] { keyType.Type, keyType.Length })
                .ToArray();
            var typesResult = WriteTlv(contentStream, 0xC2, keyData);
            if (typesResult.IsFailure)
                return Result.Failure<byte[], SmartCardError>(
                    SmartCardError.InvalidData(typesResult.Error)
                );
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
                    SmartCardError.InvalidData("Key information template too large for encoding")
                );
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
                SmartCardError.InvalidArgument("Data cannot be null")
            );

        // Parse the outer TLV structure using functional composition
        return TlvParser.Parse(data.ToImmutableArray())
            .Bind(outerTlv =>
                outerTlv
                    .Tag.ToNumber()
                    .Bind(tagNumber =>
                        tagNumber == 0xE0
                            ? Result.Success<TlvObject, SmartCardError>(outerTlv)
                            : Result.Failure<TlvObject, SmartCardError>(
                                SmartCardError.InvalidData(
                                    "Invalid key information template format - expected tag 0xE0"
                                )
                            )
                    )
            )
            .Bind(ProcessKeyInfoContent);
    }

    /// <summary>
    /// Processes the key information content from a parsed TLV object.
    /// </summary>
    /// <param name="outerTlv">The outer TLV object containing key information.</param>
    /// <returns>A Result containing the decoded key information template.</returns>
    private static Result<KeyInfoTemplate, SmartCardError> ProcessKeyInfoContent(TlvObject outerTlv)
    {
        return TlvParser.ParseMultiple(outerTlv.TlvData.Bytes)
            .Map(parseResult =>
                parseResult.Objects.Aggregate(
                    new KeyInfoTemplate(),
                    (keyInfo, element) => ProcessKeyInfoElement(keyInfo, element)
                )
            );
    }

    /// <summary>
    /// Processes a single TLV element and updates the key information template.
    /// Pure function that returns a new KeyInfoTemplate with updates.
    /// </summary>
    /// <param name="keyInfo">The current key information template.</param>
    /// <param name="element">The TLV element to process.</param>
    /// <returns>Updated key information template.</returns>
    private static KeyInfoTemplate ProcessKeyInfoElement(KeyInfoTemplate keyInfo, TlvObject element)
    {
        return element
            .Tag.ToNumber()
            .Match(
                tagNumber =>
                    tagNumber switch
                    {
                        0xC0 when element.Length.LengthValue == 1 => // Key version number
                        keyInfo with
                        {
                            KeyVersionNumber = Maybe<byte>.From(element.TlvData.Bytes[0]),
                        },

                        0xC1 when element.Length.LengthValue == 1 => // Key identifier
                        keyInfo with
                        {
                            KeyIdentifier = Maybe<byte>.From(element.TlvData.Bytes[0]),
                        },

                        0xC2 when element.TlvData.Bytes.Length >= 2 => // Key types and lengths
                        ProcessKeyTypesAndLengths(keyInfo, element.TlvData.Bytes),

                        _ => keyInfo, // Ignore unrecognized or malformed elements
                    },
                _ => keyInfo // Ignore elements with invalid tags
            );
    }

    /// <summary>
    /// Processes key types and lengths data using functional programming.
    /// </summary>
    /// <param name="keyInfo">The current key information template.</param>
    /// <param name="data">The key types and lengths data.</param>
    /// <returns>Updated key information template with key types and lengths.</returns>
    private static KeyInfoTemplate ProcessKeyTypesAndLengths(
        KeyInfoTemplate keyInfo,
        ImmutableArray<byte> data
    )
    {
        var keyTypes = Enumerable
            .Range(0, data.Length / 2)
            .Select(i => new KeyTypeAndLength(data[i * 2], data[i * 2 + 1]))
            .ToImmutableArray();

        return keyInfo with
        {
            KeyTypesAndLengths = keyTypes,
        };
    }

    private static Result WriteTlv(Stream stream, byte tag, byte[] value)
    {
        if (value.Length > 255)
        {
            return Result.Failure(
                SmartCardError.InvalidData($"Value too long for simple TLV encoding: {value.Length} bytes").Message
            );
        }

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
        }

        stream.Write(value, 0, value.Length);
        return Result.Success();
    }
}

/// <summary>
/// Represents GlobalPlatform key information template.
/// Immutable record following functional programming principles.
/// </summary>
[PublicAPI]
public sealed record KeyInfoTemplate
{
    /// <summary>
    /// Key version number.
    /// </summary>
    public Maybe<byte> KeyVersionNumber { get; init; } = Maybe<byte>.None;

    /// <summary>
    /// Key identifier.
    /// </summary>
    public Maybe<byte> KeyIdentifier { get; init; } = Maybe<byte>.None;

    /// <summary>
    /// Key types and their lengths.
    /// </summary>
    public ImmutableArray<KeyTypeAndLength> KeyTypesAndLengths { get; init; } =
        ImmutableArray<KeyTypeAndLength>.Empty;
}

/// <summary>
/// Represents a key type and its length.
/// Immutable record following functional programming principles.
/// </summary>
[PublicAPI]
public sealed record KeyTypeAndLength(byte Type, byte Length);
