// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;
using static Gp4Net.Services.TlvService;

namespace Gp4Net.Domain.DataObjects;

/// <summary>
/// Encodes and decodes the Key Information Template returned for GET DATA tag 'E0'.
/// </summary>
[PublicAPI]
public static class KeyInfoTemplateCodec
{
    public static Result<byte[], SmartCardError> Encode(KeyInfoTemplate keyInfo)
    {
        if (keyInfo is null)
            return SmartCardError.InvalidArgument("KeyInfo cannot be null");

        ImmutableArray<KeyInformationData> keys = GetKeys(keyInfo);
        if (keys.IsEmpty)
            return SmartCardError.InvalidData("A Key Information Template must contain a key");

        using var content = new MemoryStream();
        foreach (KeyInformationData key in keys)
        {
            Result<byte[], SmartCardError> valueResult = EncodeKey(key);
            if (valueResult.IsFailure)
                return valueResult.Error;

            Result writeResult = WriteTlv(content, 0xC0, valueResult.Value);
            if (writeResult.IsFailure)
                return SmartCardError.InvalidData(writeResult.Error);
        }

        using var result = new MemoryStream();
        Result outerResult = WriteTlv(result, 0xE0, content.ToArray());
        return outerResult.IsSuccess
            ? result.ToArray()
            : SmartCardError.InvalidData(outerResult.Error);
    }

    public static Result<KeyInfoTemplate, SmartCardError> Decode(byte[] data)
    {
        if (data is null)
            return SmartCardError.InvalidArgument("Data cannot be null");

        return TlvParser
            .Parse([.. data])
            .Bind(outer =>
                outer
                    .Tag.ToNumber()
                    .Bind(tag =>
                        tag == 0xE0
                            ? Result.Success<TlvObject, SmartCardError>(outer)
                            : SmartCardError.InvalidData(
                                "Invalid key information template format, expected tag 0xE0"
                            )
                    )
            )
            .Bind(DecodeKeys);
    }

    private static ImmutableArray<KeyInformationData> GetKeys(KeyInfoTemplate keyInfo)
    {
        if (!keyInfo.Keys.IsDefaultOrEmpty)
            return keyInfo.Keys;

        if (
            keyInfo.KeyIdentifier.HasNoValue
            || keyInfo.KeyVersionNumber.HasNoValue
            || keyInfo.KeyTypesAndLengths.IsDefaultOrEmpty
        )
            return [];

        return
        [
            new KeyInformationData(
                keyInfo.KeyIdentifier.Value,
                keyInfo.KeyVersionNumber.Value,
                keyInfo.KeyTypesAndLengths
            ),
        ];
    }

    private static Result<byte[], SmartCardError> EncodeKey(KeyInformationData key)
    {
        if (key.Components.IsDefaultOrEmpty)
            return SmartCardError.InvalidData("Key Information Data requires a key component");

        bool extended = key.Components[0].Type > 0xFE;
        if (key.Components.Any(component => (component.Type > 0xFE) != extended))
            return SmartCardError.InvalidData(
                "All key components must use the same key type coding"
            );

        using var value = new MemoryStream();
        value.WriteByte(key.KeyIdentifier);
        value.WriteByte(key.KeyVersionNumber);

        if (!extended)
        {
            foreach (KeyTypeAndLength component in key.Components)
            {
                if (component.Length > byte.MaxValue)
                    return SmartCardError.InvalidData(
                        "Basic key component length exceeds one byte"
                    );
                value.WriteByte((byte)component.Type);
                value.WriteByte((byte)component.Length);
            }
        }
        else
        {
            foreach (KeyTypeAndLength component in key.Components)
            {
                if ((component.Type & 0xFF00) != 0xFF00 || component.Length is 0 or > 0x7FFF)
                    return SmartCardError.InvalidData("Invalid extended key type or length");
                value.WriteByte(0xFF);
                value.WriteByte((byte)component.Type);
                value.WriteByte((byte)(component.Length >> 8));
                value.WriteByte((byte)component.Length);
            }

            WriteOptionalByte(value, key.KeyUsage);
            WriteOptionalByte(value, key.KeyAccess);
        }

        return value.ToArray();
    }

    private static Result<KeyInfoTemplate, SmartCardError> DecodeKeys(TlvObject outer)
    {
        Result<ParseResult, SmartCardError> parsed = TlvParser.ParseMultiple(outer.TlvData.Bytes);
        if (parsed.IsFailure)
            return parsed.Error;
        if (parsed.Value.BytesConsumed != outer.TlvData.Bytes.Length)
            return SmartCardError.InvalidData("Malformed Key Information Template content");

        var keys = ImmutableArray.CreateBuilder<KeyInformationData>();
        foreach (TlvObject element in parsed.Value.Objects)
        {
            Result<uint, SmartCardError> tag = element.Tag.ToNumber();
            if (tag.IsFailure || tag.Value != 0xC0)
                return SmartCardError.InvalidData(
                    "Key Information Template may contain only C0 data objects"
                );

            Result<KeyInformationData, SmartCardError> key = DecodeKey(element.TlvData.Bytes);
            if (key.IsFailure)
                return key.Error;
            keys.Add(key.Value);
        }

        if (keys.Count == 0)
            return SmartCardError.InvalidData(
                "A Key Information Template must contain a C0 data object"
            );

        KeyInformationData first = keys[0];
        return new KeyInfoTemplate
        {
            Keys = keys.ToImmutable(),
            KeyIdentifier = first.KeyIdentifier,
            KeyVersionNumber = first.KeyVersionNumber,
            KeyTypesAndLengths = first.Components,
        };
    }

    private static Result<KeyInformationData, SmartCardError> DecodeKey(ImmutableArray<byte> data)
    {
        if (data.Length < 4)
            return SmartCardError.InvalidData("Key Information Data is shorter than four bytes");

        return data[2] == 0xFF ? DecodeExtendedKey(data) : DecodeBasicKey(data);
    }

    private static Result<KeyInformationData, SmartCardError> DecodeBasicKey(
        ImmutableArray<byte> data
    )
    {
        if ((data.Length - 2) % 2 != 0)
            return SmartCardError.InvalidData(
                "Basic Key Information Data has an incomplete component"
            );

        ImmutableArray<KeyTypeAndLength> components = Enumerable
            .Range(0, (data.Length - 2) / 2)
            .Select(index => new KeyTypeAndLength(data[2 + index * 2], data[3 + index * 2]))
            .ToImmutableArray();

        return new KeyInformationData(data[0], data[1], components);
    }

    private static Result<KeyInformationData, SmartCardError> DecodeExtendedKey(
        ImmutableArray<byte> data
    )
    {
        for (int componentCount = 1; 2 + componentCount * 4 + 2 <= data.Length; componentCount++)
        {
            int suffixOffset = 2 + componentCount * 4;
            if (
                !TryDecodeOptionalBytes(
                    data,
                    suffixOffset,
                    out Maybe<byte> usage,
                    out Maybe<byte> access
                )
            )
                continue;

            var components = ImmutableArray.CreateBuilder<KeyTypeAndLength>(componentCount);
            bool valid = true;
            for (int index = 0; index < componentCount; index++)
            {
                int offset = 2 + index * 4;
                ushort type = (ushort)(data[offset] << 8 | data[offset + 1]);
                ushort length = (ushort)(data[offset + 2] << 8 | data[offset + 3]);
                if ((type & 0xFF00) != 0xFF00 || length is 0 or > 0x7FFF)
                {
                    valid = false;
                    break;
                }
                components.Add(new KeyTypeAndLength(type, length));
            }

            if (valid)
                return new KeyInformationData(
                    data[0],
                    data[1],
                    components.ToImmutable(),
                    usage,
                    access
                );
        }

        return SmartCardError.InvalidData("Invalid extended Key Information Data");
    }

    private static bool TryDecodeOptionalBytes(
        ImmutableArray<byte> data,
        int offset,
        out Maybe<byte> usage,
        out Maybe<byte> access
    )
    {
        usage = Maybe<byte>.None;
        access = Maybe<byte>.None;
        if (offset >= data.Length || data[offset] > 1)
            return false;

        int usageLength = data[offset++];
        if (offset + usageLength >= data.Length)
            return false;
        if (usageLength == 1)
            usage = data[offset++];

        int accessLength = data[offset++];
        if (accessLength > 1 || offset + accessLength != data.Length)
            return false;
        if (accessLength == 1)
            access = data[offset];
        return true;
    }

    private static void WriteOptionalByte(Stream stream, Maybe<byte> value)
    {
        stream.WriteByte(value.HasValue ? (byte)1 : (byte)0);
        if (value.HasValue)
            stream.WriteByte(value.Value);
    }

    private static Result WriteTlv(Stream stream, byte tag, byte[] value)
    {
        if (value.Length > byte.MaxValue)
            return Result.Failure($"TLV value exceeds 255 bytes: {value.Length}");

        stream.WriteByte(tag);
        if (value.Length <= 127)
            stream.WriteByte((byte)value.Length);
        else
        {
            stream.WriteByte(0x81);
            stream.WriteByte((byte)value.Length);
        }
        stream.Write(value);
        return Result.Success();
    }
}

/// <summary>
/// GP Card Specification v2.3.1, section 11.3.3.1.1: an E0 template contains C0 Key Information Data objects.
/// </summary>
[PublicAPI]
public sealed record KeyInfoTemplate
{
    public ImmutableArray<KeyInformationData> Keys { get; init; } = [];
    public Maybe<byte> KeyVersionNumber { get; init; } = Maybe<byte>.None;
    public Maybe<byte> KeyIdentifier { get; init; } = Maybe<byte>.None;
    public ImmutableArray<KeyTypeAndLength> KeyTypesAndLengths { get; init; } = [];
}

/// <summary>
/// GP Card Specification v2.3.1, Tables 11-28 and 11-29.
/// </summary>
[PublicAPI]
public sealed record KeyInformationData(
    byte KeyIdentifier,
    byte KeyVersionNumber,
    ImmutableArray<KeyTypeAndLength> Components,
    Maybe<byte> KeyUsage = default,
    Maybe<byte> KeyAccess = default
);

[PublicAPI]
public sealed record KeyTypeAndLength(ushort Type, ushort Length);
