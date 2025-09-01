// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.DataObjects;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.DataObjects;

[TestFixture]
public class KeyInfoTemplateCodecTests
{
    [Test]
    public void Encode_CompleteKeyInfo_ProducesExpectedFormat()
    {
        KeyInfoTemplate keyInfo = new KeyInfoTemplate
        {
            KeyVersionNumber = 0x01,
            KeyIdentifier = 0x00,
            KeyTypesAndLengths = [
                new KeyTypeAndLength(0x80, 0x10), // DES, 16 bytes
                new KeyTypeAndLength(0x81, 0x10), // DES-ECB, 16 bytes
                new KeyTypeAndLength(0x82, 0x10), // DES-MAC, 16 bytes
            ],
        };

        Result<byte[], SmartCardError> encodedResult = KeyInfoTemplateCodec.Encode(keyInfo);

        // Assert encoding succeeded
        _ = encodedResult.IsSuccess.Should().BeTrue("Failed to encode KeyInfoTemplate");
        byte[]? encoded = encodedResult.Value;

        _ = encoded.Should().NotBeEmpty();
        _ = encoded[0].Should().Be(0xE0, "first byte should be tag 0xE0");
        _ = encoded[1].Should().BeGreaterThan(0, "length should be positive");

        // Should contain all three component tags
        _ = encoded.Should().Contain(0xC0, "should contain key version tag");
        _ = encoded.Should().Contain(0xC1, "should contain key identifier tag");
        _ = encoded.Should().Contain(0xC2, "should contain key types tag");
    }

    [Test]
    public void Encode_MinimalKeyInfo_ProducesValidFormat()
    {
        KeyInfoTemplate keyInfo = new KeyInfoTemplate { KeyVersionNumber = 0x01 };

        Result<byte[], SmartCardError> encodedResult = KeyInfoTemplateCodec.Encode(keyInfo);

        // Assert encoding succeeded
        _ = encodedResult.IsSuccess.Should().BeTrue("Failed to encode KeyInfoTemplate");
        byte[]? encoded = encodedResult.Value;

        _ = encoded.Should().NotBeEmpty();
        _ = encoded[0].Should().Be(0xE0);
        _ = encoded.Should().Contain(0xC0, "should contain key version tag");
        _ = encoded.Should().NotContain(0xC1, "should not contain key identifier tag");
        _ = encoded.Should().NotContain(0xC2, "should not contain key types tag");
    }

    [Test]
    public void Decode_ValidKeyInfoTemplate_ReturnsCorrectStructure()
    {
        byte[] testData =
        [
            0xE0,
            0x0C, // Tag and length (fixed: 12 bytes, not 11)
            0xC0,
            0x01,
            0x01, // Key version number = 1
            0xC1,
            0x01,
            0x00, // Key identifier = 0
            0xC2,
            0x04,
            0x80,
            0x10,
            0x81,
            0x10, // Two key types: DES 16 bytes each
        ];

        Result<KeyInfoTemplate, SmartCardError> result = KeyInfoTemplateCodec.Decode(testData);

        _ = result.IsSuccess.Should().BeTrue();
        KeyInfoTemplate? keyInfo = result.Value;

        _ = keyInfo.KeyVersionNumber.HasValue.Should().BeTrue();
        _ = keyInfo.KeyVersionNumber.Value.Should().Be(0x01);
        _ = keyInfo.KeyIdentifier.HasValue.Should().BeTrue();
        _ = keyInfo.KeyIdentifier.Value.Should().Be(0x00);
        _ = keyInfo.KeyTypesAndLengths.Should().HaveCount(2);

        KeyTypeAndLength? firstKeyType = keyInfo.KeyTypesAndLengths[0];
        _ = firstKeyType.Type.Should().Be(0x80);
        _ = firstKeyType.Length.Should().Be(0x10);

        KeyTypeAndLength? secondKeyType = keyInfo.KeyTypesAndLengths[1];
        _ = secondKeyType.Type.Should().Be(0x81);
        _ = secondKeyType.Length.Should().Be(0x10);
    }

    [Test]
    public void Decode_InvalidTag_ReturnsError()
    {
        byte[] invalidData = [0xE1, 0x03, 0xC0, 0x01, 0x01]; // Wrong tag

        Result<KeyInfoTemplate, SmartCardError> result = KeyInfoTemplateCodec.Decode(invalidData);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Code.Should().Be("INVALID_DATA");
        _ = result
            .Error.Message.Should()
            .Contain("Invalid key information template format - expected tag 0xE0");
    }

    [Test]
    public void Decode_ExtendedLength_HandlesCorrectly()
    {
        byte[] testData =
        [
            0xE0,
            0x81,
            0x06, // Tag with extended length (6 bytes content)
            0xC0,
            0x01,
            0x01, // Key version number = 1
            0xC1,
            0x01,
            0x00, // Key identifier = 0
        ];

        Result<KeyInfoTemplate, SmartCardError> result = KeyInfoTemplateCodec.Decode(testData);

        _ = result.IsSuccess.Should().BeTrue();
        KeyInfoTemplate? keyInfo = result.Value;
        _ = keyInfo.KeyVersionNumber.HasValue.Should().BeTrue();
        _ = keyInfo.KeyVersionNumber.Value.Should().Be(0x01);
        _ = keyInfo.KeyIdentifier.HasValue.Should().BeTrue();
        _ = keyInfo.KeyIdentifier.Value.Should().Be(0x00);
    }

    [Test]
    public void RoundTrip_PreservesAllData()
    {
        KeyInfoTemplate original = new KeyInfoTemplate
        {
            KeyVersionNumber = Maybe<byte>.From(0x02),
            KeyIdentifier = Maybe<byte>.From(0x01),
            KeyTypesAndLengths =
            {
                new KeyTypeAndLength { Type = 0x80, Length = 0x18 }, // 3DES, 24 bytes
                new KeyTypeAndLength { Type = 0x88, Length = 0x10 }, // AES, 16 bytes
                new KeyTypeAndLength { Type = 0x88, Length = 0x20 }, // AES, 32 bytes
            },
        };

        Result<byte[], SmartCardError> encodedResult = KeyInfoTemplateCodec.Encode(original);
        _ = encodedResult.IsSuccess.Should().BeTrue("Failed to encode KeyInfoTemplate");
        byte[]? encoded = encodedResult.Value;
        Result<KeyInfoTemplate, SmartCardError> decoded = KeyInfoTemplateCodec.Decode(encoded);

        _ = decoded.IsSuccess.Should().BeTrue();
        KeyInfoTemplate? result = decoded.Value;

        _ = result.KeyVersionNumber.Should().Be(original.KeyVersionNumber);
        _ = result.KeyIdentifier.Should().Be(original.KeyIdentifier);
        _ = result.KeyTypesAndLengths.Count.Should().Be(original.KeyTypesAndLengths.Count);

        for (int i = 0; i < original.KeyTypesAndLengths.Count; i++)
        {
            _ = result.KeyTypesAndLengths[i].Type.Should().Be(original.KeyTypesAndLengths[i].Type);
            _ = result
                .KeyTypesAndLengths[i]
                .Length.Should()
                .Be(original.KeyTypesAndLengths[i].Length);
        }
    }

    [Test]
    public void Encode_EmptyKeyInfo_ProducesMinimalStructure()
    {
        KeyInfoTemplate keyInfo = new KeyInfoTemplate();

        Result<byte[], SmartCardError> encodedResult = KeyInfoTemplateCodec.Encode(keyInfo);

        // Assert encoding succeeded
        _ = encodedResult.IsSuccess.Should().BeTrue("Failed to encode KeyInfoTemplate");
        byte[]? encoded = encodedResult.Value;

        _ = encoded.Should().NotBeEmpty();
        _ = encoded[0].Should().Be(0xE0);
        _ = encoded[1].Should().Be(0x00, "should have zero content length");
        _ = encoded.Should().HaveCount(2);
    }

    [Test]
    public void Decode_EmptyKeyInfo_ReturnsEmptyStructure()
    {
        byte[] emptyData = [0xE0, 0x00]; // Tag with zero length

        Result<KeyInfoTemplate, SmartCardError> result = KeyInfoTemplateCodec.Decode(emptyData);

        _ = result.IsSuccess.Should().BeTrue();
        KeyInfoTemplate? keyInfo = result.Value;
        _ = keyInfo.KeyVersionNumber.HasValue.Should().BeFalse();
        _ = keyInfo.KeyIdentifier.HasValue.Should().BeFalse();
        _ = keyInfo.KeyTypesAndLengths.Should().BeEmpty();
    }

    [Test]
    public void Decode_PartialKeyTypes_HandlesMissingSecondByte()
    {
        byte[] testData =
        [
            0xE0,
            0x06, // Tag and length
            0xC0,
            0x01,
            0x01, // Key version number = 1
            0xC2,
            0x01,
            0x80, // Key types with odd length (missing second byte)
        ];

        Result<KeyInfoTemplate, SmartCardError> result = KeyInfoTemplateCodec.Decode(testData);

        _ = result.IsSuccess.Should().BeTrue();
        KeyInfoTemplate? keyInfo = result.Value;
        _ = keyInfo.KeyVersionNumber.HasValue.Should().BeTrue();
        _ = keyInfo.KeyVersionNumber.Value.Should().Be(0x01);
        _ = keyInfo.KeyTypesAndLengths.Should().BeEmpty(); // Should not add incomplete pair
    }

    [Test]
    public void Encode_OnlyKeyTypes_ProducesValidStructure()
    {
        KeyInfoTemplate keyInfo = new KeyInfoTemplate
        {
            KeyTypesAndLengths =
            {
                new KeyTypeAndLength { Type = 0x88, Length = 0x20 }, // AES, 32 bytes
            },
        };

        Result<byte[], SmartCardError> encodedResult = KeyInfoTemplateCodec.Encode(keyInfo);

        // Assert encoding succeeded
        _ = encodedResult.IsSuccess.Should().BeTrue("Failed to encode KeyInfoTemplate");
        byte[]? encoded = encodedResult.Value;

        _ = encoded.Should().NotBeEmpty();
        _ = encoded[0].Should().Be(0xE0);
        _ = encoded.Should().Contain(0xC2, "should contain key types tag");
        _ = encoded.Should().NotContain(0xC0, "should not contain key version tag");
        _ = encoded.Should().NotContain(0xC1, "should not contain key identifier tag");
    }

    [Test]
    public void Decode_MalformedData_ReturnsError()
    {
        byte[] malformedData = [0xE0, 0x05, 0xC0, 0x01]; // Incomplete structure

        Result<KeyInfoTemplate, SmartCardError> result = KeyInfoTemplateCodec.Decode(malformedData);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        // The error will be from TlvParser when it can't parse the malformed TLV structure
        _ = result.Error.Message.Should().NotBeNullOrEmpty();
    }
}
