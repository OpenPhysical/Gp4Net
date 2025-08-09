// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using AwesomeAssertions;
using Gp4Net.Core;
using Gp4Net.Domain.DataObjects;
using NUnit.Framework;
using CSharpFunctionalExtensions;

namespace Gp4Net.Tests.Domain.DataObjects;

[TestFixture]
public class KeyInfoTemplateCodecTests
{
    [Test]
    public void Encode_CompleteKeyInfo_ProducesExpectedFormat()
    {
        var keyInfo = new KeyInfoTemplate
        {
            KeyVersionNumber = 0x01,
            KeyIdentifier = 0x00,
            KeyTypesAndLengths =
            {
                new KeyTypeAndLength { Type = 0x80, Length = 0x10 }, // DES, 16 bytes
                new KeyTypeAndLength { Type = 0x81, Length = 0x10 }, // DES-ECB, 16 bytes
                new KeyTypeAndLength { Type = 0x82, Length = 0x10 }  // DES-MAC, 16 bytes
            }
        };

        var encodedResult = KeyInfoTemplateCodec.Encode(keyInfo);
        
        // Assert encoding succeeded
        encodedResult.IsSuccess.Should().BeTrue("Failed to encode KeyInfoTemplate");
        var encoded = encodedResult.Value;

        encoded.Should().NotBeEmpty();
        encoded[0].Should().Be(0xE0, "first byte should be tag 0xE0");
        encoded[1].Should().BeGreaterThan(0, "length should be positive");

        // Should contain all three component tags
        encoded.Should().Contain(0xC0, "should contain key version tag");
        encoded.Should().Contain(0xC1, "should contain key identifier tag");
        encoded.Should().Contain(0xC2, "should contain key types tag");
    }

    [Test]
    public void Encode_MinimalKeyInfo_ProducesValidFormat()
    {
        var keyInfo = new KeyInfoTemplate
        {
            KeyVersionNumber = 0x01
        };

        var encodedResult = KeyInfoTemplateCodec.Encode(keyInfo);
        
        // Assert encoding succeeded
        encodedResult.IsSuccess.Should().BeTrue("Failed to encode KeyInfoTemplate");
        var encoded = encodedResult.Value;

        encoded.Should().NotBeEmpty();
        encoded[0].Should().Be(0xE0);
        encoded.Should().Contain(0xC0, "should contain key version tag");
        encoded.Should().NotContain(0xC1, "should not contain key identifier tag");
        encoded.Should().NotContain(0xC2, "should not contain key types tag");
    }

    [Test]
    public void Decode_ValidKeyInfoTemplate_ReturnsCorrectStructure()
    {
        var testData = new byte[]
        {
            0xE0, 0x0C, // Tag and length (fixed: 12 bytes, not 11)
            0xC0, 0x01, 0x01, // Key version number = 1
            0xC1, 0x01, 0x00, // Key identifier = 0
            0xC2, 0x04, 0x80, 0x10, 0x81, 0x10 // Two key types: DES 16 bytes each
        };

        var result = KeyInfoTemplateCodec.Decode(testData);

        result.IsSuccess.Should().BeTrue();
        var keyInfo = result.Value;

        keyInfo.KeyVersionNumber.HasValue.Should().BeTrue();
        keyInfo.KeyVersionNumber.Value.Should().Be(0x01);
        keyInfo.KeyIdentifier.HasValue.Should().BeTrue();
        keyInfo.KeyIdentifier.Value.Should().Be(0x00);
        keyInfo.KeyTypesAndLengths.Should().HaveCount(2);

        var firstKeyType = keyInfo.KeyTypesAndLengths[0];
        firstKeyType.Type.Should().Be(0x80);
        firstKeyType.Length.Should().Be(0x10);

        var secondKeyType = keyInfo.KeyTypesAndLengths[1];
        secondKeyType.Type.Should().Be(0x81);
        secondKeyType.Length.Should().Be(0x10);
    }

    [Test]
    public void Decode_InvalidTag_ReturnsError()
    {
        var invalidData = new byte[] { 0xE1, 0x03, 0xC0, 0x01, 0x01 }; // Wrong tag

        var result = KeyInfoTemplateCodec.Decode(invalidData);

        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<SmartCardError>();
        result.Error.Code.Should().Be("INVALID_DATA");
        result.Error.Message.Should().Contain("Invalid key information template format - expected tag 0xE0");
    }

    [Test]
    public void Decode_ExtendedLength_HandlesCorrectly()
    {
        var testData = new byte[]
        {
            0xE0, 0x81, 0x06, // Tag with extended length (6 bytes content)
            0xC0, 0x01, 0x01, // Key version number = 1
            0xC1, 0x01, 0x00  // Key identifier = 0
        };

        var result = KeyInfoTemplateCodec.Decode(testData);

        result.IsSuccess.Should().BeTrue();
        var keyInfo = result.Value;
        keyInfo.KeyVersionNumber.HasValue.Should().BeTrue();
        keyInfo.KeyVersionNumber.Value.Should().Be(0x01);
        keyInfo.KeyIdentifier.HasValue.Should().BeTrue();
        keyInfo.KeyIdentifier.Value.Should().Be(0x00);
    }

    [Test]
    public void RoundTrip_PreservesAllData()
    {
        var original = new KeyInfoTemplate
        {
            KeyVersionNumber = Maybe<byte>.From(0x02),
            KeyIdentifier = Maybe<byte>.From(0x01),
            KeyTypesAndLengths =
            {
                new KeyTypeAndLength { Type = 0x80, Length = 0x18 }, // 3DES, 24 bytes
                new KeyTypeAndLength { Type = 0x88, Length = 0x10 }, // AES, 16 bytes
                new KeyTypeAndLength { Type = 0x88, Length = 0x20 }, // AES, 32 bytes
            }
        };

        var encodedResult = KeyInfoTemplateCodec.Encode(original);
        encodedResult.IsSuccess.Should().BeTrue("Failed to encode KeyInfoTemplate");
        var encoded = encodedResult.Value;
        var decoded = KeyInfoTemplateCodec.Decode(encoded);

        decoded.IsSuccess.Should().BeTrue();
        var result = decoded.Value;

        result.KeyVersionNumber.Should().Be(original.KeyVersionNumber);
        result.KeyIdentifier.Should().Be(original.KeyIdentifier);
        result.KeyTypesAndLengths.Count.Should().Be(original.KeyTypesAndLengths.Count);

        for (int i = 0; i < original.KeyTypesAndLengths.Count; i++)
        {
            result.KeyTypesAndLengths[i].Type.Should().Be(original.KeyTypesAndLengths[i].Type);
            result.KeyTypesAndLengths[i].Length.Should().Be(original.KeyTypesAndLengths[i].Length);
        }
    }

    [Test]
    public void Encode_EmptyKeyInfo_ProducesMinimalStructure()
    {
        var keyInfo = new KeyInfoTemplate();

        var encodedResult = KeyInfoTemplateCodec.Encode(keyInfo);
        
        // Assert encoding succeeded
        encodedResult.IsSuccess.Should().BeTrue("Failed to encode KeyInfoTemplate");
        var encoded = encodedResult.Value;

        encoded.Should().NotBeEmpty();
        encoded[0].Should().Be(0xE0);
        encoded[1].Should().Be(0x00, "should have zero content length");
        encoded.Should().HaveCount(2);
    }

    [Test]
    public void Decode_EmptyKeyInfo_ReturnsEmptyStructure()
    {
        var emptyData = new byte[] { 0xE0, 0x00 }; // Tag with zero length

        var result = KeyInfoTemplateCodec.Decode(emptyData);

        result.IsSuccess.Should().BeTrue();
        var keyInfo = result.Value;
        keyInfo.KeyVersionNumber.HasValue.Should().BeFalse();
        keyInfo.KeyIdentifier.HasValue.Should().BeFalse();
        keyInfo.KeyTypesAndLengths.Should().BeEmpty();
    }

    [Test]
    public void Decode_PartialKeyTypes_HandlesMissingSecondByte()
    {
        var testData = new byte[]
        {
            0xE0, 0x06, // Tag and length
            0xC0, 0x01, 0x01, // Key version number = 1
            0xC2, 0x01, 0x80 // Key types with odd length (missing second byte)
        };

        var result = KeyInfoTemplateCodec.Decode(testData);

        result.IsSuccess.Should().BeTrue();
        var keyInfo = result.Value;
        keyInfo.KeyVersionNumber.HasValue.Should().BeTrue();
        keyInfo.KeyVersionNumber.Value.Should().Be(0x01);
        keyInfo.KeyTypesAndLengths.Should().BeEmpty(); // Should not add incomplete pair
    }

    [Test]
    public void Encode_OnlyKeyTypes_ProducesValidStructure()
    {
        var keyInfo = new KeyInfoTemplate
        {
            KeyTypesAndLengths =
            {
                new KeyTypeAndLength { Type = 0x88, Length = 0x20 } // AES, 32 bytes
            }
        };

        var encodedResult = KeyInfoTemplateCodec.Encode(keyInfo);
        
        // Assert encoding succeeded
        encodedResult.IsSuccess.Should().BeTrue("Failed to encode KeyInfoTemplate");
        var encoded = encodedResult.Value;

        encoded.Should().NotBeEmpty();
        encoded[0].Should().Be(0xE0);
        encoded.Should().Contain(0xC2, "should contain key types tag");
        encoded.Should().NotContain(0xC0, "should not contain key version tag");
        encoded.Should().NotContain(0xC1, "should not contain key identifier tag");
    }

    [Test]
    public void Decode_MalformedData_ReturnsError()
    {
        var malformedData = new byte[] { 0xE0, 0x05, 0xC0, 0x01 }; // Incomplete structure

        var result = KeyInfoTemplateCodec.Decode(malformedData);

        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<SmartCardError>();
        // The error will be from TlvParser when it can't parse the malformed TLV structure
        result.Error.Message.Should().NotBeNullOrEmpty();
    }
}
