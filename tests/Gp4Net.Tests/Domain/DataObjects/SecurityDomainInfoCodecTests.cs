// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.DataObjects;
using Gp4Net.Tests.Infrastructure;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.DataObjects;

[TestFixture]
public class SecurityDomainInfoCodecTests
{
    [Test]
    public void Encode_CompleteSecurityDomainInfo_ProducesExpectedFormat()
    {
        var sdInfo = new SecurityDomainInfo
        {
            Oid = Convert.FromHexString("A000000151000000"), // GP OID
            SecurityDomainAid = Convert.FromHexString("4F08A000000151000000"), // AID with length
            ImageData = Convert.FromHexString("0102030405"),
            LifeCycleData = Convert.FromHexString("07"),
        };

        Result<byte[], SmartCardError> encodedResult = SecurityDomainInfoCodec.Encode(sdInfo);

        // Assert encoding succeeded
        _ = encodedResult.IsSuccess.Should().BeTrue("Failed to encode SecurityDomainInfo");
        byte[]? encoded = encodedResult.Value;

        _ = encoded.Should().NotBeEmpty();
        _ = encoded[0].Should().Be(0xC1, "first byte should be tag 0xC1");
        _ = encoded[1].Should().BeGreaterThan(0, "length should be positive");

        // Should contain OID tag sequence
        _ = encoded.Should().Contain(0x9F, "should contain first byte of OID tag");
        _ = encoded.Should().Contain(0x70, "should contain second byte of OID tag");

        // Should contain image data tag
        _ = encoded.Should().Contain(0xC5, "should contain image data tag");

        // Should contain lifecycle data tag
        _ = encoded.Should().Contain(0xC4, "should contain lifecycle data tag");
    }

    [Test]
    public void Encode_MinimalSecurityDomainInfo_ProducesValidFormat()
    {
        var sdInfo = new SecurityDomainInfo { Oid = Convert.FromHexString("A000000151") };

        Result<byte[], SmartCardError> encodedResult = SecurityDomainInfoCodec.Encode(sdInfo);

        // Assert encoding succeeded
        _ = encodedResult.IsSuccess.Should().BeTrue("Failed to encode SecurityDomainInfo");
        byte[]? encoded = encodedResult.Value;

        _ = encoded.Should().NotBeEmpty();
        _ = encoded[0].Should().Be(0xC1);
        _ = encoded.Should().Contain(0x9F, "should contain OID tag");
        _ = encoded.Should().Contain(0x70, "should contain OID tag");
        _ = encoded.Should().NotContain(0xC5, "should not contain image data tag");
        _ = encoded.Should().NotContain(0xC4, "should not contain lifecycle data tag");
    }

    [Test]
    public void Decode_ValidSecurityDomainInfo_ReturnsCorrectStructure()
    {
        byte[] testData =
        [
            0xC1,
            0x13, // Tag and length (19 bytes)
            0x9F,
            0x70,
            0x08,
            0xA0,
            0x00,
            0x00,
            0x01,
            0x51,
            0x00,
            0x00,
            0x00, // OID
            0xC5,
            0x03,
            0x01,
            0x02,
            0x03, // Image data
            0xC4,
            0x01,
            0x07, // Lifecycle data
        ];

        Result<SecurityDomainInfo, SmartCardError> result = SecurityDomainInfoCodec.Decode(
            testData
        );

        _ = result.IsSuccess.Should().BeTrue();
        var sdInfo = result.Value;

        _ = sdInfo.Oid.Should().HaveValue(Convert.FromHexString("A000000151000000"));
        _ = sdInfo.ImageData.Should().HaveValue([0x01, 0x02, 0x03]);
        _ = sdInfo.LifeCycleData.Should().HaveValue([0x07]);
    }

    [Test]
    public void Decode_WithSecurityDomainAid_ParsesCorrectly()
    {
        byte[] testData =
        [
            0xC1,
            0x0F, // Tag and length (15 bytes)
            0x9F,
            0x70,
            0x05,
            0xA0,
            0x00,
            0x00,
            0x01,
            0x51, // OID
            0x4F,
            0x05,
            0xA0,
            0x00,
            0x00,
            0x01,
            0x51, // Security Domain AID
        ];

        Result<SecurityDomainInfo, SmartCardError> result = SecurityDomainInfoCodec.Decode(
            testData
        );

        _ = result.IsSuccess.Should().BeTrue();
        if (result.IsSuccess)
        {
            var sdInfo = result.Value;

            _ = sdInfo
                .Oid.Should()
                .HaveValue()
                .And.TheValue.Should()
                .BeEquivalentTo(Convert.FromHexString("A000000151"));
            _ = sdInfo.SecurityDomainAid.Should().HaveValue();

            sdInfo.SecurityDomainAid.Map(aidData =>
            {
                _ = aidData[0].Should().Be(0x4F, "should preserve tag");
                _ = aidData[1].Should().Be(0x05, "should preserve length");
                return aidData;
            });
        }
    }

    [Test]
    public void Decode_InvalidTag_ReturnsError()
    {
        byte[] invalidData = [0xC2, 0x03, 0x01, 0x02, 0x03]; // Wrong tag

        Result<SecurityDomainInfo, SmartCardError> result = SecurityDomainInfoCodec.Decode(
            invalidData
        );

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Code.Should().Be("INVALID_DATA");
        _ = result
            .Error.Message.Should()
            .Contain("Invalid security domain information format - expected tag 0xC1");
    }

    [Test]
    public void Decode_ExtendedLength_HandlesCorrectly()
    {
        byte[] testData =
        [
            0xC1,
            0x81,
            0x08, // Tag with extended length (8 bytes content)
            0x9F,
            0x70,
            0x05,
            0xA0,
            0x00,
            0x00,
            0x01,
            0x51, // OID only
        ];

        Result<SecurityDomainInfo, SmartCardError> result = SecurityDomainInfoCodec.Decode(
            testData
        );

        _ = result.IsSuccess.Should().BeTrue();
        var sdInfo = result.Value;
        _ = sdInfo
            .Oid.Should()
            .HaveValue()
            .And.TheValue.Should()
            .BeEquivalentTo(Convert.FromHexString("A000000151"));
    }

    [Test]
    public void RoundTrip_PreservesAllData()
    {
        var original = new SecurityDomainInfo
        {
            Oid = Maybe<byte[]>.From(Convert.FromHexString("A000000151000000")),
            SecurityDomainAid = Maybe<byte[]>.From(Convert.FromHexString("4F08A000000151000000")),
            ImageData = Maybe<byte[]>.From(Convert.FromHexString("010203040506070809")),
            LifeCycleData = Maybe<byte[]>.From(Convert.FromHexString("0F")),
        };

        Result<byte[], SmartCardError> encodedResult = SecurityDomainInfoCodec.Encode(original);
        _ = encodedResult.IsSuccess.Should().BeTrue("Failed to encode SecurityDomainInfo");
        byte[]? encoded = encodedResult.Value;
        Result<SecurityDomainInfo, SmartCardError> decoded = SecurityDomainInfoCodec.Decode(
            encoded
        );

        _ = decoded.IsSuccess.Should().BeTrue();
        var result = decoded.Value;

        original.Oid.Match(
            oid => _ = result.Oid.Should().HaveValue(oid),
            () => _ = result.Oid.Should().HaveNoValue()
        );
        original.SecurityDomainAid.Match(
            aid => _ = result.SecurityDomainAid.Should().HaveValue(aid),
            () => _ = result.SecurityDomainAid.Should().HaveNoValue()
        );
        original.ImageData.Match(
            data => _ = result.ImageData.Should().HaveValue(data),
            () => _ = result.ImageData.Should().HaveNoValue()
        );
        original.LifeCycleData.Match(
            data => _ = result.LifeCycleData.Should().HaveValue(data),
            () => _ = result.LifeCycleData.Should().HaveNoValue()
        );
    }

    [Test]
    public void Encode_EmptySecurityDomainInfo_ProducesMinimalStructure()
    {
        var sdInfo = new SecurityDomainInfo();

        Result<byte[], SmartCardError> encodedResult = SecurityDomainInfoCodec.Encode(sdInfo);

        // Assert encoding succeeded
        _ = encodedResult.IsSuccess.Should().BeTrue("Failed to encode SecurityDomainInfo");
        byte[]? encoded = encodedResult.Value;

        _ = encoded.Should().NotBeEmpty();
        _ = encoded[0].Should().Be(0xC1);
        _ = encoded[1].Should().Be(0x00, "should have zero content length");
        _ = encoded.Should().HaveCount(2);
    }

    [Test]
    public void Decode_EmptySecurityDomainInfo_ReturnsEmptyStructure()
    {
        byte[] emptyData = [0xC1, 0x00]; // Tag with zero length

        Result<SecurityDomainInfo, SmartCardError> result = SecurityDomainInfoCodec.Decode(
            emptyData
        );

        _ = result.IsSuccess.Should().BeTrue();
        var sdInfo = result.Value;
        _ = sdInfo.Oid.Should().HaveNoValue();
        _ = sdInfo.SecurityDomainAid.Should().HaveNoValue();
        _ = sdInfo.ImageData.Should().HaveNoValue();
        _ = sdInfo.LifeCycleData.Should().HaveNoValue();
    }

    [Test]
    public void Decode_OnlyOid_ParsesCorrectly()
    {
        byte[] testData =
        [
            0xC1,
            0x08, // Tag and length
            0x9F,
            0x70,
            0x05,
            0xA0,
            0x00,
            0x00,
            0x01,
            0x51, // OID only
        ];

        Result<SecurityDomainInfo, SmartCardError> result = SecurityDomainInfoCodec.Decode(
            testData
        );

        _ = result.IsSuccess.Should().BeTrue();
        var sdInfo = result.Value;

        _ = sdInfo
            .Oid.Should()
            .HaveValue()
            .And.TheValue.Should()
            .BeEquivalentTo(Convert.FromHexString("A000000151"));
        _ = sdInfo.SecurityDomainAid.Should().HaveNoValue();
        _ = sdInfo.ImageData.Should().HaveNoValue();
        _ = sdInfo.LifeCycleData.Should().HaveNoValue();
    }

    [Test]
    public void Decode_MalformedOidTag_HandlesGracefully()
    {
        byte[] testData =
        [
            0xC1,
            0x03, // Tag and length (3 bytes)
            0x9F,
            0x70,
            0x00, // OID with zero length
        ];

        Result<SecurityDomainInfo, SmartCardError> result = SecurityDomainInfoCodec.Decode(
            testData
        );

        _ = result.IsSuccess.Should().BeTrue();
        var sdInfo = result.Value;
        _ = sdInfo.Oid.Should().HaveNoValue(); // Should not set zero-length OID
    }

    [Test]
    public void Encode_OnlyImageData_ProducesValidStructure()
    {
        var sdInfo = new SecurityDomainInfo { ImageData = Convert.FromHexString("ABCDEF") };

        Result<byte[], SmartCardError> encodedResult = SecurityDomainInfoCodec.Encode(sdInfo);

        // Assert encoding succeeded
        _ = encodedResult.IsSuccess.Should().BeTrue("Failed to encode SecurityDomainInfo");
        byte[]? encoded = encodedResult.Value;

        _ = encoded.Should().NotBeEmpty();
        _ = encoded[0].Should().Be(0xC1);
        _ = encoded.Should().Contain(0xC5, "should contain image data tag");
        _ = encoded.Should().NotContain(0x9F, "should not contain OID tag");
        _ = encoded.Should().NotContain(0xC4, "should not contain lifecycle data tag");
    }

    [Test]
    public void Decode_UnknownTags_IgnoresGracefully()
    {
        byte[] testData =
        [
            0xC1,
            0x0C, // Tag and length (12 bytes)
            0x9F,
            0x70,
            0x05,
            0xA0,
            0x00,
            0x00,
            0x01,
            0x51, // OID
            0xC6,
            0x02,
            0xFF,
            0xFE, // Unknown tag with data
        ];

        Result<SecurityDomainInfo, SmartCardError> result = SecurityDomainInfoCodec.Decode(
            testData
        );

        _ = result.IsSuccess.Should().BeTrue();
        var sdInfo = result.Value;
        _ = sdInfo
            .Oid.Should()
            .HaveValue()
            .And.TheValue.Should()
            .BeEquivalentTo(Convert.FromHexString("A000000151"));
        // Unknown tag should be handled as potential AID data
        _ = sdInfo.SecurityDomainAid.Should().HaveValue();
    }
}
