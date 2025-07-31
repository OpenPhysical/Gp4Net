// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using FluentAssertions;
using Gp4Net.Domain.DataObjects;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.DataObjects
{
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
                LifeCycleData = Convert.FromHexString("07")
            };

            var encoded = SecurityDomainInfoCodec.Encode(sdInfo);

            encoded.Should().NotBeEmpty();
            encoded[0].Should().Be(0xC1, "first byte should be tag 0xC1");
            encoded[1].Should().BeGreaterThan(0, "length should be positive");
            
            // Should contain OID tag sequence
            encoded.Should().Contain(0x9F, "should contain first byte of OID tag");
            encoded.Should().Contain(0x70, "should contain second byte of OID tag");
            
            // Should contain image data tag
            encoded.Should().Contain(0xC5, "should contain image data tag");
            
            // Should contain lifecycle data tag
            encoded.Should().Contain(0xC4, "should contain lifecycle data tag");
        }

        [Test]
        public void Encode_MinimalSecurityDomainInfo_ProducesValidFormat()
        {
            var sdInfo = new SecurityDomainInfo
            {
                Oid = Convert.FromHexString("A000000151")
            };

            var encoded = SecurityDomainInfoCodec.Encode(sdInfo);

            encoded.Should().NotBeEmpty();
            encoded[0].Should().Be(0xC1);
            encoded.Should().Contain(0x9F, "should contain OID tag");
            encoded.Should().Contain(0x70, "should contain OID tag");
            encoded.Should().NotContain(0xC5, "should not contain image data tag");
            encoded.Should().NotContain(0xC4, "should not contain lifecycle data tag");
        }

        [Test]
        public void Decode_ValidSecurityDomainInfo_ReturnsCorrectStructure()
        {
            var testData = new byte[]
            {
                0xC1, 0x15, // Tag and length
                0x9F, 0x70, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, // OID
                0xC5, 0x03, 0x01, 0x02, 0x03, // Image data
                0xC4, 0x01, 0x07 // Lifecycle data
            };

            var result = SecurityDomainInfoCodec.Decode(testData);

            result.IsSuccess.Should().BeTrue();
            var sdInfo = result.Value;
            
            sdInfo.Oid.Should().Equal(Convert.FromHexString("A000000151000000"));
            sdInfo.ImageData.Should().Equal(new byte[] { 0x01, 0x02, 0x03 });
            sdInfo.LifeCycleData.Should().Equal(new byte[] { 0x07 });
        }

        [Test]
        public void Decode_WithSecurityDomainAid_ParsesCorrectly()
        {
            var testData = new byte[]
            {
                0xC1, 0x0E, // Tag and length
                0x9F, 0x70, 0x05, 0xA0, 0x00, 0x00, 0x01, 0x51, // OID
                0x4F, 0x05, 0xA0, 0x00, 0x00, 0x01, 0x51 // Security Domain AID
            };

            var result = SecurityDomainInfoCodec.Decode(testData);

            result.IsSuccess.Should().BeTrue();
            var sdInfo = result.Value;
            
            sdInfo.Oid.Should().Equal(Convert.FromHexString("A000000151"));
            sdInfo.SecurityDomainAid.Should().NotBeNull();
            sdInfo.SecurityDomainAid[0].Should().Be(0x4F, "should preserve tag");
            sdInfo.SecurityDomainAid[1].Should().Be(0x05, "should preserve length");
        }

        [Test]
        public void Decode_InvalidTag_ReturnsError()
        {
            var invalidData = new byte[] { 0xC2, 0x03, 0x01, 0x02, 0x03 }; // Wrong tag

            var result = SecurityDomainInfoCodec.Decode(invalidData);

            result.IsFailure.Should().BeTrue();
            result.Error.Code.Should().Be("INVALID_DATA");
        }

        [Test]
        public void Decode_ExtendedLength_HandlesCorrectly()
        {
            var testData = new byte[]
            {
                0xC1, 0x81, 0x08, // Tag with extended length (8 bytes content)
                0x9F, 0x70, 0x05, 0xA0, 0x00, 0x00, 0x01, 0x51 // OID only
            };

            var result = SecurityDomainInfoCodec.Decode(testData);

            result.IsSuccess.Should().BeTrue();
            var sdInfo = result.Value;
            sdInfo.Oid.Should().Equal(Convert.FromHexString("A000000151"));
        }

        [Test]
        public void RoundTrip_PreservesAllData()
        {
            var original = new SecurityDomainInfo
            {
                Oid = Convert.FromHexString("A000000151000000"),
                SecurityDomainAid = Convert.FromHexString("4F08A000000151000000"),
                ImageData = Convert.FromHexString("010203040506070809"),
                LifeCycleData = Convert.FromHexString("0F")
            };

            var encoded = SecurityDomainInfoCodec.Encode(original);
            var decoded = SecurityDomainInfoCodec.Decode(encoded);

            decoded.IsSuccess.Should().BeTrue();
            var result = decoded.Value;
            
            result.Oid.Should().Equal(original.Oid);
            result.SecurityDomainAid.Should().Equal(original.SecurityDomainAid);
            result.ImageData.Should().Equal(original.ImageData);
            result.LifeCycleData.Should().Equal(original.LifeCycleData);
        }

        [Test]
        public void Encode_EmptySecurityDomainInfo_ProducesMinimalStructure()
        {
            var sdInfo = new SecurityDomainInfo();

            var encoded = SecurityDomainInfoCodec.Encode(sdInfo);

            encoded.Should().NotBeEmpty();
            encoded[0].Should().Be(0xC1);
            encoded[1].Should().Be(0x00, "should have zero content length");
            encoded.Should().HaveCount(2);
        }

        [Test]
        public void Decode_EmptySecurityDomainInfo_ReturnsEmptyStructure()
        {
            var emptyData = new byte[] { 0xC1, 0x00 }; // Tag with zero length

            var result = SecurityDomainInfoCodec.Decode(emptyData);

            result.IsSuccess.Should().BeTrue();
            var sdInfo = result.Value;
            sdInfo.Oid.Should().BeNull();
            sdInfo.SecurityDomainAid.Should().BeNull();
            sdInfo.ImageData.Should().BeNull();
            sdInfo.LifeCycleData.Should().BeNull();
        }

        [Test]
        public void Decode_OnlyOid_ParsesCorrectly()
        {
            var testData = new byte[]
            {
                0xC1, 0x08, // Tag and length
                0x9F, 0x70, 0x05, 0xA0, 0x00, 0x00, 0x01, 0x51 // OID only
            };

            var result = SecurityDomainInfoCodec.Decode(testData);

            result.IsSuccess.Should().BeTrue();
            var sdInfo = result.Value;
            
            sdInfo.Oid.Should().Equal(Convert.FromHexString("A000000151"));
            sdInfo.SecurityDomainAid.Should().BeNull();
            sdInfo.ImageData.Should().BeNull();
            sdInfo.LifeCycleData.Should().BeNull();
        }

        [Test]
        public void Decode_MalformedOidTag_HandlesGracefully()
        {
            var testData = new byte[]
            {
                0xC1, 0x05, // Tag and length
                0x9F, 0x70, 0x05 // Incomplete OID (missing data)
            };

            var result = SecurityDomainInfoCodec.Decode(testData);

            result.IsSuccess.Should().BeTrue();
            var sdInfo = result.Value;
            sdInfo.Oid.Should().BeNull(); // Should not set incomplete OID
        }

        [Test]
        public void Encode_OnlyImageData_ProducesValidStructure()
        {
            var sdInfo = new SecurityDomainInfo
            {
                ImageData = Convert.FromHexString("ABCDEF")
            };

            var encoded = SecurityDomainInfoCodec.Encode(sdInfo);

            encoded.Should().NotBeEmpty();
            encoded[0].Should().Be(0xC1);
            encoded.Should().Contain(0xC5, "should contain image data tag");
            encoded.Should().NotContain(0x9F, "should not contain OID tag");
            encoded.Should().NotContain(0xC4, "should not contain lifecycle data tag");
        }

        [Test]
        public void Decode_UnknownTags_IgnoresGracefully()
        {
            var testData = new byte[]
            {
                0xC1, 0x0D, // Tag and length
                0x9F, 0x70, 0x05, 0xA0, 0x00, 0x00, 0x01, 0x51, // OID
                0xC6, 0x02, 0xFF, 0xFE // Unknown tag with data
            };

            var result = SecurityDomainInfoCodec.Decode(testData);

            result.IsSuccess.Should().BeTrue();
            var sdInfo = result.Value;
            sdInfo.Oid.Should().Equal(Convert.FromHexString("A000000151"));
            // Unknown tag should be handled as potential AID data
            sdInfo.SecurityDomainAid.Should().NotBeNull();
        }
    }
}