// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Immutable;
using AwesomeAssertions;
using Gp4Net.Domain.DataObjects;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.DataObjects;

[TestFixture]
public class KeyInfoTemplateCodecTests
{
    [Test]
    public void Should_Encode_Basic_Key_Information_Data()
    {
        // GP Card Specification v2.3.1, section 11.3.3.1.1 and Table 11-28.
        var template = new KeyInfoTemplate
        {
            Keys = [new KeyInformationData(0x01, 0x02, [new KeyTypeAndLength(0x88, 0x10)]),],
        };

        var result = KeyInfoTemplateCodec.Encode(template);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Should().Equal(Convert.FromHexString("E006C00401028810"));
    }

    [Test]
    public void Should_Decode_Multiple_C0_Objects()
    {
        // GP Card Specification v2.3.1, section 11.3.3.1.1: each key is introduced by C0.
        byte[] encoded = Convert.FromHexString("E012C00401018810C00402018810C00403018810");

        var result = KeyInfoTemplateCodec.Decode(encoded);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Keys.Should().HaveCount(3);
        _ = result.Value.Keys[1].KeyIdentifier.Should().Be(0x02);
        _ = result.Value.Keys[1].KeyVersionNumber.Should().Be(0x01);
        _ = result.Value.Keys[1].Components.Should().Equal(new KeyTypeAndLength(0x88, 0x10));
    }

    [Test]
    public void Should_Preserve_Type_And_Length_Pairs()
    {
        // GP Card Specification v2.3.1, Table 11-28: component type and length alternate.
        byte[] encoded = Convert.FromHexString("E008C006010180108820");

        var result = KeyInfoTemplateCodec.Decode(encoded);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result
            .Value.Keys[0]
            .Components.Should()
            .Equal(new KeyTypeAndLength(0x80, 0x10), new KeyTypeAndLength(0x88, 0x20));
    }

    [Test]
    public void Should_Round_Trip_Extended_Key_Information_Data()
    {
        // GP Card Specification v2.3.1, Table 11-29: FFxx types and lengths are two bytes.
        byte[] encoded = Convert.FromHexString("E00CC00A0102FF01010001AA0101");

        var decoded = KeyInfoTemplateCodec.Decode(encoded);

        _ = decoded.IsSuccess.Should().BeTrue();
        _ = decoded.Value.Keys[0].Components.Should().Equal(new KeyTypeAndLength(0xFF01, 0x0100));
        _ = decoded.Value.Keys[0].KeyUsage.Value.Should().Be(0xAA);
        _ = decoded.Value.Keys[0].KeyAccess.Value.Should().Be(0x01);
        _ = KeyInfoTemplateCodec.Encode(decoded.Value).Value.Should().Equal(encoded);
    }

    [Test]
    public void Should_Reject_Incomplete_Basic_Component()
    {
        // GP Card Specification v2.3.1, Table 11-28: every key type has a component length.
        byte[] encoded = Convert.FromHexString("E005C003010188");

        var result = KeyInfoTemplateCodec.Decode(encoded);

        _ = result.IsFailure.Should().BeTrue();
    }

    [Test]
    public void Should_Reject_Empty_Template()
    {
        // GP Card Specification v2.3.1, section 11.3.3.1.1: E0 contains C0 Key Information Data.
        var result = KeyInfoTemplateCodec.Decode([0xE0, 0x00]);

        _ = result.IsFailure.Should().BeTrue();
    }

    [Test]
    public void Should_Encode_Legacy_Single_Key_Model_As_C0()
    {
        // GP Card Specification v2.3.1, Table 11-28.
        var template = new KeyInfoTemplate
        {
            KeyIdentifier = 0x03,
            KeyVersionNumber = 0x7F,
            KeyTypesAndLengths = ImmutableArray.Create(new KeyTypeAndLength(0x88, 0x20)),
        };

        var result = KeyInfoTemplateCodec.Encode(template);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Should().Equal(Convert.FromHexString("E006C004037F8820"));
    }
}
