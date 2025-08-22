using System;
using AwesomeAssertions;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.CardInfo;

/// <summary>
/// Tests for KeyInformationTemplate parsing to verify E0 tag handling.
/// </summary>
[TestFixture]
[Category("Unit")]
public class KeyInfoTemplateParsingTest
{
    [Test]
    public void Parse_E012Bytes_ExtractsThreeKeys()
    {
        // From gp_pro_card_info_complete.json - actual GET DATA response without status
        // E012 = tag E0, length 12 (18 bytes)
        // C00401018810 = key 1: C0 tag, 04 length, 01 keyId, 01 version, 88 type, 10 length
        // C00402018810 = key 2: C0 tag, 04 length, 02 keyId, 01 version, 88 type, 10 length  
        // C004030188   = key 3: C0 tag, 04 length, 03 keyId, 01 version, 88 type
        var keyInfoBytes = Convert.FromHexString("E012C00401018810C00402018810C00403018810");
        
        // Parse
        var result = KeyInformationTemplate.Parse(keyInfoBytes);

        // Verify parse succeeded
        _ = result.IsSuccess.Should().BeTrue($"Parse failed: {(result.IsFailure ? result.Error.ToString() : "Unknown")}");
        
        // Verify 3 keys
        var keyInfo = result.Value;
        _ = keyInfo.Keys.Should().HaveCount(3);

        // Verify keys
        _ = keyInfo.Keys[0].KeyId.Should().Be(1);
        _ = keyInfo.Keys[0].KeyVersion.Should().Be(1);

        _ = keyInfo.Keys[1].KeyId.Should().Be(2);
        _ = keyInfo.Keys[1].KeyVersion.Should().Be(1);

        _ = keyInfo.Keys[2].KeyId.Should().Be(3);
        _ = keyInfo.Keys[2].KeyVersion.Should().Be(1);
    }
}