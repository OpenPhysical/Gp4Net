// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.DataObjects;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Integration tests for card discovery capabilities using real GET DATA responses from traces.
/// These tests validate that our domain codecs can properly parse and understand
/// real card data structures from P71 and other card types.
/// </summary>
[TestFixture]
[Category("Integration")]
public class CardDiscoveryCapabilityTests
{
    /// <summary>
    /// Real GET DATA responses extracted from P71 card traces.
    /// These represent actual card behavior and data structures.
    /// </summary>
    public static class P71CardResponses
    {
        // GET DATA 0x0066 (Card Data) - Contains card manager and supported protocols information
        public static readonly byte[] CardData_0x0066 = Convert.FromHexString("664D734B06072A864886FC6B01600B06092A864886FC6B020203630906072A864886FC6B03640B06092A864886FC6B040370650D060B2A864886FC6B0507020000660C060A2B060104012A026E0103");

        // GET DATA 0x0067 (Card Capabilities) - Contains card capabilities and supported algorithms
        public static readonly byte[] CardCapabilities_0x0067 = Convert.FromHexString("6728A00D800103810500102060708201078103E5BEC082031E030083010284010285017B86010C87017B");

        // GET DATA 0x00C1 (Security Domain Info) - Contains security domain information
        public static readonly byte[] SecurityDomainInfo_0x00C1_P71_Key01 = Convert.FromHexString("C103000001");
        public static readonly byte[] SecurityDomainInfo_0x00C1_P71_Key19 = Convert.FromHexString("C103000019");

        // GET DATA 0x00E0 (Key Information Template) - Contains key information
        public static readonly byte[] KeyInfoTemplate_0x00E0 = Convert.FromHexString("E012C00401018810C00402018810C00403018810");

        // Alternative card with different capabilities (from gp_pro_list_success.txt)
        public static readonly byte[] CardCapabilities_Alternative = Convert.FromHexString("6724A0098001028104153555758103E5BEC082031E030083010284010285017B86010C87017B");
        public static readonly byte[] SecurityDomainInfo_Alternative = Convert.FromHexString("C1020000");
        public static readonly byte[] KeyInfoTemplate_Alternative = Convert.FromHexString("E012C00401018010C00402018010C00403018010");
    }

    [Test]
    public void CardData_P71_ParsesCorrectly()
    {
        // Test that we can parse Card Data (0x0066) from real P71 card
        // This data contains OIDs for supported card manager and protocols

        var cardData = P71CardResponses.CardData_0x0066;

        // Basic structure validation
        _ = cardData[0].Should().Be(0x66, "Card Data should start with tag 0x66");
        _ = cardData[1].Should().Be(0x4D, "Length should be 0x4D (77 bytes)");

        // The actual structure starts with tag 0x73 (card configuration details)
        // which contains nested OID structures
        _ = cardData[2].Should().Be(0x73, "Card Data contains configuration details tag");
        _ = cardData[3].Should().Be(0x4B, "Configuration details length should be 0x4B (75 bytes)");

        // Within the configuration details, we should find the GlobalPlatform OID
        // Structure: 73 4B 06 07 2A864886FC6B01 ...
        var configDetailsStart = 4; // After tag 0x73 and length 0x4B
        _ = cardData[configDetailsStart].Should().Be(0x06, "Should contain OID tag");
        _ = cardData[configDetailsStart + 1].Should().Be(0x07, "OID length should be 7");

        var gpCardManagerOid = new ArraySegment<byte>(cardData, configDetailsStart + 2, 7).ToArray();
        var expectedGpOid = new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01 };
        _ = gpCardManagerOid.Should().BeEquivalentTo(expectedGpOid,
            "Should contain GlobalPlatform Card Manager OID");
    }

    [Test]
    public void CardCapabilities_P71_ParsesWithCodec()
    {
        // Test parsing real P71 card capabilities data (tag 0x0067)
        // This data uses the format expected by CardCapabilities.Parse, not CardCapabilitiesCodec
        var capabilitiesData = P71CardResponses.CardCapabilities_0x0067;

        // Strip the tag and length bytes (0x67 0x28) to get the raw capabilities data
        var rawData = capabilitiesData.Skip(2).ToArray();

        // Use CardCapabilities.Parse which expects the format with tags 0xA0, 0x81, etc.
        var result = Gp4Net.Domain.CardInfo.CardCapabilities.TryParse(Maybe<byte[]>.From(rawData));

        _ = result.IsSuccess.Should().BeTrue("P71 capabilities should parse successfully");

        if (result.IsSuccess)
        {
            var capabilities = result.Value;
            _ = capabilities.Should().NotBeNull("Decoded capabilities should not be null");

            // Verify the parsed SCP options
            _ = capabilities.ScpOptions.Should().NotBeEmpty("P71 should have SCP options");
            _ = capabilities.SupportsScp03.Should().BeTrue("P71 should support SCP03");

            // Real P71 structure: 67 28 A0 0D 80010381050010206070820107 81 03 E5BEC0 ...
            // Tag A0 (length 0D) contains SCP information: 800103 (SCP02) 81050010206070820107 (SCP03)
            // This shows the card supports both SCP02 (0x02) and SCP03 (0x03) protocols
        }
    }

    [Test]
    public void SecurityDomainInfo_P71_ParsesWithCodec()
    {
        // Test SecurityDomainInfoCodec against both P71 configurations
        var sdInfo1 = SecurityDomainInfoCodec.Decode(P71CardResponses.SecurityDomainInfo_0x00C1_P71_Key01);
        var sdInfo2 = SecurityDomainInfoCodec.Decode(P71CardResponses.SecurityDomainInfo_0x00C1_P71_Key19);

        _ = sdInfo1.IsSuccess.Should().BeTrue("P71 Security Domain Info (key 01) should decode");
        _ = sdInfo2.IsSuccess.Should().BeTrue("P71 Security Domain Info (key 19) should decode");

        // C103000001 = Security Domain with key version 01
        // C103000019 = Security Domain with key version 19 (0x13 in hex)
        _ = sdInfo1.Value.Should().NotBeNull();
        _ = sdInfo2.Value.Should().NotBeNull();
    }

    [Test]
    public void KeyInfoTemplate_P71_ParsesWithCodec()
    {
        // Test KeyInfoTemplateCodec against real P71 key information
        var keyInfoData = P71CardResponses.KeyInfoTemplate_0x00E0;

        var result = KeyInfoTemplateCodec.Decode(keyInfoData);

        _ = result.IsSuccess.Should().BeTrue("P71 Key Info Template should decode successfully");

        var keyInfo = result.Value;
        _ = keyInfo.Should().NotBeNull("Decoded key info should not be null");

        // E012 = Key Info Template with length 0x12 (18 bytes)
        // Contains 3 key entries: C00401018810, C00402018810, C00403018810
        // Each represents a key with different usage (ENC, MAC, DEK)
    }

    [Test]
    public void CardCapabilities_CompareVariants_ShowsDifferences()
    {
        // Compare P71 capabilities with alternative card using the correct parser
        // Strip tag and length bytes before parsing
        var p71RawData = P71CardResponses.CardCapabilities_0x0067.Skip(2).ToArray();
        var altRawData = P71CardResponses.CardCapabilities_Alternative.Skip(2).ToArray();

        var p71Result = Gp4Net.Domain.CardInfo.CardCapabilities.TryParse(Maybe<byte[]>.From(p71RawData));
        var altResult = Gp4Net.Domain.CardInfo.CardCapabilities.TryParse(Maybe<byte[]>.From(altRawData));

        _ = p71Result.IsSuccess.Should().BeTrue("P71 capabilities should decode");
        _ = altResult.IsSuccess.Should().BeTrue("Alternative capabilities should decode");

        // The two cards have different capability structures
        // P71: 6728A00D800103810500102060708201078103E5BEC082031E030083010284010285017B86010C87017B
        // Alt: 6724A0098001028104153555758103E5BEC082031E030083010284010285017B86010C87017B

        // Length difference: 0x28 (40) vs 0x24 (36) - P71 has more capabilities
        _ = P71CardResponses.CardCapabilities_0x0067[1].Should().Be(0x28, "P71 should have 40 bytes of capabilities");
        _ = P71CardResponses.CardCapabilities_Alternative[1].Should().Be(0x24, "Alternative should have 36 bytes");
    }

    [Test]
    public void CardDiscovery_UnsupportedFeatures_HandledGracefully()
    {
        // Test that unsupported GET DATA commands (returning 6982) are handled properly
        // This simulates the gp_pro_bad_key_list.txt trace where many GET DATA commands fail

        var unsupportedStatus = new byte[] { 0x69, 0x82 }; // Command not allowed / function not supported

        // Our codecs should handle empty responses gracefully
        var emptyData = Array.Empty<byte>();

        // Test that parsers return appropriate failures for empty/invalid data
        var cardCapResult = Gp4Net.Domain.CardInfo.CardCapabilities.TryParse(Maybe<byte[]>.From(emptyData));
        var sdInfoResult = SecurityDomainInfoCodec.Decode(emptyData);
        var keyInfoResult = KeyInfoTemplateCodec.Decode(emptyData);

        _ = cardCapResult.IsFailure.Should().BeTrue("Empty card capabilities data should fail to decode");
        _ = sdInfoResult.IsFailure.Should().BeTrue("Empty security domain info should fail to decode");
        _ = keyInfoResult.IsFailure.Should().BeTrue("Empty key info template should fail to decode");
    }

    [Test]
    public void CardDiscovery_RealWorldScenario_DetectsCardType()
    {
        // Integration test that simulates real card discovery workflow
        // Using the data from gp_pro_card_info.txt trace

        // Step 1: Parse card capabilities to determine supported protocols
        var capabilitiesRawData = P71CardResponses.CardCapabilities_0x0067.Skip(2).ToArray();
        var capabilitiesResult = Gp4Net.Domain.CardInfo.CardCapabilities.TryParse(Maybe<byte[]>.From(capabilitiesRawData));
        _ = capabilitiesResult.IsSuccess.Should().BeTrue("Card capabilities should be parseable");

        // Step 2: Parse security domain info to get key version information
        var sdInfoResult = SecurityDomainInfoCodec.Decode(P71CardResponses.SecurityDomainInfo_0x00C1_P71_Key19);
        _ = sdInfoResult.IsSuccess.Should().BeTrue("Security domain info should be parseable");

        // Step 3: Parse key information to understand key structure
        var keyInfoResult = KeyInfoTemplateCodec.Decode(P71CardResponses.KeyInfoTemplate_0x00E0);
        _ = keyInfoResult.IsSuccess.Should().BeTrue("Key info template should be parseable");

        // Step 4: Validate that all parsing succeeded (real P71 card supports all these features)
        var allParsingSucceeded = capabilitiesResult.IsSuccess &&
                                  sdInfoResult.IsSuccess &&
                                  keyInfoResult.IsSuccess;

        _ = allParsingSucceeded.Should().BeTrue("P71 card should support full discovery workflow");
    }

    [Test]
    public void CardData_OidParsing_IdentifiesProtocolSupport()
    {
        // Detailed analysis of Card Data OID structures
        var cardData = P71CardResponses.CardData_0x0066;

        // Structure: 66 4D 73 4B 06 07 2A864886FC6B01 60 0B 06 09 2A864886FC6B020203 ...
        // 66 = Card Data tag
        // 4D = Length (77 bytes)
        // 73 4B = Card configuration details tag and length
        // 06 07 2A864886FC6B01 = GlobalPlatform Card Manager OID
        // 60 0B = Context tag with length
        // 06 09 2A864886FC6B020203 = GP 2.2.1 Application OID

        var offset = 4; // Skip 66 4D 73 4B

        // First OID: GlobalPlatform Card Manager
        _ = cardData[offset].Should().Be(0x06, "Should be OID tag");
        _ = cardData[offset + 1].Should().Be(0x07, "OID length should be 7");

        var gpCardManagerOid = new ArraySegment<byte>(cardData, offset + 2, 7).ToArray();
        var expectedGpOid = new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01 };
        _ = gpCardManagerOid.Should().BeEquivalentTo(expectedGpOid,
            "Should contain GlobalPlatform Card Manager OID");

        // Second structure at offset 13: 60 0B (context tag)
        var contextTagOffset = offset + 9; // After first OID
        _ = cardData[contextTagOffset].Should().Be(0x60, "Should be context tag");
        _ = cardData[contextTagOffset + 1].Should().Be(0x0B, "Context length should be 0x0B");

        // Third OID within context: 06 09 2A864886FC6B020203 (GP 2.2.1)
        var secondOidOffset = contextTagOffset + 2;
        _ = cardData[secondOidOffset].Should().Be(0x06, "Should be second OID tag");
        _ = cardData[secondOidOffset + 1].Should().Be(0x09, "Second OID length should be 9");
    }
}
