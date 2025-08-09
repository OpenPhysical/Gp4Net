using System;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Tool.Commands.Card;
using NUnit.Framework;

namespace Gp4Net.Tests.Tool.Commands.Card;

/// <summary>
/// Tests for the pure functional CardInfoTableBuilder.
/// Verifies semantic row type creation and functional composition patterns.
/// </summary>
[TestFixture]
[Category("Unit")]
public class CardInfoTableBuilderTests
{
    /// <summary>
    /// Tests that BuildCardInfoRows creates proper semantic row types.
    /// </summary>
    [Test]
    public void BuildCardInfoRows_EmptyCardInfo_ReturnsMinimalRows()
    {
        // Empty card information
        var cardInfo = CardInformation.Empty;

        // Build rows
        var rows = CardInfoTableBuilder.BuildCardInfoRows(cardInfo, isSecureChannelEstablished: false).ToList();

        // Should have at least connection status
        rows.Should().HaveCount(c => c >= 2);
        
        // First two rows should be status rows
        rows[0].Should().BeOfType<CardInfoTableBuilder.StatusRow>();
        rows[1].Should().BeOfType<CardInfoTableBuilder.StatusRow>();
        
        var connectionRow = (CardInfoTableBuilder.StatusRow)rows[0];
        connectionRow.Name.Should().Be("Connection");
        connectionRow.IsAvailable.Should().BeTrue();
        
        var secureChannelRow = (CardInfoTableBuilder.StatusRow)rows[1];
        secureChannelRow.Name.Should().Be("Secure Channel");
        secureChannelRow.IsAvailable.Should().BeFalse();
    }

    /// <summary>
    /// Tests that BuildCardInfoRows includes ATR when available.
    /// </summary>
    [Test]
    public void BuildCardInfoRows_WithAtr_IncludesAtrRow()
    {
        // Card info with ATR
        var atr = new byte[] { 0x3B, 0xD5, 0x18, 0xFF, 0x81, 0x91, 0xFE };
        var cardInfo = CardInformation.Empty with { Atr = Maybe<byte[]>.From(atr) };

        // Build rows
        var rows = CardInfoTableBuilder.BuildCardInfoRows(cardInfo, isSecureChannelEstablished: false).ToList();

        // Should have ATR row
        var atrRow = rows.OfType<CardInfoTableBuilder.PropertyRow>()
            .FirstOrDefault(r => r.Name == "ATR");
        
        atrRow.Should().NotBeNull();
        atrRow!.Value.Should().Contain("3BD518FF8191FE");
    }

    /// <summary>
    /// Tests that BuildCardInfoRows includes CPLC manufacturing info when available.
    /// </summary>
    [Test]
    public void BuildCardInfoRows_WithCplc_IncludesManufacturingSection()
    {
        // Create CPLC data
        var cplcBytes = Convert.FromHexString("4790D3214700000000002345558919204839000000000000000018649535383931390000000000000000");
        var cplcResult = CplcData.Parse(cplcBytes);
        cplcResult.IsSuccess.Should().BeTrue();
        
        var cardInfo = CardInformation.Empty with { Cplc = Maybe<CplcData>.From(cplcResult.Value) };

        // Build rows
        var rows = CardInfoTableBuilder.BuildCardInfoRows(cardInfo, isSecureChannelEstablished: false).ToList();

        // Should have manufacturing section
        var sectionHeader = rows.OfType<CardInfoTableBuilder.SectionHeader>()
            .FirstOrDefault(h => h.Title == "Manufacturing");
        sectionHeader.Should().NotBeNull();

        // Should have IC Fabricator row
        var fabricatorRow = rows.OfType<CardInfoTableBuilder.PropertyRow>()
            .FirstOrDefault(r => r.Name == "IC Fabricator");
        fabricatorRow.Should().NotBeNull();
        fabricatorRow!.Value.Should().Contain("NXP");
    }

    /// <summary>
    /// Tests that BuildCardInfoRows includes key information when available.
    /// </summary>
    [Test]
    public void BuildCardInfoRows_WithKeyInfo_IncludesKeySection()
    {
        // Create key info with 3 keys - from actual GP trace
        var keyInfoBytes = Convert.FromHexString("E012C00401018810C00402018810C00403018810");
        var keyInfoResult = KeyInformationTemplate.Parse(keyInfoBytes);
        keyInfoResult.IsSuccess.Should().BeTrue();
        
        var cardInfo = CardInformation.Empty with { KeyInfo = Maybe<KeyInformationTemplate>.From(keyInfoResult.Value) };

        // Build rows
        var rows = CardInfoTableBuilder.BuildCardInfoRows(cardInfo, isSecureChannelEstablished: true).ToList();
        
        // Should have rows generated
        rows.Should().NotBeEmpty();
        rows.Should().HaveCount(c => c > 2, $"Expected more than 2 rows but found {rows.Count}");

        // Should have key section
        var sectionHeader = rows.OfType<CardInfoTableBuilder.SectionHeader>()
            .FirstOrDefault(h => h.Title == "Cryptographic Keys");
        sectionHeader.Should().NotBeNull();

        // Should have ENC, MAC, and KEK keys
        var encKey = rows.OfType<CardInfoTableBuilder.PropertyRow>()
            .FirstOrDefault(r => r.Name.Contains("ENC Key"));
        encKey.Should().NotBeNull();

        var macKey = rows.OfType<CardInfoTableBuilder.PropertyRow>()
            .FirstOrDefault(r => r.Name.Contains("MAC Key"));
        macKey.Should().NotBeNull();

        var kekKey = rows.OfType<CardInfoTableBuilder.PropertyRow>()
            .FirstOrDefault(r => r.Name.Contains("KEK Key"));
        kekKey.Should().NotBeNull();
    }

    /// <summary>
    /// Tests that BuildCardInfoRows handles ISD with FCI data properly.
    /// </summary>
    [Test]
    public void BuildCardInfoRows_WithIsdInfo_IncludesIsdDetails()
    {
        // Create ISD select response
        var isdBytes = Convert.FromHexString("6F108408A000000151000000A5049F6501FF");
        var selectResponse = SelectResponse.Parse(isdBytes);
        selectResponse.IsSuccess.Should().BeTrue();
        
        var cardInfo = CardInformation.Empty with { IsdInfo = Maybe<SelectResponse>.From(selectResponse.Value) };

        // Build rows
        var rows = CardInfoTableBuilder.BuildCardInfoRows(cardInfo, isSecureChannelEstablished: false).ToList();

        // Should have ISD status
        var isdStatus = rows.OfType<CardInfoTableBuilder.StatusRow>()
            .FirstOrDefault(r => r.Name == "ISD");
        isdStatus.Should().NotBeNull();
        isdStatus!.IsAvailable.Should().BeTrue();

        // Should have ISD AID
        var aidRow = rows.OfType<CardInfoTableBuilder.PropertyRow>()
            .FirstOrDefault(r => r.Name == "ISD AID");
        aidRow.Should().NotBeNull();
        aidRow!.Value.Should().Be("A000000151000000");
    }

    /// <summary>
    /// Tests that semantic row types maintain immutability.
    /// </summary>
    [Test]
    public void SemanticRowTypes_AreImmutable()
    {
        // Create different row types
        var propertyRow = new CardInfoTableBuilder.PropertyRow("Test", "Value");
        var statusRow = new CardInfoTableBuilder.StatusRow("Status", true, "Details");
        var sectionHeader = new CardInfoTableBuilder.SectionHeader("Section");
        var errorRow = new CardInfoTableBuilder.ErrorRow("Error", "Message");
        var infoRow = new CardInfoTableBuilder.InfoRow("Information");

        // All should be records with value equality
        var propertyRow2 = new CardInfoTableBuilder.PropertyRow("Test", "Value");
        propertyRow.Should().Be(propertyRow2);

        var statusRow2 = new CardInfoTableBuilder.StatusRow("Status", true, "Details");
        statusRow.Should().Be(statusRow2);
    }

    /// <summary>
    /// Tests that BuildCardInfoRows handles all Maybe<T> fields correctly without nulls.
    /// </summary>
    [Test]
    public void BuildCardInfoRows_WithCompleteCardInfo_HandlesAllMaybeTypes()
    {
        // Create complete card info
        var atr = new byte[] { 0x3B, 0xD5 };
        var cplcBytes = Convert.FromHexString("4790D3214700000000002345558919204839000000000000000018649535383931390000000000000000");
        var capabilitiesBytes = Convert.FromHexString("6728A00D800103810500102060708201078103E5BEC082031E030083010284010285017B86010C87017B");
        var keyInfoBytes = Convert.FromHexString("E012C00401018810C00402018810C004030188");
        var cardDataBytes = Convert.FromHexString("664D734B06072A864886FC6B01600B06092A864886FC6B020203");
        var diversificationBytes = Convert.FromHexString("CF0A037000000000000000");
        var securityBytes = Convert.FromHexString("C1030000");
        
        var cplcResult = CplcData.Parse(cplcBytes);
        cplcResult.IsSuccess.Should().BeTrue();
        var capabilities = CardCapabilities.TryParse(Maybe<byte[]>.From(capabilitiesBytes));
        var keyInfo = KeyInformationTemplate.Parse(keyInfoBytes);
        var cardData = CardDataInfo.Parse(cardDataBytes);
        var scpInfo = ScpCapabilitiesParser.ParseDetailed(capabilitiesBytes);
        var securityStatus = SecurityDomainStatus.Parse(securityBytes);
        
        var cardInfo = new CardInformation(
            Maybe<byte[]>.From(atr),
            Maybe<CplcData>.From(cplcResult.Value),
            capabilities.IsSuccess ? Maybe<CardCapabilities>.From(capabilities.Value) : Maybe<CardCapabilities>.None,
            keyInfo.IsSuccess ? Maybe<KeyInformationTemplate>.From(keyInfo.Value) : Maybe<KeyInformationTemplate>.None,
            cardData.IsSuccess ? Maybe<CardDataInfo>.From(cardData.Value) : Maybe<CardDataInfo>.None,
            Maybe<ScpInformation>.From(scpInfo),
            securityStatus.IsSuccess ? Maybe<SecurityDomainStatus>.From(securityStatus.Value) : Maybe<SecurityDomainStatus>.None,
            Maybe<byte[]>.From(diversificationBytes),
            Maybe<SelectResponse>.None,
            Maybe<ChipInfo>.None
        );

        // Build rows - should not throw any null exceptions
        var rows = CardInfoTableBuilder.BuildCardInfoRows(cardInfo, isSecureChannelEstablished: true).ToList();

        // Should have many rows
        rows.Should().HaveCount(c => c > 10);
        
        // Should have no null values in any property rows
        var propertyRows = rows.OfType<CardInfoTableBuilder.PropertyRow>();
        foreach (var row in propertyRows)
        {
            row.Name.Should().NotBeNull();
            row.Value.Should().NotBeNull();
        }
    }
}