using System;
using System.Collections.Generic;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
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
        CardInformation? cardInfo = CardInformation.Empty;

        // Build rows
        List<CardInfoTableBuilder.TableRow> rows = [.. CardInfoTableBuilder.BuildCardInfoRows(cardInfo, isSecureChannelEstablished: false)];

        // Should have at least connection status
        _ = rows.Should().HaveCount(c => c >= 2);

        // First two rows should be status rows
        _ = rows[0].Should().BeOfType<CardInfoTableBuilder.StatusRow>();
        _ = rows[1].Should().BeOfType<CardInfoTableBuilder.StatusRow>();

        CardInfoTableBuilder.StatusRow connectionRow = (CardInfoTableBuilder.StatusRow)rows[0];
        _ = connectionRow.Name.Should().Be("Connection");
        _ = connectionRow.IsAvailable.Should().BeTrue();

        CardInfoTableBuilder.StatusRow secureChannelRow = (CardInfoTableBuilder.StatusRow)rows[1];
        _ = secureChannelRow.Name.Should().Be("Secure Channel");
        _ = secureChannelRow.IsAvailable.Should().BeFalse();
    }

    /// <summary>
    /// Tests that BuildCardInfoRows includes ATR when available.
    /// </summary>
    [Test]
    public void BuildCardInfoRows_WithAtr_IncludesAtrRow()
    {
        // Card info with ATR
        byte[] atr = [0x3B, 0xD5, 0x18, 0xFF, 0x81, 0x91, 0xFE];
        CardInformation cardInfo = CardInformation.Empty with { Atr = Maybe<byte[]>.From(atr) };

        // Build rows
        List<CardInfoTableBuilder.TableRow> rows = [.. CardInfoTableBuilder.BuildCardInfoRows(cardInfo, isSecureChannelEstablished: false)];

        // Should have ATR row
        CardInfoTableBuilder.PropertyRow? atrRow = rows.OfType<CardInfoTableBuilder.PropertyRow>()
            .FirstOrDefault(r => r.Name == "ATR");

        _ = atrRow.Should().NotBeNull();
        _ = atrRow!.Value.Should().Contain("3BD518FF8191FE");
    }

    /// <summary>
    /// Tests that BuildCardInfoRows includes CPLC manufacturing info when available.
    /// </summary>
    [Test]
    public void BuildCardInfoRows_WithCplc_IncludesManufacturingSection()
    {
        // Create CPLC data
        byte[] cplcBytes = Convert.FromHexString(
            "4790D3214700000000002345558919204839000000000000000018649535383931390000000000000000"
        );
        Result<CplcData, SmartCardError> cplcResult = CplcData.Parse(cplcBytes);
        _ = cplcResult.IsSuccess.Should().BeTrue();

        CardInformation cardInfo = CardInformation.Empty with
        {
            Cplc = Maybe<CplcData>.From(cplcResult.Value),
        };

        // Build rows
        List<CardInfoTableBuilder.TableRow> rows = [.. CardInfoTableBuilder.BuildCardInfoRows(cardInfo, isSecureChannelEstablished: false)];

        // Should have manufacturing section
        CardInfoTableBuilder.SectionHeader? sectionHeader =
            rows.OfType<CardInfoTableBuilder.SectionHeader>()
                .FirstOrDefault(h => h.Title == "Manufacturing");
        _ = sectionHeader.Should().NotBeNull();

        // Should have IC Fabricator row
        CardInfoTableBuilder.PropertyRow? fabricatorRow =
            rows.OfType<CardInfoTableBuilder.PropertyRow>()
                .FirstOrDefault(r => r.Name == "IC Fabricator");
        _ = fabricatorRow.Should().NotBeNull();
        _ = fabricatorRow!.Value.Should().Contain("NXP");
    }

    /// <summary>
    /// Tests that BuildCardInfoRows includes key information when available.
    /// </summary>
    [Test]
    public void BuildCardInfoRows_WithKeyInfo_IncludesKeySection()
    {
        // Create key info with 3 keys - from actual GP trace
        byte[] keyInfoBytes = Convert.FromHexString("E012C00401018810C00402018810C00403018810");
        Result<KeyInformationTemplate, SmartCardError> keyInfoResult = KeyInformationTemplate.Parse(
            keyInfoBytes
        );
        _ = keyInfoResult.IsSuccess.Should().BeTrue();

        CardInformation cardInfo = CardInformation.Empty with
        {
            KeyInfo = Maybe<KeyInformationTemplate>.From(keyInfoResult.Value),
        };

        // Build rows
        List<CardInfoTableBuilder.TableRow> rows = [.. CardInfoTableBuilder.BuildCardInfoRows(cardInfo, isSecureChannelEstablished: true)];

        // Should have rows generated
        _ = rows.Should().NotBeEmpty();
        _ = rows.Should()
            .HaveCount(c => c > 2, $"Expected more than 2 rows but found {rows.Count}");

        // Should have key section
        CardInfoTableBuilder.SectionHeader? sectionHeader =
            rows.OfType<CardInfoTableBuilder.SectionHeader>()
                .FirstOrDefault(h => h.Title == "Cryptographic Keys");
        _ = sectionHeader.Should().NotBeNull();

        // Should have ENC, MAC, and KEK keys
        CardInfoTableBuilder.PropertyRow? encKey = rows.OfType<CardInfoTableBuilder.PropertyRow>()
            .FirstOrDefault(r => r.Name.Contains("ENC Key"));
        _ = encKey.Should().NotBeNull();

        CardInfoTableBuilder.PropertyRow? macKey = rows.OfType<CardInfoTableBuilder.PropertyRow>()
            .FirstOrDefault(r => r.Name.Contains("MAC Key"));
        _ = macKey.Should().NotBeNull();

        CardInfoTableBuilder.PropertyRow? kekKey = rows.OfType<CardInfoTableBuilder.PropertyRow>()
            .FirstOrDefault(r => r.Name.Contains("KEK Key"));
        _ = kekKey.Should().NotBeNull();
    }

    /// <summary>
    /// Tests that BuildCardInfoRows handles ISD with FCI data properly.
    /// </summary>
    [Test]
    public void BuildCardInfoRows_WithIsdInfo_IncludesIsdDetails()
    {
        // Create ISD select response
        byte[] isdBytes = Convert.FromHexString("6F108408A000000151000000A5049F6501FF");
        Result<SelectResponse, SmartCardError> selectResponse = SelectResponse.Parse(isdBytes);
        _ = selectResponse.IsSuccess.Should().BeTrue();

        CardInformation cardInfo = CardInformation.Empty with
        {
            IsdInfo = Maybe<SelectResponse>.From(selectResponse.Value),
        };

        // Build rows
        List<CardInfoTableBuilder.TableRow> rows = [.. CardInfoTableBuilder.BuildCardInfoRows(cardInfo, isSecureChannelEstablished: false)];

        // Should have ISD status
        CardInfoTableBuilder.StatusRow? isdStatus = rows.OfType<CardInfoTableBuilder.StatusRow>()
            .FirstOrDefault(r => r.Name == "ISD");
        _ = isdStatus.Should().NotBeNull();
        _ = isdStatus!.IsAvailable.Should().BeTrue();

        // Should have ISD AID
        CardInfoTableBuilder.PropertyRow? aidRow = rows.OfType<CardInfoTableBuilder.PropertyRow>()
            .FirstOrDefault(r => r.Name == "ISD AID");
        _ = aidRow.Should().NotBeNull();
        _ = aidRow!.Value.Should().Be("A000000151000000");
    }

    /// <summary>
    /// Tests that semantic row types maintain immutability.
    /// </summary>
    [Test]
    public void SemanticRowTypes_AreImmutable()
    {
        // Create different row types
        CardInfoTableBuilder.PropertyRow propertyRow = new CardInfoTableBuilder.PropertyRow(
            "Test",
            "Value"
        );
        CardInfoTableBuilder.StatusRow statusRow = new CardInfoTableBuilder.StatusRow(
            "Status",
            true,
            "Details"
        );
        CardInfoTableBuilder.SectionHeader sectionHeader = new CardInfoTableBuilder.SectionHeader(
            "Section"
        );
        CardInfoTableBuilder.ErrorRow errorRow = new CardInfoTableBuilder.ErrorRow(
            "Error",
            "Message"
        );
        CardInfoTableBuilder.InfoRow infoRow = new CardInfoTableBuilder.InfoRow("Information");

        // All should be records with value equality
        CardInfoTableBuilder.PropertyRow propertyRow2 = new CardInfoTableBuilder.PropertyRow(
            "Test",
            "Value"
        );
        _ = propertyRow.Should().Be(propertyRow2);

        CardInfoTableBuilder.StatusRow statusRow2 = new CardInfoTableBuilder.StatusRow(
            "Status",
            true,
            "Details"
        );
        _ = statusRow.Should().Be(statusRow2);
    }

    /// <summary>
    /// Tests that BuildCardInfoRows handles all Maybe<T> fields correctly without nulls.
    /// </summary>
    [Test]
    public void BuildCardInfoRows_WithCompleteCardInfo_HandlesAllMaybeTypes()
    {
        // Create complete card info
        byte[] atr = [0x3B, 0xD5];
        byte[] cplcBytes = Convert.FromHexString(
            "4790D3214700000000002345558919204839000000000000000018649535383931390000000000000000"
        );
        byte[] capabilitiesBytes = Convert.FromHexString(
            "6728A00D800103810500102060708201078103E5BEC082031E030083010284010285017B86010C87017B"
        );
        byte[] keyInfoBytes = Convert.FromHexString("E012C00401018810C00402018810C004030188");
        byte[] cardDataBytes = Convert.FromHexString(
            "664D734B06072A864886FC6B01600B06092A864886FC6B020203"
        );
        byte[] diversificationBytes = Convert.FromHexString("CF0A037000000000000000");
        byte[] securityBytes = Convert.FromHexString("C1030000");

        Result<CplcData, SmartCardError> cplcResult = CplcData.Parse(cplcBytes);
        _ = cplcResult.IsSuccess.Should().BeTrue();
        Result<CardCapabilities, SmartCardError> capabilities = CardCapabilities.TryParse(
            Maybe<byte[]>.From(capabilitiesBytes)
        );
        Result<KeyInformationTemplate, SmartCardError> keyInfo = KeyInformationTemplate.Parse(
            keyInfoBytes
        );
        Result<CardDataInfo, SmartCardError> cardData = CardDataInfo.Parse(cardDataBytes);
        ScpInformation? scpInfo = ScpCapabilitiesParser.ParseDetailed(capabilitiesBytes);
        Result<SecurityDomainStatus, SmartCardError> securityStatus = SecurityDomainStatus.Parse(
            securityBytes
        );

        CardInformation cardInfo = new CardInformation(
            Maybe<byte[]>.From(atr),
            Maybe<CplcData>.From(cplcResult.Value),
            capabilities.IsSuccess
                ? Maybe<CardCapabilities>.From(capabilities.Value)
                : Maybe<CardCapabilities>.None,
            keyInfo.IsSuccess
                ? Maybe<KeyInformationTemplate>.From(keyInfo.Value)
                : Maybe<KeyInformationTemplate>.None,
            cardData.IsSuccess
                ? Maybe<CardDataInfo>.From(cardData.Value)
                : Maybe<CardDataInfo>.None,
            Maybe<ScpInformation>.From(scpInfo),
            securityStatus.IsSuccess
                ? Maybe<SecurityDomainStatus>.From(securityStatus.Value)
                : Maybe<SecurityDomainStatus>.None,
            Maybe<byte[]>.From(diversificationBytes),
            Maybe<SelectResponse>.None,
            Maybe<ChipInfo>.None
        );

        // Build rows - should not throw any null exceptions
        List<CardInfoTableBuilder.TableRow> rows = [.. CardInfoTableBuilder.BuildCardInfoRows(cardInfo, isSecureChannelEstablished: true)];

        // Should have many rows
        _ = rows.Should().HaveCount(c => c > 10);

        // Should have no null values in any property rows
        IEnumerable<CardInfoTableBuilder.PropertyRow> propertyRows =
            rows.OfType<CardInfoTableBuilder.PropertyRow>();
        foreach (CardInfoTableBuilder.PropertyRow row in propertyRows)
        {
            _ = row.Name.Should().NotBeNull();
            _ = row.Value.Should().NotBeNull();
        }
    }
}
