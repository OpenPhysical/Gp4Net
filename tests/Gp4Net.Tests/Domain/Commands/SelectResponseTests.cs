using System;
using System.Text;
using AwesomeAssertions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Tests.Domain.Commands.TestHelpers;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

[TestFixture]
[Category("Unit")]
public class SelectResponseTests
{
    [Test]
    public void Parse_WithNullData_ReturnsFailure()
    {
        var result = SelectResponse.Parse(null);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<InvalidDataError>();
        var error = (InvalidDataError)result.Error;
        _ = error.Field.Should().Be("Response");
        _ = error.Reason.Should().Be("cannot be null");
    }

    [Test]
    public void Parse_WithEmptyData_ReturnsSuccessWithNullFci()
    {
        var result = SelectResponse.Parse([]);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.RawData.Should().BeEmpty();
        _ = result.Value.Fci.Should().BeNull();
    }

    [Test]
    public void Parse_WithNonFciData_ReturnsSuccessWithNullFci()
    {
        var nonFciData = Convert.FromHexString("9F7F2A47900000");

        var result = SelectResponse.Parse(nonFciData);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.RawData.Should().BeEquivalentTo(nonFciData);
        _ = result.Value.Fci.Should().BeNull();
    }

    [Test]
    public void Parse_WithSimpleFci_ParsesCorrectly()
    {
        var fciData = Convert.FromHexString("6F108408A000000151000000A5049F6501FF");

        var result = SelectResponse.Parse(fciData);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Fci.Should().NotBeNull();
        _ = result.Value.Fci.ApplicationAid.Should().BeEquivalentTo(Convert.FromHexString("A000000151000000"));
        _ = result.Value.Fci.MaxCommandDataLength.Should().Be(255);
    }

    [Test]
    public void Parse_WithComplexFci_ParsesAllFields()
    {
        var tlvBuilder = new TlvTestBuilder();
        tlvBuilder.Add(0x6F, builder =>
        {
            builder.Add(0x84, Convert.FromHexString("A0000000030000")); // AID
            builder.Add(0x50, Encoding.UTF8.GetBytes("ISD")); // Label
            builder.Add(0x87, [0x01]); // Priority
            builder.Add(0xA5, subBuilder =>
            {
                subBuilder.Add(0x9F65, [0x01, 0x00]); // Max command length (256)
                subBuilder.Add(0x9F66, [0x02, 0x00]); // Max response length (512)
                subBuilder.Add(0x42, [0x12, 0x34]); // Issuer ID
                subBuilder.Add(0x45, [0x56, 0x78]); // Card Image
                subBuilder.Add(0x66, [0x9A, 0xBC]); // Card Data
            });
            builder.Add(0xBF0C, [0xDE, 0xF0]); // Discretionary Data
        });

        var fciData = tlvBuilder.Build();
        var result = SelectResponse.Parse(fciData);

        _ = result.IsSuccess.Should().BeTrue();
        var fci = result.Value.Fci;
        _ = fci.Should().NotBeNull();
        _ = fci.ApplicationAid.Should().BeEquivalentTo(Convert.FromHexString("A0000000030000"));
        _ = fci.ApplicationLabel.Should().Be("ISD");
        _ = fci.ApplicationPriorityIndicator.Should().Be(0x01);
        _ = fci.MaxCommandDataLength.Should().Be(256);
        _ = fci.MaxResponseDataLength.Should().Be(512);
        _ = fci.IssuerIdentificationNumber.Should().BeEquivalentTo(new byte[] { 0x12, 0x34 });
        _ = fci.CardImageNumber.Should().BeEquivalentTo(new byte[] { 0x56, 0x78 });
        _ = fci.CardData.Should().BeEquivalentTo(new byte[] { 0x9A, 0xBC });
        _ = fci.DiscretionaryData.Should().BeEquivalentTo(new byte[] { 0xDE, 0xF0 });
    }

    [Test]
    public void Parse_WithSingleByteMaxLengths_ParsesCorrectly()
    {
        var tlvBuilder = new TlvTestBuilder();
        tlvBuilder.Add(0x6F, builder =>
        {
            builder.Add(0x84, Convert.FromHexString("A000000151000000"));
            builder.Add(0xA5, subBuilder =>
            {
                subBuilder.Add(0x9F65, [0xFF]); // Single byte max command
                subBuilder.Add(0x9F66, [0x80]); // Single byte max response
            });
        });

        var fciData = tlvBuilder.Build();
        var result = SelectResponse.Parse(fciData);

        _ = result.IsSuccess.Should().BeTrue();
        var fci = result.Value.Fci;
        _ = fci.Should().NotBeNull();
        // After verifying not null, we can safely access properties
        _ = fci.MaxCommandDataLength.Should().Be(255);
        _ = fci.MaxResponseDataLength.Should().Be(128);
    }

    [Test]
    public void Parse_WithEmptyApplicationLabel_ParsesCorrectly()
    {
        var tlvBuilder = new TlvTestBuilder();
        tlvBuilder.Add(0x6F, builder =>
        {
            builder.Add(0x84, Convert.FromHexString("A000000151000000"));
            builder.Add(0x50, []); // Empty label
        });

        var fciData = tlvBuilder.Build();
        var result = SelectResponse.Parse(fciData);

        _ = result.IsSuccess.Should().BeTrue();
        var fci = result.Value.Fci;
        _ = fci.Should().NotBeNull();
        // After verifying not null, we can safely access properties
        _ = fci.ApplicationLabel.Should().Be("");
    }

    [Test]
    public void Parse_WithEmptyPriorityIndicator_HandlesGracefully()
    {
        var tlvBuilder = new TlvTestBuilder();
        tlvBuilder.Add(0x6F, builder =>
        {
            builder.Add(0x84, Convert.FromHexString("A000000151000000"));
            builder.Add(0x87, []); // Empty priority
        });

        var fciData = tlvBuilder.Build();
        var result = SelectResponse.Parse(fciData);

        _ = result.IsSuccess.Should().BeTrue();
        var fci = result.Value.Fci;
        _ = fci.Should().NotBeNull();
        // After verifying not null, we can safely access properties
        _ = fci.ApplicationPriorityIndicator.Should().BeNull();
    }

    [Test]
    public void Parse_WithPdolTag_IgnoresItGracefully()
    {
        var tlvBuilder = new TlvTestBuilder();
        tlvBuilder.Add(0x6F, builder =>
        {
            builder.Add(0x84, Convert.FromHexString("A000000151000000"));
            builder.Add(0x9F38, [0x9F, 0x66, 0x02]); // PDOL
        });

        var fciData = tlvBuilder.Build();
        var result = SelectResponse.Parse(fciData);

        _ = result.IsSuccess.Should().BeTrue();
        var fci = result.Value.Fci;
        _ = fci.Should().NotBeNull();
        // After verifying not null, we can safely access properties
        _ = fci.ApplicationAid.Should().BeEquivalentTo(Convert.FromHexString("A000000151000000"));
    }

    [Test]
    public void Parse_WithMalformedFci_ReturnsSuccessWithNullFci()
    {
        // Create intentionally malformed FCI data
        var malformedData = new byte[] { 0x6F, 0x10, 0x84, 0xFF }; // Length mismatch

        var result = SelectResponse.Parse(malformedData);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Fci.Should().BeNull();
        _ = result.Value.RawData.Should().BeEquivalentTo(malformedData);
    }

    [Test]
    public void ParseWithFci_CallsParseMethod()
    {
        var fciData = Convert.FromHexString("6F108408A000000151000000A5049F6501FF");

        var result = SelectResponse.ParseWithFci(fciData);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Fci.Should().NotBeNull();
    }

    [Test]
    public void Constructor_ClonesRawData()
    {
        var originalData = new byte[] { 0x01, 0x02, 0x03 };
        var response = new SelectResponse(originalData);

        originalData[0] = 0xFF;

        _ = response.RawData[0].Should().Be(0x01);
    }

    [Test]
    public void Constructor_WithFci_StoresBoth()
    {
        var rawData = new byte[] { 0x01, 0x02, 0x03 };
        var fci = new FileControlInformation(applicationAid: Convert.FromHexString("A000000151000000"));

        var response = new SelectResponse(rawData, fci);

        _ = response.RawData.Should().BeEquivalentTo(rawData);
        _ = response.Fci.Should().BeEquivalentTo(fci);
    }
}

[TestFixture]
public class FileControlInformationTests
{
    [Test]
    public void Constructor_WithAllParameters_StoresCorrectly()
    {
        var aid = Convert.FromHexString("A000000151000000");
        var label = "Test App";
        var priority = (byte)0x01;
        var maxCommand = (ushort)255;
        var maxResponse = (ushort)256;
        var issuerNumber = new byte[] { 0x12, 0x34 };
        var cardImage = new byte[] { 0x56, 0x78 };
        var cardData = new byte[] { 0x9A, 0xBC };
        var discretionaryData = new byte[] { 0xDE, 0xF0 };

        var fci = new FileControlInformation(
            applicationAid: aid,
            applicationLabel: label,
            applicationPriorityIndicator: priority,
            maxCommandDataLength: maxCommand,
            maxResponseDataLength: maxResponse,
            issuerIdentificationNumber: issuerNumber,
            cardImageNumber: cardImage,
            cardData: cardData,
            discretionaryData: discretionaryData
        );

        _ = fci.ApplicationAid.Should().BeEquivalentTo(aid);
        _ = fci.ApplicationLabel.Should().Be(label);
        _ = fci.ApplicationPriorityIndicator.Should().Be(priority);
        _ = fci.MaxCommandDataLength.Should().Be(maxCommand);
        _ = fci.MaxResponseDataLength.Should().Be(maxResponse);
        _ = fci.IssuerIdentificationNumber.Should().BeEquivalentTo(issuerNumber);
        _ = fci.CardImageNumber.Should().BeEquivalentTo(cardImage);
        _ = fci.CardData.Should().BeEquivalentTo(cardData);
        _ = fci.DiscretionaryData.Should().BeEquivalentTo(discretionaryData);
    }

    [Test]
    public void Constructor_WithNullParameters_HandlesCorrectly()
    {
        var fci = new FileControlInformation();

        _ = fci.ApplicationAid.Should().BeEmpty();
        _ = fci.ApplicationLabel.Should().BeNull();
        _ = fci.ApplicationPriorityIndicator.Should().BeNull();
        _ = fci.MaxCommandDataLength.Should().BeNull();
        _ = fci.MaxResponseDataLength.Should().BeNull();
        _ = fci.IssuerIdentificationNumber.Should().BeEmpty();
        _ = fci.CardImageNumber.Should().BeEmpty();
        _ = fci.CardData.Should().BeEmpty();
        _ = fci.DiscretionaryData.Should().BeEmpty();
    }

    [Test]
    public void Constructor_ClonesArrays()
    {
        var aid = Convert.FromHexString("A000000151000000");
        var issuerNumber = new byte[] { 0x12, 0x34 };
        var cardImage = new byte[] { 0x56, 0x78 };
        var cardData = new byte[] { 0x9A, 0xBC };
        var discretionaryData = new byte[] { 0xDE, 0xF0 };

        var fci = new FileControlInformation(
            applicationAid: aid,
            issuerIdentificationNumber: issuerNumber,
            cardImageNumber: cardImage,
            cardData: cardData,
            discretionaryData: discretionaryData
        );

        // Modify original arrays
        aid[0] = 0xFF;
        issuerNumber[0] = 0xFF;
        cardImage[0] = 0xFF;
        cardData[0] = 0xFF;
        discretionaryData[0] = 0xFF;

        // Verify FCI arrays are not affected
        _ = fci.ApplicationAid.Should().NotBeNull();
        // After verifying ApplicationAid is not null, we can safely access its elements
        _ = fci.ApplicationAid[0].Should().Be(0xA0);

        _ = fci.IssuerIdentificationNumber.Should().NotBeNull();
        // After verifying IssuerIdentificationNumber is not null, we can safely access its elements
        _ = fci.IssuerIdentificationNumber[0].Should().Be(0x12);

        _ = fci.CardImageNumber.Should().NotBeNull();
        // After verifying CardImageNumber is not null, we can safely access its elements
        _ = fci.CardImageNumber[0].Should().Be(0x56);

        _ = fci.CardData.Should().NotBeNull();
        // After verifying CardData is not null, we can safely access its elements
        _ = fci.CardData[0].Should().Be(0x9A);

        _ = fci.DiscretionaryData.Should().NotBeNull();
        // After verifying DiscretionaryData is not null, we can safely access its elements
        _ = fci.DiscretionaryData[0].Should().Be(0xDE);
    }

    [Test]
    public void Constructor_WithEmptyArrays_HandlesCorrectly()
    {
        var fci = new FileControlInformation(
            applicationAid: [],
            issuerIdentificationNumber: [],
            cardImageNumber: [],
            cardData: [],
            discretionaryData: []
        );

        _ = fci.ApplicationAid.Should().BeEmpty();
        _ = fci.IssuerIdentificationNumber.Should().BeEmpty();
        _ = fci.CardImageNumber.Should().BeEmpty();
        _ = fci.CardData.Should().BeEmpty();
        _ = fci.DiscretionaryData.Should().BeEmpty();
    }
}
