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

        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<InvalidDataError>();
        var error = (InvalidDataError)result.Error;
        error.Field.Should().Be("Response");
        error.Reason.Should().Be("cannot be null");
    }

    [Test]
    public void Parse_WithEmptyData_ReturnsSuccessWithNullFci()
    {
        var result = SelectResponse.Parse([]);

        result.IsSuccess.Should().BeTrue();
        result.Value.RawData.Should().BeEmpty();
        result.Value.Fci.Should().BeNull();
    }

    [Test]
    public void Parse_WithNonFciData_ReturnsSuccessWithNullFci()
    {
        var nonFciData = Convert.FromHexString("9F7F2A47900000");

        var result = SelectResponse.Parse(nonFciData);

        result.IsSuccess.Should().BeTrue();
        result.Value.RawData.Should().BeEquivalentTo(nonFciData);
        result.Value.Fci.Should().BeNull();
    }

    [Test]
    public void Parse_WithSimpleFci_ParsesCorrectly()
    {
        var fciData = Convert.FromHexString("6F108408A000000151000000A5049F6501FF");

        var result = SelectResponse.Parse(fciData);

        result.IsSuccess.Should().BeTrue();
        result.Value.Fci.Should().NotBeNull();
        result.Value.Fci.ApplicationAid.Should().BeEquivalentTo(Convert.FromHexString("A000000151000000"));
        result.Value.Fci.MaxCommandDataLength.Should().Be(255);
    }

    [Test]
    public void Parse_WithComplexFci_ParsesAllFields()
    {
        var tlvBuilder = new TlvTestBuilder();
        tlvBuilder.Add(0x6F, builder =>
        {
            builder.Add(0x84, Convert.FromHexString("A0000000030000")); // AID
            builder.Add(0x50, Encoding.UTF8.GetBytes("ISD")); // Label
            builder.Add(0x87, new byte[] { 0x01 }); // Priority
            builder.Add(0xA5, subBuilder =>
            {
                subBuilder.Add(0x9F65, new byte[] { 0x01, 0x00 }); // Max command length (256)
                subBuilder.Add(0x9F66, new byte[] { 0x02, 0x00 }); // Max response length (512)
                subBuilder.Add(0x42, new byte[] { 0x12, 0x34 }); // Issuer ID
                subBuilder.Add(0x45, new byte[] { 0x56, 0x78 }); // Card Image
                subBuilder.Add(0x66, new byte[] { 0x9A, 0xBC }); // Card Data
            });
            builder.Add(0xBF0C, new byte[] { 0xDE, 0xF0 }); // Discretionary Data
        });

        var fciData = tlvBuilder.Build();
        var result = SelectResponse.Parse(fciData);

        result.IsSuccess.Should().BeTrue();
        var fci = result.Value.Fci;
        fci.Should().NotBeNull();
        fci.ApplicationAid.Should().BeEquivalentTo(Convert.FromHexString("A0000000030000"));
        fci.ApplicationLabel.Should().Be("ISD");
        fci.ApplicationPriorityIndicator.Should().Be(0x01);
        fci.MaxCommandDataLength.Should().Be(256);
        fci.MaxResponseDataLength.Should().Be(512);
        fci.IssuerIdentificationNumber.Should().BeEquivalentTo(new byte[] { 0x12, 0x34 });
        fci.CardImageNumber.Should().BeEquivalentTo(new byte[] { 0x56, 0x78 });
        fci.CardData.Should().BeEquivalentTo(new byte[] { 0x9A, 0xBC });
        fci.DiscretionaryData.Should().BeEquivalentTo(new byte[] { 0xDE, 0xF0 });
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
                subBuilder.Add(0x9F65, new byte[] { 0xFF }); // Single byte max command
                subBuilder.Add(0x9F66, new byte[] { 0x80 }); // Single byte max response
            });
        });

        var fciData = tlvBuilder.Build();
        var result = SelectResponse.Parse(fciData);

        result.IsSuccess.Should().BeTrue();
        var fci = result.Value.Fci;
        fci.Should().NotBeNull();
        // After verifying not null, we can safely access properties
        fci.MaxCommandDataLength.Should().Be(255);
        fci.MaxResponseDataLength.Should().Be(128);
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

        result.IsSuccess.Should().BeTrue();
        var fci = result.Value.Fci;
        fci.Should().NotBeNull();
        // After verifying not null, we can safely access properties
        fci.ApplicationLabel.Should().Be("");
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

        result.IsSuccess.Should().BeTrue();
        var fci = result.Value.Fci;
        fci.Should().NotBeNull();
        // After verifying not null, we can safely access properties
        fci.ApplicationPriorityIndicator.Should().BeNull();
    }

    [Test]
    public void Parse_WithPdolTag_IgnoresItGracefully()
    {
        var tlvBuilder = new TlvTestBuilder();
        tlvBuilder.Add(0x6F, builder =>
        {
            builder.Add(0x84, Convert.FromHexString("A000000151000000"));
            builder.Add(0x9F38, new byte[] { 0x9F, 0x66, 0x02 }); // PDOL
        });

        var fciData = tlvBuilder.Build();
        var result = SelectResponse.Parse(fciData);

        result.IsSuccess.Should().BeTrue();
        var fci = result.Value.Fci;
        fci.Should().NotBeNull();
        // After verifying not null, we can safely access properties
        fci.ApplicationAid.Should().BeEquivalentTo(Convert.FromHexString("A000000151000000"));
    }

    [Test]
    public void Parse_WithMalformedFci_ReturnsSuccessWithNullFci()
    {
        // Create intentionally malformed FCI data
        var malformedData = new byte[] { 0x6F, 0x10, 0x84, 0xFF }; // Length mismatch

        var result = SelectResponse.Parse(malformedData);

        result.IsSuccess.Should().BeTrue();
        result.Value.Fci.Should().BeNull();
        result.Value.RawData.Should().BeEquivalentTo(malformedData);
    }

    [Test]
    public void ParseWithFci_CallsParseMethod()
    {
        var fciData = Convert.FromHexString("6F108408A000000151000000A5049F6501FF");

        var result = SelectResponse.ParseWithFci(fciData);

        result.IsSuccess.Should().BeTrue();
        result.Value.Fci.Should().NotBeNull();
    }

    [Test]
    public void Constructor_ClonesRawData()
    {
        var originalData = new byte[] { 0x01, 0x02, 0x03 };
        var response = new SelectResponse(originalData);

        originalData[0] = 0xFF;

        response.RawData[0].Should().Be(0x01);
    }

    [Test]
    public void Constructor_WithFci_StoresBoth()
    {
        var rawData = new byte[] { 0x01, 0x02, 0x03 };
        var fci = new FileControlInformation(applicationAid: Convert.FromHexString("A000000151000000"));

        var response = new SelectResponse(rawData, fci);

        response.RawData.Should().BeEquivalentTo(rawData);
        response.Fci.Should().BeEquivalentTo(fci);
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

        fci.ApplicationAid.Should().BeEquivalentTo(aid);
        fci.ApplicationLabel.Should().Be(label);
        fci.ApplicationPriorityIndicator.Should().Be(priority);
        fci.MaxCommandDataLength.Should().Be(maxCommand);
        fci.MaxResponseDataLength.Should().Be(maxResponse);
        fci.IssuerIdentificationNumber.Should().BeEquivalentTo(issuerNumber);
        fci.CardImageNumber.Should().BeEquivalentTo(cardImage);
        fci.CardData.Should().BeEquivalentTo(cardData);
        fci.DiscretionaryData.Should().BeEquivalentTo(discretionaryData);
    }

    [Test]
    public void Constructor_WithNullParameters_HandlesCorrectly()
    {
        var fci = new FileControlInformation();

        fci.ApplicationAid.Should().BeEmpty();
        fci.ApplicationLabel.Should().BeNull();
        fci.ApplicationPriorityIndicator.Should().BeNull();
        fci.MaxCommandDataLength.Should().BeNull();
        fci.MaxResponseDataLength.Should().BeNull();
        fci.IssuerIdentificationNumber.Should().BeEmpty();
        fci.CardImageNumber.Should().BeEmpty();
        fci.CardData.Should().BeEmpty();
        fci.DiscretionaryData.Should().BeEmpty();
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
        fci.ApplicationAid.Should().NotBeNull();
        // After verifying ApplicationAid is not null, we can safely access its elements
        fci.ApplicationAid[0].Should().Be(0xA0);
        
        fci.IssuerIdentificationNumber.Should().NotBeNull();
        // After verifying IssuerIdentificationNumber is not null, we can safely access its elements
        fci.IssuerIdentificationNumber[0].Should().Be(0x12);
        
        fci.CardImageNumber.Should().NotBeNull();
        // After verifying CardImageNumber is not null, we can safely access its elements
        fci.CardImageNumber[0].Should().Be(0x56);
        
        fci.CardData.Should().NotBeNull();
        // After verifying CardData is not null, we can safely access its elements
        fci.CardData[0].Should().Be(0x9A);
        
        fci.DiscretionaryData.Should().NotBeNull();
        // After verifying DiscretionaryData is not null, we can safely access its elements
        fci.DiscretionaryData[0].Should().Be(0xDE);
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

        fci.ApplicationAid.Should().BeEmpty();
        fci.IssuerIdentificationNumber.Should().BeEmpty();
        fci.CardImageNumber.Should().BeEmpty();
        fci.CardData.Should().BeEmpty();
        fci.DiscretionaryData.Should().BeEmpty();
    }
}
