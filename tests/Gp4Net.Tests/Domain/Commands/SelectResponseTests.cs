using System;
using System.Linq;
using System.Text;
using Gp4Net.Core;
using Gp4Net.Core.Tlv;
using Gp4Net.Domain.Commands;
using Gp4Net.Tests.Domain.Commands.TestHelpers;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands
{
    [TestFixture]
    public class SelectResponseTests
    {
        [Test]
        public void Parse_WithNullData_ReturnsFailure()
        {
            var result = SelectResponse.Parse(null);

            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Code, Is.EqualTo("INVALID_DATA"));
            Assert.That(result.Error.Message, Does.Contain("Response data cannot be null"));
        }

        [Test]
        public void Parse_WithEmptyData_ReturnsSuccessWithNullFci()
        {
            var result = SelectResponse.Parse(Array.Empty<byte>());

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.RawData, Is.Empty);
            Assert.That(result.Value.Fci, Is.Null);
        }

        [Test]
        public void Parse_WithNonFciData_ReturnsSuccessWithNullFci()
        {
            var nonFciData = Convert.FromHexString("9F7F2A47900000");

            var result = SelectResponse.Parse(nonFciData);

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.RawData, Is.EqualTo(nonFciData));
            Assert.That(result.Value.Fci, Is.Null);
        }

        [Test]
        public void Parse_WithSimpleFci_ParsesCorrectly()
        {
            var fciData = Convert.FromHexString("6F108408A000000151000000A5049F6501FF");

            var result = SelectResponse.Parse(fciData);

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Fci, Is.Not.Null);
            Assert.That(result.Value.Fci.ApplicationAid, Is.EqualTo(Convert.FromHexString("A000000151000000")));
            Assert.That(result.Value.Fci.MaxCommandDataLength, Is.EqualTo(255));
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

            Assert.That(result.IsSuccess, Is.True);
            var fci = result.Value.Fci;
            Assert.That(fci, Is.Not.Null);
            Assert.That(fci.ApplicationAid, Is.EqualTo(Convert.FromHexString("A0000000030000")));
            Assert.That(fci.ApplicationLabel, Is.EqualTo("ISD"));
            Assert.That(fci.ApplicationPriorityIndicator, Is.EqualTo(0x01));
            Assert.That(fci.MaxCommandDataLength, Is.EqualTo(256));
            Assert.That(fci.MaxResponseDataLength, Is.EqualTo(512));
            Assert.That(fci.IssuerIdentificationNumber, Is.EqualTo(new byte[] { 0x12, 0x34 }));
            Assert.That(fci.CardImageNumber, Is.EqualTo(new byte[] { 0x56, 0x78 }));
            Assert.That(fci.CardData, Is.EqualTo(new byte[] { 0x9A, 0xBC }));
            Assert.That(fci.DiscretionaryData, Is.EqualTo(new byte[] { 0xDE, 0xF0 }));
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

            Assert.That(result.IsSuccess, Is.True);
            var fci = result.Value.Fci;
            Assert.That(fci.MaxCommandDataLength, Is.EqualTo(255));
            Assert.That(fci.MaxResponseDataLength, Is.EqualTo(128));
        }

        [Test]
        public void Parse_WithEmptyApplicationLabel_ParsesCorrectly()
        {
            var tlvBuilder = new TlvTestBuilder();
            tlvBuilder.Add(0x6F, builder =>
            {
                builder.Add(0x84, Convert.FromHexString("A000000151000000"));
                builder.Add(0x50, Array.Empty<byte>()); // Empty label
            });

            var fciData = tlvBuilder.Build();
            var result = SelectResponse.Parse(fciData);

            Assert.That(result.IsSuccess, Is.True);
            var fci = result.Value.Fci;
            Assert.That(fci.ApplicationLabel, Is.EqualTo(""));
        }

        [Test]
        public void Parse_WithEmptyPriorityIndicator_HandlesGracefully()
        {
            var tlvBuilder = new TlvTestBuilder();
            tlvBuilder.Add(0x6F, builder =>
            {
                builder.Add(0x84, Convert.FromHexString("A000000151000000"));
                builder.Add(0x87, Array.Empty<byte>()); // Empty priority
            });

            var fciData = tlvBuilder.Build();
            var result = SelectResponse.Parse(fciData);

            Assert.That(result.IsSuccess, Is.True);
            var fci = result.Value.Fci;
            Assert.That(fci.ApplicationPriorityIndicator, Is.Null);
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

            Assert.That(result.IsSuccess, Is.True);
            var fci = result.Value.Fci;
            Assert.That(fci.ApplicationAid, Is.EqualTo(Convert.FromHexString("A000000151000000")));
        }

        [Test]
        public void Parse_WithMalformedFci_ReturnsSuccessWithNullFci()
        {
            // Create intentionally malformed FCI data
            var malformedData = new byte[] { 0x6F, 0x10, 0x84, 0xFF }; // Length mismatch

            var result = SelectResponse.Parse(malformedData);

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Fci, Is.Null);
            Assert.That(result.Value.RawData, Is.EqualTo(malformedData));
        }

        [Test]
        public void ParseWithFci_CallsParseMethod()
        {
            var fciData = Convert.FromHexString("6F108408A000000151000000A5049F6501FF");

            var result = SelectResponse.ParseWithFci(fciData);

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Fci, Is.Not.Null);
        }

        [Test]
        public void Constructor_ClonesRawData()
        {
            var originalData = new byte[] { 0x01, 0x02, 0x03 };
            var response = new SelectResponse(originalData);

            originalData[0] = 0xFF;

            Assert.That(response.RawData[0], Is.EqualTo(0x01));
        }

        [Test]
        public void Constructor_WithFci_StoresBoth()
        {
            var rawData = new byte[] { 0x01, 0x02, 0x03 };
            var fci = new FileControlInformation(applicationAid: Convert.FromHexString("A000000151000000"));

            var response = new SelectResponse(rawData, fci);

            Assert.That(response.RawData, Is.EqualTo(rawData));
            Assert.That(response.Fci, Is.EqualTo(fci));
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

            Assert.That(fci.ApplicationAid, Is.EqualTo(aid));
            Assert.That(fci.ApplicationLabel, Is.EqualTo(label));
            Assert.That(fci.ApplicationPriorityIndicator, Is.EqualTo(priority));
            Assert.That(fci.MaxCommandDataLength, Is.EqualTo(maxCommand));
            Assert.That(fci.MaxResponseDataLength, Is.EqualTo(maxResponse));
            Assert.That(fci.IssuerIdentificationNumber, Is.EqualTo(issuerNumber));
            Assert.That(fci.CardImageNumber, Is.EqualTo(cardImage));
            Assert.That(fci.CardData, Is.EqualTo(cardData));
            Assert.That(fci.DiscretionaryData, Is.EqualTo(discretionaryData));
        }

        [Test]
        public void Constructor_WithNullParameters_HandlesCorrectly()
        {
            var fci = new FileControlInformation();

            Assert.That(fci.ApplicationAid, Is.Null);
            Assert.That(fci.ApplicationLabel, Is.Null);
            Assert.That(fci.ApplicationPriorityIndicator, Is.Null);
            Assert.That(fci.MaxCommandDataLength, Is.Null);
            Assert.That(fci.MaxResponseDataLength, Is.Null);
            Assert.That(fci.IssuerIdentificationNumber, Is.Null);
            Assert.That(fci.CardImageNumber, Is.Null);
            Assert.That(fci.CardData, Is.Null);
            Assert.That(fci.DiscretionaryData, Is.Null);
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
            Assert.That(fci.ApplicationAid[0], Is.EqualTo(0xA0));
            Assert.That(fci.IssuerIdentificationNumber[0], Is.EqualTo(0x12));
            Assert.That(fci.CardImageNumber[0], Is.EqualTo(0x56));
            Assert.That(fci.CardData[0], Is.EqualTo(0x9A));
            Assert.That(fci.DiscretionaryData[0], Is.EqualTo(0xDE));
        }

        [Test]
        public void Constructor_WithEmptyArrays_HandlesCorrectly()
        {
            var fci = new FileControlInformation(
                applicationAid: Array.Empty<byte>(),
                issuerIdentificationNumber: Array.Empty<byte>(),
                cardImageNumber: Array.Empty<byte>(),
                cardData: Array.Empty<byte>(),
                discretionaryData: Array.Empty<byte>()
            );

            Assert.That(fci.ApplicationAid, Is.Empty);
            Assert.That(fci.IssuerIdentificationNumber, Is.Empty);
            Assert.That(fci.CardImageNumber, Is.Empty);
            Assert.That(fci.CardData, Is.Empty);
            Assert.That(fci.DiscretionaryData, Is.Empty);
        }
    }
}