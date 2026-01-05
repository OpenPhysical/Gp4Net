using System;
using System.Text;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Tests.Domain.Commands.TestHelpers;
using Gp4Net.Tests.Infrastructure;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

[TestFixture]
[Category("Unit")]
public class SelectResponseTests
{
    [Test]
    public void Parse_WithNullData_ReturnsFailure()
    {
        Result<SelectResponse, SmartCardError> result = SelectResponse.Parse(null!);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<InvalidDataError>();
        var error = (InvalidDataError)result.Error;
        _ = error.Field.Should().Be("Response");
        _ = error.Reason.Should().Be("cannot be null");
    }

    [Test]
    public void Parse_WithEmptyData_ReturnsSuccessWithNullFci()
    {
        Result<SelectResponse, SmartCardError> result = SelectResponse.Parse([]);

        _ = result.IsSuccess.Should().BeTrue();
        if (result.IsSuccess)
        {
            var response = result.Value;
            _ = response.RawData.Should().BeEmpty();
            _ = response.Fci.HasValue.Should().BeFalse();
        }
    }

    [Test]
    public void Parse_WithNonFciData_ReturnsSuccessWithNullFci()
    {
        byte[] nonFciData = Convert.FromHexString("9F7F2A47900000");

        Result<SelectResponse, SmartCardError> result = SelectResponse.Parse(nonFciData);

        _ = result.IsSuccess.Should().BeTrue();
        if (result.IsSuccess)
        {
            var response = result.Value;
            _ = response.RawData.Should().BeEquivalentTo(nonFciData);
            _ = response.Fci.HasValue.Should().BeFalse();
        }
    }

    [Test]
    public void Parse_WithSimpleFci_ParsesCorrectly()
    {
        byte[] fciData = Convert.FromHexString("6F108408A000000151000000A5049F6501FF");

        Result<SelectResponse, SmartCardError> result = SelectResponse.Parse(fciData);

        _ = result.IsSuccess.Should().BeTrue();
        if (result.IsSuccess)
        {
            var response = result.Value;
            byte[]? aid = response.Fci.Map(fci => fci.ApplicationAid).GetValueOrDefault([]);
            _ = aid.Should().BeEquivalentTo(Convert.FromHexString("A000000151000000"));

            response.Fci.Match(
                fci =>
                    fci.MaxCommandDataLength.Match(
                        value => value.Should().Be(255),
                        () => false.Should().BeTrue("MaxCommandDataLength should have a value")
                    ),
                () => false.Should().BeTrue("FCI should have a value")
            );
        }
    }

    [Test]
    public void Parse_WithComplexFci_ParsesAllFields()
    {
        var tlvBuilder = new TlvTestBuilder();
        tlvBuilder.Add(
            0x6F,
            builder =>
            {
                builder.Add(0x84, Convert.FromHexString("A0000000030000")); // AID
                builder.Add(0x50, Encoding.UTF8.GetBytes("ISD")); // Label
                builder.Add(0x87, [0x01]); // Priority
                builder.Add(
                    0xA5,
                    subBuilder =>
                    {
                        subBuilder.Add(0x9F65, [0x01, 0x00]); // Max command length (256)
                        subBuilder.Add(0x9F66, [0x02, 0x00]); // Max response length (512)
                        subBuilder.Add(0x42, [0x12, 0x34]); // Issuer ID
                        subBuilder.Add(0x45, [0x56, 0x78]); // Card Image
                        subBuilder.Add(0x66, [0x9A, 0xBC]); // Card Data
                    }
                );
                builder.Add(0xBF0C, [0xDE, 0xF0]); // Discretionary Data
            }
        );

        byte[] fciData = tlvBuilder.Build();
        Result<SelectResponse, SmartCardError> result = SelectResponse.Parse(fciData);

        _ = result.IsSuccess.Should().BeTrue();
        if (result.IsSuccess)
        {
            var response = result.Value;
            _ = response.Fci.HasValue.Should().BeTrue();
            _ = response.Fci.Match(
                fci =>
                {
                    _ = fci
                        .ApplicationAid.Should()
                        .BeEquivalentTo(Convert.FromHexString("A0000000030000"));
                    _ = fci.ApplicationLabel.Match(
                        label =>
                        {
                            _ = label.Should().Be("ISD");
                            return true;
                        },
                        () =>
                        {
                            _ = false.Should().BeTrue("ApplicationLabel should have a value");
                            return false;
                        }
                    );
                    _ = fci.ApplicationPriorityIndicator.Match(
                        value =>
                        {
                            _ = value.Should().Be(0x01);
                            return true;
                        },
                        () =>
                        {
                            _ = false
                                .Should()
                                .BeTrue("ApplicationPriorityIndicator should have a value");
                            return false;
                        }
                    );
                    _ = fci.MaxCommandDataLength.Match(
                        value =>
                        {
                            _ = value.Should().Be(256);
                            return true;
                        },
                        () =>
                        {
                            _ = false.Should().BeTrue("MaxCommandDataLength should have a value");
                            return false;
                        }
                    );
                    _ = fci.MaxResponseDataLength.Match(
                        value =>
                        {
                            _ = value.Should().Be(512);
                            return true;
                        },
                        () =>
                        {
                            _ = false.Should().BeTrue("MaxResponseDataLength should have a value");
                            return false;
                        }
                    );
                    _ = fci
                        .IssuerIdentificationNumber.Should()
                        .BeEquivalentTo(new byte[] { 0x12, 0x34 });
                    _ = fci.CardImageNumber.Should().BeEquivalentTo(new byte[] { 0x56, 0x78 });
                    _ = fci.CardData.Should().BeEquivalentTo(new byte[] { 0x9A, 0xBC });
                    _ = fci.DiscretionaryData.Should().BeEquivalentTo(new byte[] { 0xDE, 0xF0 });
                    return true;
                },
                () =>
                {
                    _ = false.Should().BeTrue("FCI should have a value");
                    return false;
                }
            );
        }
    }

    [Test]
    public void Parse_WithSingleByteMaxLengths_ParsesCorrectly()
    {
        var tlvBuilder = new TlvTestBuilder();
        tlvBuilder.Add(
            0x6F,
            builder =>
            {
                builder.Add(0x84, Convert.FromHexString("A000000151000000"));
                builder.Add(
                    0xA5,
                    subBuilder =>
                    {
                        subBuilder.Add(0x9F65, [0xFF]); // Single byte max command
                        subBuilder.Add(0x9F66, [0x80]); // Single byte max response
                    }
                );
            }
        );

        byte[] fciData = tlvBuilder.Build();
        Result<SelectResponse, SmartCardError> result = SelectResponse.Parse(fciData);

        _ = result.IsSuccess.Should().BeTrue();
        if (result.IsSuccess)
        {
            var response = result.Value;
            _ = response.Fci.HasValue.Should().BeTrue();
            _ = response.Fci.Match(
                fci =>
                {
                    _ = fci.MaxCommandDataLength.Match(
                        value =>
                        {
                            _ = value.Should().Be(255);
                            return true;
                        },
                        () =>
                        {
                            _ = false.Should().BeTrue("MaxCommandDataLength should have a value");
                            return false;
                        }
                    );
                    _ = fci.MaxResponseDataLength.Match(
                        value =>
                        {
                            _ = value.Should().Be(128);
                            return true;
                        },
                        () =>
                        {
                            _ = false.Should().BeTrue("MaxResponseDataLength should have a value");
                            return false;
                        }
                    );
                    return true;
                },
                () =>
                {
                    _ = false.Should().BeTrue("FCI should have a value");
                    return false;
                }
            );
        }
    }

    [Test]
    public void Parse_WithEmptyApplicationLabel_ParsesCorrectly()
    {
        var tlvBuilder = new TlvTestBuilder();
        tlvBuilder.Add(
            0x6F,
            builder =>
            {
                builder.Add(0x84, Convert.FromHexString("A000000151000000"));
                builder.Add(0x50, []); // Empty label
            }
        );

        byte[] fciData = tlvBuilder.Build();
        Result<SelectResponse, SmartCardError> result = SelectResponse.Parse(fciData);

        _ = result.IsSuccess.Should().BeTrue();
        if (result.IsSuccess)
        {
            var response = result.Value;
            _ = response.Fci.HasValue.Should().BeTrue();
            _ = response.Fci.Match(
                fci =>
                {
                    _ = fci.ApplicationLabel.Match(
                        label =>
                        {
                            _ = label.Should().Be("");
                            return true;
                        },
                        () =>
                        {
                            _ = false.Should().BeTrue("ApplicationLabel should have a value");
                            return false;
                        }
                    );
                    return true;
                },
                () =>
                {
                    _ = false.Should().BeTrue("FCI should have a value");
                    return false;
                }
            );
        }
    }

    [Test]
    public void Parse_WithEmptyPriorityIndicator_HandlesGracefully()
    {
        var tlvBuilder = new TlvTestBuilder();
        tlvBuilder.Add(
            0x6F,
            builder =>
            {
                builder.Add(0x84, Convert.FromHexString("A000000151000000"));
                builder.Add(0x87, []); // Empty priority
            }
        );

        byte[] fciData = tlvBuilder.Build();
        Result<SelectResponse, SmartCardError> result = SelectResponse.Parse(fciData);

        _ = result.IsSuccess.Should().BeTrue();
        if (result.IsSuccess)
        {
            var response = result.Value;
            _ = response.Fci.HasValue.Should().BeTrue();
            _ = response.Fci.Match(
                fci =>
                {
                    _ = fci.ApplicationPriorityIndicator.HasValue.Should().BeFalse();
                    return true;
                },
                () =>
                {
                    _ = false.Should().BeTrue("FCI should have a value");
                    return false;
                }
            );
        }
    }

    [Test]
    public void Parse_WithPdolTag_IgnoresItGracefully()
    {
        var tlvBuilder = new TlvTestBuilder();
        tlvBuilder.Add(
            0x6F,
            builder =>
            {
                builder.Add(0x84, Convert.FromHexString("A000000151000000"));
                builder.Add(0x9F38, [0x9F, 0x66, 0x02]); // PDOL
            }
        );

        byte[] fciData = tlvBuilder.Build();
        Result<SelectResponse, SmartCardError> result = SelectResponse.Parse(fciData);

        _ = result.IsSuccess.Should().BeTrue();
        if (result.IsSuccess)
        {
            var response = result.Value;
            _ = response.Fci.HasValue.Should().BeTrue();
            _ = response.Fci.Match(
                fci =>
                {
                    _ = fci
                        .ApplicationAid.Should()
                        .BeEquivalentTo(Convert.FromHexString("A000000151000000"));
                    return true;
                },
                () =>
                {
                    _ = false.Should().BeTrue("FCI should have a value");
                    return false;
                }
            );
        }
    }

    [Test]
    public void Parse_WithMalformedFci_ReturnsSuccessWithNullFci()
    {
        // Create intentionally malformed FCI data
        byte[] malformedData = [0x6F, 0x10, 0x84, 0xFF]; // Length mismatch

        Result<SelectResponse, SmartCardError> result = SelectResponse.Parse(malformedData);

        _ = result.IsSuccess.Should().BeTrue();
        if (result.IsSuccess)
        {
            var response = result.Value;
            _ = response.Fci.HasValue.Should().BeFalse();
            _ = response.RawData.Should().BeEquivalentTo(malformedData);
        }
    }

    [Test]
    public void ParseWithFci_CallsParseMethod()
    {
        byte[] fciData = Convert.FromHexString("6F108408A000000151000000A5049F6501FF");

        Result<SelectResponse, SmartCardError> result = SelectResponse.ParseWithFci(fciData);

        _ = result.IsSuccess.Should().BeTrue();
        if (result.IsSuccess)
        {
            var response = result.Value;
            _ = response.Fci.HasValue.Should().BeTrue();
        }
    }

    [Test]
    public void Constructor_ClonesRawData()
    {
        byte[] originalData = [0x01, 0x02, 0x03];
        var response = new SelectResponse(originalData);

        originalData[0] = 0xFF;

        _ = response.RawData[0].Should().Be(0x01);
    }

    [Test]
    public void Constructor_WithFci_StoresBoth()
    {
        byte[] rawData = [0x01, 0x02, 0x03];
        var fci = new FileControlInformation(
            applicationAid: Convert.FromHexString("A000000151000000"),
            applicationLabel: string.Empty,
            applicationPriorityIndicator: Maybe<byte>.None,
            maxCommandDataLength: Maybe<ushort>.None,
            maxResponseDataLength: Maybe<ushort>.None,
            issuerIdentificationNumber: [],
            cardImageNumber: [],
            cardData: [],
            discretionaryData: []
        );

        var response = new SelectResponse(rawData, fci);

        _ = response.RawData.Should().BeEquivalentTo(rawData);
        _ = response.Fci.HasValue.Should().BeTrue();
        var actualFci = response.Fci.GetValueOrDefault();
        _ = actualFci.Should().BeEquivalentTo(fci);
    }
}

[TestFixture]
public class FileControlInformationTests
{
    [Test]
    public void Constructor_WithAllParameters_StoresCorrectly()
    {
        byte[] aid = Convert.FromHexString("A000000151000000");
        string label = "Test App";
        byte priority = 0x01;
        ushort maxCommand = 255;
        ushort maxResponse = 256;
        byte[] issuerNumber = [0x12, 0x34];
        byte[] cardImage = [0x56, 0x78];
        byte[] cardData = [0x9A, 0xBC];
        byte[] discretionaryData = [0xDE, 0xF0];

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
        _ = fci.ApplicationLabel.Should().HaveValue(label);
        _ = fci.ApplicationPriorityIndicator.Should().HaveValue(priority);
        _ = fci.MaxCommandDataLength.Should().HaveValue(maxCommand);
        _ = fci.MaxResponseDataLength.Should().HaveValue(maxResponse);
        _ = fci.IssuerIdentificationNumber.Should().BeEquivalentTo(issuerNumber);
        _ = fci.CardImageNumber.Should().BeEquivalentTo(cardImage);
        _ = fci.CardData.Should().BeEquivalentTo(cardData);
        _ = fci.DiscretionaryData.Should().BeEquivalentTo(discretionaryData);
    }

    [Test]
    public void Constructor_WithNullParameters_HandlesCorrectly()
    {
        var fci = new FileControlInformation(
            applicationAid: [],
            applicationLabel: null!,
            applicationPriorityIndicator: Maybe<byte>.None,
            maxCommandDataLength: Maybe<ushort>.None,
            maxResponseDataLength: Maybe<ushort>.None,
            issuerIdentificationNumber: [],
            cardImageNumber: [],
            cardData: [],
            discretionaryData: []
        );

        _ = fci.ApplicationAid.Should().BeEmpty();
        _ = fci.ApplicationLabel.HasValue.Should().BeFalse();
        _ = fci.ApplicationPriorityIndicator.HasValue.Should().BeFalse();
        _ = fci.MaxCommandDataLength.HasValue.Should().BeFalse();
        _ = fci.MaxResponseDataLength.HasValue.Should().BeFalse();
        _ = fci.IssuerIdentificationNumber.Should().BeEmpty();
        _ = fci.CardImageNumber.Should().BeEmpty();
        _ = fci.CardData.Should().BeEmpty();
        _ = fci.DiscretionaryData.Should().BeEmpty();
    }

    [Test]
    public void Constructor_ClonesArrays()
    {
        byte[] aid = Convert.FromHexString("A000000151000000");
        byte[] issuerNumber = [0x12, 0x34];
        byte[] cardImage = [0x56, 0x78];
        byte[] cardData = [0x9A, 0xBC];
        byte[] discretionaryData = [0xDE, 0xF0];

        var fci = new FileControlInformation(
            applicationAid: aid,
            applicationLabel: string.Empty,
            applicationPriorityIndicator: Maybe<byte>.None,
            maxCommandDataLength: Maybe<ushort>.None,
            maxResponseDataLength: Maybe<ushort>.None,
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
        _ = fci.ApplicationAid.Should().NotBeEmpty();
        _ = fci.ApplicationAid[0].Should().Be(0xA0);

        _ = fci.IssuerIdentificationNumber.Should().NotBeEmpty();
        _ = fci.IssuerIdentificationNumber[0].Should().Be(0x12);

        _ = fci.CardImageNumber.Should().NotBeEmpty();
        _ = fci.CardImageNumber[0].Should().Be(0x56);

        _ = fci.CardData.Should().NotBeEmpty();
        _ = fci.CardData[0].Should().Be(0x9A);

        _ = fci.DiscretionaryData.Should().NotBeEmpty();
        _ = fci.DiscretionaryData[0].Should().Be(0xDE);
    }

    [Test]
    public void Constructor_WithEmptyArrays_HandlesCorrectly()
    {
        var fci = new FileControlInformation(
            applicationAid: [],
            applicationLabel: string.Empty,
            applicationPriorityIndicator: Maybe<byte>.None,
            maxCommandDataLength: Maybe<ushort>.None,
            maxResponseDataLength: Maybe<ushort>.None,
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
