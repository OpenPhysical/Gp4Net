using Gp4Net.Domain.CardInfo;
using NUnit.Framework;
using AwesomeAssertions;

namespace Gp4Net.Tests.Domain.CardInfo;

[TestFixture]
public class CardDataInfoOidTests
{
    [Test]
    public void Parse_WithOids_ExtractsCorrectly()
    {
        // Arrange - Real card data with OIDs
        var data = new byte[]
        {
            0x66,
            0x4D, // Tag 66, length 77
            0x73,
            0x4B, // Tag 73, length 75
            0x06,
            0x07,
            0x2A,
            0x86,
            0x48,
            0x86,
            0xFC,
            0x6B,
            0x01, // OID: 1.2.840.114283.1
            0x60,
            0x0B, // Tag 60, length 11
            0x06,
            0x09,
            0x2A,
            0x86,
            0x48,
            0x86,
            0xFC,
            0x6B,
            0x02,
            0x02,
            0x03, // OID: 1.2.840.114283.2.2.3
            0x63,
            0x09, // Tag 63, length 9
            0x06,
            0x07,
            0x2A,
            0x86,
            0x48,
            0x86,
            0xFC,
            0x6B,
            0x03, // OID: 1.2.840.114283.3
            0x64,
            0x0B, // Tag 64, length 11
            0x06,
            0x09,
            0x2A,
            0x86,
            0x48,
            0x86,
            0xFC,
            0x6B,
            0x04,
            0x03,
            0x70, // OID: 1.2.840.114283.4.3.112
            0x65,
            0x0D, // Tag 65, length 13
            0x06,
            0x0B,
            0x2A,
            0x86,
            0x48,
            0x86,
            0xFC,
            0x6B,
            0x05,
            0x07,
            0x02,
            0x00,
            0x00, // OID: 1.2.840.114283.5.7.2.0.0
            0x66,
            0x0C, // Tag 66, length 12
            0x06,
            0x0A,
            0x2B,
            0x06,
            0x01,
            0x04,
            0x01,
            0x2A,
            0x02,
            0x6E,
            0x01,
            0x03 // OID: 1.3.6.1.4.1.42.2.110.1.3
        };

        // Act
        var cardData = CardDataInfo.Parse(data);

        // Assert
        cardData.IsSuccess.Should().BeTrue();
        cardData.Value.Oids.Should().HaveCount(6);
        cardData.Value.Oids[0].Should().BeEquivalentTo("1.2.840.114283.1");
        cardData.Value.Oids[1].Should().BeEquivalentTo("1.2.840.114283.2.2.3");
        cardData.Value.Oids[2].Should().BeEquivalentTo("1.2.840.114283.3");
        cardData.Value.Oids[3].Should().BeEquivalentTo("1.2.840.114283.4.3.112");
        cardData.Value.Oids[4].Should().BeEquivalentTo("1.2.840.114283.5.7.2.0.0");
        cardData.Value.Oids[5].Should().BeEquivalentTo("1.3.6.1.4.1.42.2.110.1.3");
    }

    [Test]
    public void Parse_ExtractsGlobalPlatformVersionFromOid()
    {
        // Arrange - Data with GP version OID
        var data = new byte[]
        {
            0x06,
            0x09,
            0x2A,
            0x86,
            0x48,
            0x86,
            0xFC,
            0x6B,
            0x02,
            0x02,
            0x03 // 1.2.840.114283.2.2.3
        };

        // Act
        var cardData = CardDataInfo.Parse(data);

        // Assert
        cardData.Value.GlobalPlatformVersionFromOid.GetValueOrDefault().Should().BeEquivalentTo("2.2.3");
    }

    [Test]
    public void ToString_IncludesOidDescriptions()
    {
        // Arrange
        var data = new byte[]
        {
            0x06,
            0x09,
            0x2A,
            0x86,
            0x48,
            0x86,
            0xFC,
            0x6B,
            0x02,
            0x02,
            0x03, // GP 2.2.3
            0x64,
            0x02,
            0x03,
            0x70 // SCP info
        };

        // Act
        var cardData = CardDataInfo.Parse(data);
        cardData.IsSuccess.Should().BeTrue();
        var output = cardData.Value.ToString();

        // Assert
        output.Should().Contain("Parsed OIDs:");
        output.Should().Contain("1.2.840.114283.2.2.3");
        output.Should().Contain("GlobalPlatform");
        output.Should().Contain("-> GP Version: 2.2.3");
        output.Should().Contain("Secure Channel Protocol Info:");
    }

    [Test]
    public void Parse_HandlesDataWithoutOids()
    {
        // Arrange - Data without OIDs
        var data = new byte[]
        {
            0x73,
            0x02,
            0x02,
            0x03 // Just GP version bytes - tag 73, length 2, value 02 03
        };

        // Act
        var cardData = CardDataInfo.Parse(data);

        // Assert
        cardData.Value.Oids.Should().BeEmpty();
        cardData.Value.GlobalPlatformVersionFromOid.HasValue.Should().BeFalse();
        cardData.Value.GlobalPlatformVersion.HasValue.Should().BeTrue();
        cardData.Value.GlobalPlatformVersion.GetValueOrDefault().Should().BeEquivalentTo(new System.Version(2, 3));
    }

    [Test]
    public void Parse_PreservesExistingTagParsing()
    {
        // Arrange
        var data = new byte[]
        {
            0x73,
            0x03,
            0x02,
            0x02,
            0x03, // GP version 2.2.3
            0x64,
            0x02,
            0x03,
            0x70, // SCP info
            0x65,
            0x04,
            0x01,
            0x02,
            0x03,
            0x04, // Config details
            0x66,
            0x02,
            0xFF,
            0xEE // Chip details
        };

        // Act
        var cardData = CardDataInfo.Parse(data);

        // Assert
        cardData.Value.Tags.Should().HaveCount(4);
        cardData.Value.GlobalPlatformVersion.GetValueOrDefault().Should().BeEquivalentTo(new System.Version(2, 2, 3));
        cardData.Value.SecureChannelProtocolInfo.GetValueOrDefault().Should().BeEquivalentTo(new byte[] { 0x03, 0x70 });
        cardData.Value.CardConfigurationDetails.GetValueOrDefault().Should().BeEquivalentTo(new byte[] { 0x01, 0x02, 0x03, 0x04 });
        cardData.Value.CardChipDetails.GetValueOrDefault().Should().BeEquivalentTo(new byte[] { 0xFF, 0xEE });
    }

    [Test]
    public void Parse_WithMixedOidsAndTags_ParsesBoth()
    {
        // Arrange - Mix of OIDs and regular tags
        var data = new byte[]
        {
            0x73,
            0x03,
            0x02,
            0x02,
            0x01, // GP version tag
            0x06,
            0x09,
            0x2A,
            0x86,
            0x48,
            0x86,
            0xFC,
            0x6B,
            0x02,
            0x02,
            0x03, // OID for GP 2.2.3 (1.2.840.114283.2.2.3)
            0x64,
            0x01,
            0x03 // SCP tag
        };

        // Act
        var cardData = CardDataInfo.Parse(data);

        // Assert
        cardData.Value.Tags.Should().HaveCount(3); // Tags 73, 06, and 64
        cardData.Value.Oids.Should().HaveCount(1);
        cardData.Value.Oids[0].Should().BeEquivalentTo("1.2.840.114283.2.2.3");
        cardData.Value.GlobalPlatformVersionFromOid.GetValueOrDefault().Should().BeEquivalentTo("2.2.3");
        cardData.Value.GlobalPlatformVersion.GetValueOrDefault().Should().BeEquivalentTo(new System.Version(2, 2, 1)); // From tag 73
    }

    [Test]
    public void Parse_NonGlobalPlatformOid_ParsedButNoVersionExtracted()
    {
        // Arrange - NIST OID
        var data = new byte[]
        {
            0x06,
            0x0A,
            0x2B,
            0x06,
            0x01,
            0x04,
            0x01,
            0x2A,
            0x02,
            0x6E,
            0x01,
            0x03
        };

        // Act
        var cardData = CardDataInfo.Parse(data);

        // Assert
        cardData.Value.Oids.Should().HaveCount(1);
        cardData.Value.Oids[0].Should().BeEquivalentTo("1.3.6.1.4.1.42.2.110.1.3");
        cardData.Value.GlobalPlatformVersionFromOid.HasValue.Should().BeFalse(); // Not a GP version OID
    }
}