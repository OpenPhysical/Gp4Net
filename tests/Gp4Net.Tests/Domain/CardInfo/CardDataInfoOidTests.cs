using System.Linq;
using Gp4Net.Domain.CardInfo;
using Xunit;

namespace Gp4Net.Tests.Domain.CardInfo
{
    public class CardDataInfoOidTests
    {
        [Fact]
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
            Assert.NotNull(cardData);
            Assert.Equal(6, cardData.Oids.Count);
            Assert.Contains("1.2.840.114283.1", cardData.Oids);
            Assert.Contains("1.2.840.114283.2.2.3", cardData.Oids);
            Assert.Contains("1.2.840.114283.3", cardData.Oids);
            Assert.Contains("1.2.840.114283.4.3.112", cardData.Oids);
            Assert.Contains("1.2.840.114283.5.7.2.0.0", cardData.Oids);
            Assert.Contains("1.3.6.1.4.1.42.2.110.1.3", cardData.Oids);
        }

        [Fact]
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
            Assert.Equal("2.2.3", cardData.GlobalPlatformVersionFromOid);
        }

        [Fact]
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
            var output = cardData.ToString();

            // Assert
            Assert.Contains("Parsed OIDs:", output);
            Assert.Contains("1.2.840.114283.2.2.3", output);
            Assert.Contains("GlobalPlatform", output);
            Assert.Contains("-> GP Version: 2.2.3", output);
            Assert.Contains("Secure Channel Protocol Info:", output);
        }

        [Fact]
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
            Assert.Empty(cardData.Oids);
            Assert.Null(cardData.GlobalPlatformVersionFromOid);
            Assert.NotNull(cardData.GlobalPlatformVersion);
            Assert.Equal(new System.Version(2, 3), cardData.GlobalPlatformVersion);
        }

        [Fact]
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
            Assert.Equal(4, cardData.Tags.Count);
            Assert.Equal(new System.Version(2, 2, 3), cardData.GlobalPlatformVersion);
            Assert.Equal(new byte[] { 0x03, 0x70 }, cardData.SecureChannelProtocolInfo);
            Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04 }, cardData.CardConfigurationDetails);
            Assert.Equal(new byte[] { 0xFF, 0xEE }, cardData.CardChipDetails);
        }

        [Fact]
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
            Assert.Equal(3, cardData.Tags.Count); // Tags 73, 06, and 64
            _ = Assert.Single(cardData.Oids);
            Assert.Contains("1.2.840.114283.2.2.3", cardData.Oids);
            Assert.Equal("2.2.3", cardData.GlobalPlatformVersionFromOid);
            Assert.Equal(new System.Version(2, 2, 1), cardData.GlobalPlatformVersion); // From tag 73
        }

        [Fact]
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
            _ = Assert.Single(cardData.Oids);
            Assert.Contains("1.3.6.1.4.1.42.2.110.1.3", cardData.Oids);
            Assert.Null(cardData.GlobalPlatformVersionFromOid); // Not a GP version OID
        }
    }
}
