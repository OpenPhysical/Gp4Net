using System;
using Gp4Net.Domain.CardInfo;
using Xunit;

namespace Gp4Net.Tests.Domain.CardInfo
{
    public class ScpCapabilitiesParserTests
    {
        [Fact]
        public void Parse_WithSecureMessagingSupport_IdentifiesScp02()
        {
            // Arrange - Tag 81 with SCP02 indicators
            var data = Convert.FromHexString("810201");

            // Act
            var result = ScpCapabilitiesParser.Parse(data);

            // Assert
            Assert.Equal("SCP02", result);
        }

        [Fact]
        public void Parse_WithSecureMessagingSupport_IdentifiesScp03()
        {
            // Arrange - Tag 81 with SCP03 indicators
            var data = Convert.FromHexString("810206");

            // Act
            var result = ScpCapabilitiesParser.Parse(data);

            // Assert
            Assert.Equal("SCP03", result);
        }

        [Fact]
        public void Parse_WithMultipleProtocols_ReturnsOrderedList()
        {
            // Arrange - Tag 81 with both SCP02 and SCP03
            var data = Convert.FromHexString("81040102");

            // Act
            var result = ScpCapabilitiesParser.Parse(data);

            // Assert
            Assert.Equal("SCP02", result);
        }

        [Fact]
        public void Parse_WithSecureChannelProtocolData_IdentifiesProtocols()
        {
            // Arrange - Tag 82 with direct protocol indicators
            var data = Convert.FromHexString("82020203");

            // Act
            var result = ScpCapabilitiesParser.Parse(data);

            // Assert
            Assert.Equal("SCP02, SCP03", result);
        }

        [Fact]
        public void Parse_WithAdditionalSecurityCapabilities_IdentifiesProtocols()
        {
            // Arrange - Tag 83 with capability bits
            var data = Convert.FromHexString("830103"); // Both SCP02 and SCP03 bits set

            // Act
            var result = ScpCapabilitiesParser.Parse(data);

            // Assert
            Assert.Equal("SCP02, SCP03", result);
        }

        [Fact]
        public void Parse_WithScp10Support_IdentifiesScp10()
        {
            // Arrange - Tag 81 with SCP10 indicator
            var data = Convert.FromHexString("810110");

            // Act
            var result = ScpCapabilitiesParser.Parse(data);

            // Assert
            Assert.Equal("SCP10", result);
        }

        [Fact]
        public void Parse_WithMultipleTags_ParsesAllTags()
        {
            // Arrange - Multiple tags with different protocols
            var data = Convert.FromHexString("810201820103");

            // Act
            var result = ScpCapabilitiesParser.Parse(data);

            // Assert
            Assert.Equal("SCP02, SCP03", result);
        }

        [Fact]
        public void Parse_RemovesDuplicatesAndSorts()
        {
            // Arrange - Multiple occurrences of same protocol
            var data = Convert.FromHexString("810402020306");

            // Act
            var result = ScpCapabilitiesParser.Parse(data);

            // Assert
            Assert.Equal("SCP02, SCP03", result);
        }

        [Fact]
        public void Parse_WithEmptyData_ReturnsEmptyString()
        {
            // Arrange
            var data = Array.Empty<byte>();

            // Act
            var result = ScpCapabilitiesParser.Parse(data);

            // Assert
            Assert.Equal(string.Empty, result);
        }

        [Fact]
        public void Parse_WithNullData_ReturnsEmptyString()
        {
            // Act
            var result = ScpCapabilitiesParser.Parse(null);

            // Assert
            Assert.Equal(string.Empty, result);
        }

        [Fact]
        public void Parse_WithMalformedTlv_ReturnsEmptyString()
        {
            // Arrange - Tag with length exceeding data
            var data = Convert.FromHexString("81FF01");

            // Act
            var result = ScpCapabilitiesParser.Parse(data);

            // Assert
            Assert.Equal(string.Empty, result);
        }

        [Fact]
        public void Parse_WithUnknownProtocolIndicators_IgnoresUnknownValues()
        {
            // Arrange - Tag 81 with mix of known and unknown values
            var data = Convert.FromHexString("810401FF0610");

            // Act
            var result = ScpCapabilitiesParser.Parse(data);

            // Assert
            Assert.Equal("SCP03, SCP10", result);
        }
    }
}