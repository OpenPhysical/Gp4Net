using System;
using Gp4Net.Domain.CardInfo;
using Xunit;

namespace Gp4Net.Tests.Domain.CardInfo
{
    public class SecurityDomainDataParserTests
    {
        [Fact]
        public void Decode_WithA5Tag_ParsesMaxApduSize()
        {
            // Arrange - A5 tag with 9F65 (Max APDU size = 255)
            var data = Convert.FromHexString("A5089F650200FF9F6E0107");

            // Act
            var result = SecurityDomainDataParser.Decode(data);

            // Assert
            Assert.Contains("Max APDU: 255 bytes", result);
        }

        [Fact]
        public void Decode_WithA5Tag_ParsesLifecycleState()
        {
            // Arrange - A5 tag with 9F6E (Lifecycle = Selectable)
            var data = Convert.FromHexString("A5049F6E0107");

            // Act
            var result = SecurityDomainDataParser.Decode(data);

            // Assert
            Assert.Contains("Lifecycle: Selectable", result);
        }

        [Fact]
        public void Decode_WithMultipleTags_ParsesAllValues()
        {
            // Arrange - A5 tag with both Max APDU and Lifecycle
            var data = Convert.FromHexString("A50A9F650200FF9F6E010F");

            // Act
            var result = SecurityDomainDataParser.Decode(data);

            // Assert
            Assert.Contains("Max APDU: 255 bytes", result);
            Assert.Contains("Lifecycle: Personalized", result);
        }

        [Theory]
        [InlineData("01", "Loaded")]
        [InlineData("03", "Installed")]
        [InlineData("07", "Selectable")]
        [InlineData("0F", "Personalized")]
        [InlineData("83", "Blocked")]
        [InlineData("87", "Locked")]
        public void Decode_RecognizesAllLifecycleStates(string stateHex, string expectedState)
        {
            // Arrange
            var data = Convert.FromHexString($"A5049F6E01{stateHex}");

            // Act
            var result = SecurityDomainDataParser.Decode(data);

            // Assert
            Assert.Contains($"Lifecycle: {expectedState}", result);
        }

        [Fact]
        public void Decode_WithUnknownLifecycleState_ShowsHexValue()
        {
            // Arrange - Unknown lifecycle state 0xAB
            var data = Convert.FromHexString("A5049F6E01AB");

            // Act
            var result = SecurityDomainDataParser.Decode(data);

            // Assert
            Assert.Contains("Lifecycle: 0xAB", result);
        }

        [Fact]
        public void Decode_WithUnknownTag_ShowsTagAndValue()
        {
            // Arrange - Unknown tag 9F99
            var data = Convert.FromHexString("A5069F9903112233");

            // Act
            var result = SecurityDomainDataParser.Decode(data);

            // Assert
            Assert.Contains("Tag 9F99: 112233", result);
        }

        [Fact]
        public void Decode_WithNonA5Tag_ReturnsHexString()
        {
            // Arrange - Data not starting with A5
            var data = Convert.FromHexString("B5041122");

            // Act
            var result = SecurityDomainDataParser.Decode(data);

            // Assert
            Assert.Equal("B5041122", result);
        }

        [Fact]
        public void Decode_WithEmptyData_ReturnsEmptyString()
        {
            // Arrange
            var data = Array.Empty<byte>();

            // Act
            var result = SecurityDomainDataParser.Decode(data);

            // Assert
            Assert.Equal(string.Empty, result);
        }

        [Fact]
        public void Decode_WithNullData_ReturnsEmptyString()
        {
            // Act
            var result = SecurityDomainDataParser.Decode(null);

            // Assert
            Assert.Equal(string.Empty, result);
        }

        [Fact]
        public void Decode_WithMalformedTlv_ReturnsHexString()
        {
            // Arrange - A5 with invalid length
            var data = Convert.FromHexString("A5FF112233");

            // Act
            var result = SecurityDomainDataParser.Decode(data);

            // Assert
            Assert.Equal("A5FF112233", result);
        }
    }
}