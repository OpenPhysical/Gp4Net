using System;
using Gp4Net.Domain.CardInfo;
using Xunit;

namespace Gp4Net.Tests.Domain.CardInfo
{
    public class DiversificationDataParserTests
    {
        [Fact]
        public void ParseAsHex_WithValidData_ReturnsHexString()
        {
            // Arrange
            var data = Convert.FromHexString("CF0A0215031070060301060000");

            // Act
            var result = DiversificationDataParser.ParseAsHex(data);

            // Assert
            Assert.Equal("CF0A0215031070060301060000", result);
        }

        [Fact]
        public void ParseAsHex_WithEmptyData_ReturnsEmptyString()
        {
            // Arrange
            var data = Array.Empty<byte>();

            // Act
            var result = DiversificationDataParser.ParseAsHex(data);

            // Assert
            Assert.Equal(string.Empty, result);
        }

        [Fact]
        public void ParseAsHex_WithNullData_ReturnsEmptyString()
        {
            // Act
            var result = DiversificationDataParser.ParseAsHex(null);

            // Assert
            Assert.Equal(string.Empty, result);
        }

        [Fact]
        public void ParseScpSupport_WithValidCF0AFormat_ParsesScpVersions()
        {
            // Arrange - CF0A format with SCP02 (i=15) and SCP03 (i=70)
            var data = Convert.FromHexString("CF0A0215037000000000000000");

            // Act
            var result = DiversificationDataParser.ParseScpSupport(data);

            // Assert
            Assert.Contains("SCP02 (i=15)", result);
            Assert.Contains("SCP03 (i=70)", result);
        }

        [Fact]
        public void ParseScpSupport_WithMultipleScpVersions_ParsesAll()
        {
            // Arrange - CF0A format with multiple SCP versions
            var data = Convert.FromHexString("CF0A0215031060070301060000");

            // Act
            var result = DiversificationDataParser.ParseScpSupport(data);

            // Assert
            Assert.Contains("SCP02 (i=15)", result);
            Assert.Contains("SCP03 (i=10)", result);
            Assert.Contains("SCP60 (i=07)", result);
            Assert.Contains("SCP03 (i=01)", result);
            Assert.Contains("SCP06 (i=00)", result);
        }

        [Fact]
        public void ParseScpSupport_WithEmptySlots_IgnoresZeroValues()
        {
            // Arrange - CF0A format with empty slots (00 00)
            var data = Convert.FromHexString("CF0A0215000003700000000000");

            // Act
            var result = DiversificationDataParser.ParseScpSupport(data);

            // Assert
            Assert.Contains("SCP02 (i=15)", result);
            Assert.Contains("SCP03 (i=70)", result);
            Assert.DoesNotContain("SCP00", result);
        }

        [Fact]
        public void ParseScpSupport_WithNoSupportedVersions_ReturnsNone()
        {
            // Arrange - CF0A format with all zeros
            var data = Convert.FromHexString("CF0A0000000000000000000000");

            // Act
            var result = DiversificationDataParser.ParseScpSupport(data);

            // Assert
            Assert.Equal("[red]None[/]", result);
        }

        [Fact]
        public void ParseScpSupport_WithShortData_ReturnsNone()
        {
            // Arrange - Data too short (less than 12 bytes)
            var data = Convert.FromHexString("CF0A0215");

            // Act
            var result = DiversificationDataParser.ParseScpSupport(data);

            // Assert
            Assert.Equal("[red]None[/]", result);
        }

        [Fact]
        public void ParseScpSupport_WithInvalidLength_ReturnsParseError()
        {
            // Arrange - CF tag with invalid length (less than 10)
            var data = Convert.FromHexString("CF05021503700000");

            // Act
            var result = DiversificationDataParser.ParseScpSupport(data);

            // Assert
            Assert.Equal("[red]Parse error[/]", result);
        }

        [Fact]
        public void ParseScpSupport_WithNullData_ReturnsNone()
        {
            // Act
            var result = DiversificationDataParser.ParseScpSupport(null);

            // Assert
            Assert.Equal("[red]None[/]", result);
        }

        [Fact]
        public void ParseScpSupport_WithEmptyData_ReturnsNone()
        {
            // Arrange
            var data = Array.Empty<byte>();

            // Act
            var result = DiversificationDataParser.ParseScpSupport(data);

            // Assert
            Assert.Equal("[red]None[/]", result);
        }

        [Fact]
        public void ParseScpSupport_FormatsMultipleVersionsWithCommas()
        {
            // Arrange - CF0A format with three SCP versions
            var data = Convert.FromHexString("CF0A0215031060070000000000");

            // Act
            var result = DiversificationDataParser.ParseScpSupport(data);

            // Assert
            Assert.Contains(", ", result);
            var versions = result.Split(", ");
            Assert.Equal(3, versions.Length);
        }

        [Fact]
        public void ParseScpSupport_PreservesParameterOrder()
        {
            // Arrange - CF0A format with specific order
            var data = Convert.FromHexString("CF0A0370021500000000000000");

            // Act
            var result = DiversificationDataParser.ParseScpSupport(data);

            // Assert
            // Should appear in the order they are in the data
            var firstCommaIndex = result.IndexOf(',');
            var scp03Index = result.IndexOf("SCP03");
            var scp02Index = result.IndexOf("SCP02");
            Assert.True(scp03Index < scp02Index);
        }
    }
}