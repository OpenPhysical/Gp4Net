using System;
using Gp4Net.Domain.Commands;
using Xunit;

namespace Gp4Net.Tests.Domain.Commands
{
    public class GetDataResponseExtensionsTests
    {
        [Fact]
        public void ParseAsCardData_WithValidData_ReturnsCardDataInfo()
        {
            // Arrange - Sample card data with OID
            var data = Convert.FromHexString("660C73066060402A00640508AAAA");

            // Act
            var result = data.ParseAsCardData();

            // Assert
            Assert.NotNull(result);
            // Further assertions would require knowing the expected CardDataInfo structure
        }

        [Fact]
        public void ParseAsCardData_WithInvalidData_ReturnsNull()
        {
            // Arrange
            var data = new byte[] { 0x00, 0x01, 0x02 };

            // Act
            var result = data.ParseAsCardData();

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void ParseAsCardData_WithEmptyData_ReturnsNull()
        {
            // Arrange
            var data = Array.Empty<byte>();

            // Act
            var result = data.ParseAsCardData();

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void ParseAsCardData_WithNullData_ReturnsNull()
        {
            // Arrange
            byte[] data = null;

            // Act
            var result = data.ParseAsCardData();

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void ParseAsCardCapabilities_WithValidData_ReturnsCardCapabilities()
        {
            // Arrange - Sample capabilities data
            var data = Convert.FromHexString("670A810201820103830101");

            // Act
            var result = data.ParseAsCardCapabilities();

            // Assert
            Assert.NotNull(result);
            // Further assertions would require knowing the expected CardCapabilities structure
        }

        [Fact]
        public void ParseAsCardCapabilities_WithInvalidData_ReturnsNull()
        {
            // Arrange
            var data = new byte[] { 0xFF };

            // Act
            var result = data.ParseAsCardCapabilities();

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void ParseAsCardCapabilities_WithEmptyData_ReturnsNull()
        {
            // Arrange
            var data = Array.Empty<byte>();

            // Act
            var result = data.ParseAsCardCapabilities();

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void ParseAsCardCapabilities_WithNullData_ReturnsNull()
        {
            // Arrange
            byte[] data = null;

            // Act
            var result = data.ParseAsCardCapabilities();

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void ParseAsKeyInformation_WithValidData_ReturnsKeyInformationTemplate()
        {
            // Arrange - Sample key information template data (tag E0)
            var data = Convert.FromHexString("E010C00401018810C00402018810C00403018810");

            // Act
            var result = data.ParseAsKeyInformation();

            // Assert
            Assert.NotNull(result);
            Assert.NotEmpty(result.Keys);
        }

        [Fact]
        public void ParseAsKeyInformation_WithInvalidData_ReturnsNull()
        {
            // Arrange
            var data = new byte[] { 0x00 };

            // Act
            var result = data.ParseAsKeyInformation();

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void ParseAsKeyInformation_WithEmptyData_ReturnsNull()
        {
            // Arrange
            var data = Array.Empty<byte>();

            // Act
            var result = data.ParseAsKeyInformation();

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void ParseAsKeyInformation_WithNullData_ReturnsNull()
        {
            // Arrange
            byte[] data = null;

            // Act
            var result = data.ParseAsKeyInformation();

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void ParseAsCplc_WithValidData_ReturnsCplcData()
        {
            // Arrange - CPLC data is always 42 bytes
            var data = new byte[42];
            // Fill with sample data
            Array.Fill(data, (byte)0x00);
            data[0] = 0x12; // IC Fabricator
            data[1] = 0x34;

            // Act
            var result = data.ParseAsCplc();

            // Assert
            Assert.NotNull(result);
            Assert.Equal(0x1234, result.IcFabricator);
        }

        [Fact]
        public void ParseAsCplc_WithWrongLength_ReturnsNull()
        {
            // Arrange - CPLC must be exactly 42 bytes
            var data = new byte[40];

            // Act
            var result = data.ParseAsCplc();

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void ParseAsCplc_WithEmptyData_ReturnsNull()
        {
            // Arrange
            var data = Array.Empty<byte>();

            // Act
            var result = data.ParseAsCplc();

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void ParseAsCplc_WithNullData_ReturnsNull()
        {
            // Arrange
            byte[] data = null;

            // Act
            var result = data.ParseAsCplc();

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void AllParseMethods_HandleExceptionsGracefully()
        {
            // Arrange - Data that might cause parsing exceptions
            var malformedData = new byte[] { 0xFF, 0xFF, 0xFF };

            // Act & Assert - None should throw, all should return null
            Assert.Null(malformedData.ParseAsCardData());
            Assert.Null(malformedData.ParseAsCardCapabilities());
            Assert.Null(malformedData.ParseAsKeyInformation());
            Assert.Null(malformedData.ParseAsCplc());
        }
    }
}