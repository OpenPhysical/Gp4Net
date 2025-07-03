using System;
using Gp4Net.Domain.Commands;
using Xunit;

namespace Gp4Net.Tests.Domain.Commands
{
    public class DataObjectParserTests
    {
        [Fact]
        public void ParseRawDataObject_WithColonSeparator_ParsesCorrectly()
        {
            // Arrange
            var dataObject = "9F70:040102";

            // Act
            var (tag, data) = DataObjectParser.ParseRawDataObject(dataObject);

            // Assert
            Assert.Equal(0x9F70, tag);
            Assert.Equal(new byte[] { 0x04, 0x01, 0x02 }, data);
        }

        [Fact]
        public void ParseRawDataObject_WithEqualsSeparator_ParsesCorrectly()
        {
            // Arrange
            var dataObject = "9F70=040102";

            // Act
            var (tag, data) = DataObjectParser.ParseRawDataObject(dataObject);

            // Assert
            Assert.Equal(0x9F70, tag);
            Assert.Equal(new byte[] { 0x04, 0x01, 0x02 }, data);
        }

        [Fact]
        public void ParseRawDataObject_WithLongData_ParsesCorrectly()
        {
            // Arrange
            var dataObject = "DF21:112233445566778899AABBCCDDEEFF";

            // Act
            var (tag, data) = DataObjectParser.ParseRawDataObject(dataObject);

            // Assert
            Assert.Equal(0xDF21, tag);
            Assert.Equal(16, data.Length);
            Assert.Equal(0x11, data[0]);
            Assert.Equal(0xFF, data[15]);
        }

        [Fact]
        public void ParseRawDataObject_WithSingleByteTag_ParsesCorrectly()
        {
            // Arrange
            var dataObject = "C0:01020304";

            // Act
            var (tag, data) = DataObjectParser.ParseRawDataObject(dataObject);

            // Assert
            Assert.Equal(0x00C0, tag);
            Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04 }, data);
        }

        [Fact]
        public void ParseRawDataObject_WithEmptyData_ParsesCorrectly()
        {
            // Arrange
            var dataObject = "9F70:";

            // Act
            var (tag, data) = DataObjectParser.ParseRawDataObject(dataObject);

            // Assert
            Assert.Equal(0x9F70, tag);
            Assert.Empty(data);
        }

        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData(null)]
        public void ParseRawDataObject_WithEmptyInput_ThrowsArgumentException(string dataObject)
        {
            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => DataObjectParser.ParseRawDataObject(dataObject));
            Assert.Contains("Data object cannot be null or empty", ex.Message);
        }

        [Theory]
        [InlineData("9F70")]
        [InlineData("9F70-040102")]
        [InlineData("9F70_040102")]
        [InlineData("InvalidFormat")]
        public void ParseRawDataObject_WithInvalidFormat_ThrowsArgumentException(string dataObject)
        {
            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => DataObjectParser.ParseRawDataObject(dataObject));
            Assert.Contains("Invalid data object format", ex.Message);
        }

        [Theory]
        [InlineData("GHIJ:040102")]
        [InlineData("9Z70:040102")]
        [InlineData("9F7G:040102")]
        public void ParseRawDataObject_WithInvalidHexTag_ThrowsArgumentException(string dataObject)
        {
            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => DataObjectParser.ParseRawDataObject(dataObject));
            Assert.Contains("Invalid data object format", ex.Message);
        }

        [Theory]
        [InlineData("9F70:04010")]
        [InlineData("9F70:0401G2")]
        [InlineData("9F70:ZZ")]
        public void ParseRawDataObject_WithOddHexData_ThrowsArgumentException(string dataObject)
        {
            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => DataObjectParser.ParseRawDataObject(dataObject));
            Assert.Contains("even number of hex characters", ex.Message);
        }

        [Theory]
        [InlineData("9F70:040102", 0x9F70)]
        [InlineData("DF21:1122", 0xDF21)]
        [InlineData("C0:33", 0x00C0)]
        [InlineData("5F2D:0011", 0x5F2D)]
        public void ValidateDataObject_WithValidTag_ReturnsTrue(string dataObject, ushort expectedTag)
        {
            // Arrange
            var (tag, data) = DataObjectParser.ParseRawDataObject(dataObject);

            // Act
            var isValid = DataObjectParser.ValidateDataObject(tag, data);

            // Assert
            Assert.True(isValid);
            Assert.Equal(expectedTag, tag);
        }

        [Fact]
        public void ValidateDataObject_WithZeroTag_ReturnsFalse()
        {
            // Arrange
            ushort tag = 0x0000;
            var data = new byte[] { 0x01, 0x02 };

            // Act
            var isValid = DataObjectParser.ValidateDataObject(tag, data);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void ValidateDataObject_WithNullData_ReturnsFalse()
        {
            // Arrange
            ushort tag = 0x9F70;
            byte[] data = null;

            // Act
            var isValid = DataObjectParser.ValidateDataObject(tag, data);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void ValidateDataObject_WithEmptyData_ReturnsTrue()
        {
            // Arrange
            ushort tag = 0x9F70;
            var data = Array.Empty<byte>();

            // Act
            var isValid = DataObjectParser.ValidateDataObject(tag, data);

            // Assert
            Assert.True(isValid); // Empty data is allowed for some tags
        }

        [Theory]
        [InlineData("9f70:040102")]
        [InlineData("9F70:040102")]
        [InlineData("df21:AABBCC")]
        [InlineData("DF21:aabbcc")]
        public void ParseRawDataObject_IsCaseInsensitive(string dataObject)
        {
            // Act & Assert - Should not throw
            var (tag, data) = DataObjectParser.ParseRawDataObject(dataObject);
            Assert.True(tag > 0);
            Assert.NotNull(data);
        }
    }
}