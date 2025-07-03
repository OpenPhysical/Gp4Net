using Gp4Net.Core.Tlv;
using Xunit;

namespace Gp4Net.Tests.Core.Tlv
{
    /// <summary>
    /// Tests for the TLV parser functionality.
    /// </summary>
    public class TlvParserTests
    {
        [Fact]
        public void ParseSingle_WithSimpleTlv_ParsesCorrectly()
        {
            // Arrange - Simple TLV: Tag=0x80, Length=2, Value=0x0102
            var data = new byte[] { 0x80, 0x02, 0x01, 0x02 };

            // Act
            var tlv = TlvParser.ParseSingle(data);

            // Assert
            Assert.NotNull(tlv);
            Assert.Equal(new byte[] { 0x80 }, tlv.Tag);
            Assert.Equal(2, tlv.Length);
            Assert.Equal(new byte[] { 0x01, 0x02 }, tlv.Value);
        }

        [Fact]
        public void ParseSingle_WithMultiByteTag_ParsesCorrectly()
        {
            // Arrange - Multi-byte tag: 0x9F70
            var data = new byte[] { 0x9F, 0x70, 0x03, 0x01, 0x02, 0x03 };

            // Act
            var tlv = TlvParser.ParseSingle(data);

            // Assert
            Assert.NotNull(tlv);
            Assert.Equal(new byte[] { 0x9F, 0x70 }, tlv.Tag);
            Assert.Equal(3, tlv.Length);
            Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, tlv.Value);
        }

        [Fact]
        public void ParseSingle_WithLongFormLength_ParsesCorrectly()
        {
            // Arrange - Long form length: 0x81 0x80 (128 bytes)
            var data = new byte[131]; // Tag(1) + Length(2) + Value(128)
            data[0] = 0x80; // Tag
            data[1] = 0x81; // Long form, 1 byte follows
            data[2] = 0x80; // Length = 128
            // Fill value with test pattern
            for (int i = 0; i < 128; i++)
            {
                data[3 + i] = (byte)(i & 0xFF);
            }

            // Act
            var tlv = TlvParser.ParseSingle(data);

            // Assert
            Assert.NotNull(tlv);
            Assert.Equal(new byte[] { 0x80 }, tlv.Tag);
            Assert.Equal(128, tlv.Length);
            Assert.Equal(128, tlv.Value.Length);
        }

        [Fact]
        public void ParseSingle_WithEmptyValue_ParsesCorrectly()
        {
            // Arrange - TLV with zero-length value
            var data = new byte[] { 0x80, 0x00 };

            // Act
            var tlv = TlvParser.ParseSingle(data);

            // Assert
            Assert.NotNull(tlv);
            Assert.Equal(new byte[] { 0x80 }, tlv.Tag);
            Assert.Equal(0, tlv.Length);
            Assert.Empty(tlv.Value);
        }

        [Fact]
        public void ParseSingle_WithInvalidData_ReturnsNull()
        {
            // Arrange - Incomplete TLV (missing value bytes)
            var data = new byte[] { 0x80, 0x05, 0x01, 0x02 }; // Says 5 bytes but only has 2

            // Act
            var tlv = TlvParser.ParseSingle(data);

            // Assert
            Assert.Null(tlv);
        }

        [Fact]
        public void ParseAll_WithMultipleTlvObjects_ParsesAll()
        {
            // Arrange - Multiple TLV objects
            var data = new byte[]
            {
                0x80,
                0x02,
                0x01,
                0x02, // First TLV
                0x81,
                0x01,
                0x03, // Second TLV
                0x82,
                0x03,
                0x04,
                0x05,
                0x06, // Third TLV
            };

            // Act
            var tlvList = TlvParser.ParseAll(data);

            // Assert
            Assert.Equal(3, tlvList.Count);
            Assert.Equal(new byte[] { 0x80 }, tlvList[0].Tag);
            Assert.Equal(new byte[] { 0x81 }, tlvList[1].Tag);
            Assert.Equal(new byte[] { 0x82 }, tlvList[2].Tag);
        }

        [Fact]
        public void ParseAll_WithNestedTlv_ParsesTopLevel()
        {
            // Arrange - Nested TLV structure
            var nestedData = new byte[] { 0x81, 0x01, 0xFF };
            var data = new byte[]
            {
                0x80,
                0x05, // Container tag
                0x81,
                0x01,
                0xFF, // Nested TLV
                0x82,
                0x00, // Empty nested TLV
            };

            // Act
            var tlvList = TlvParser.ParseAll(data);

            // Assert
            _ = Assert.Single(tlvList);
            Assert.Equal(new byte[] { 0x80 }, tlvList[0].Tag);
            Assert.Equal(5, tlvList[0].Length);

            // Parse nested content
            var nested = tlvList[0].ParseNestedTlv();
            Assert.Equal(2, nested.Count);
        }

        [Fact]
        public void FindByTag_WithSingleByteTag_FindsCorrectObject()
        {
            // Arrange
            var data = new byte[]
            {
                0x80,
                0x02,
                0x01,
                0x02,
                0x81,
                0x01,
                0x03,
                0x82,
                0x03,
                0x04,
                0x05,
                0x06,
            };

            // Act
            var found = TlvParser.FindByTag(data, 0x81);

            // Assert
            Assert.NotNull(found);
            Assert.Equal(new byte[] { 0x81 }, found.Tag);
            Assert.Equal(new byte[] { 0x03 }, found.Value);
        }

        [Fact]
        public void FindByTag_WithTwoByteTag_FindsCorrectObject()
        {
            // Arrange
            var data = new byte[]
            {
                0x80,
                0x02,
                0x01,
                0x02,
                0x9F,
                0x70,
                0x01,
                0x03,
                0x82,
                0x03,
                0x04,
                0x05,
                0x06,
            };

            // Act
            var found = TlvParser.FindByTag(data, (ushort)0x9F70);

            // Assert
            Assert.NotNull(found);
            Assert.Equal(new byte[] { 0x9F, 0x70 }, found.Tag);
            Assert.Equal(new byte[] { 0x03 }, found.Value);
        }

        [Fact]
        public void TlvObject_GetValueAsNumber_ConvertsCorrectly()
        {
            // Arrange
            var tlv = new TlvObject(new byte[] { 0x80 }, new byte[] { 0x01, 0x23, 0x45 });

            // Act
            var number = tlv.GetValueAsNumber();

            // Assert
            _ = Assert.NotNull(number);
            Assert.Equal(0x012345u, number.Value);
        }

        [Fact]
        public void TlvObject_GetValueAsHexString_FormatsCorrectly()
        {
            // Arrange
            var tlv = new TlvObject(new byte[] { 0x80 }, new byte[] { 0x01, 0x23, 0x45, 0x67 });

            // Act
            var hexString = tlv.GetValueAsHexString();

            // Assert
            Assert.Equal("01234567", hexString);
        }

        [Fact]
        public void TagToNumber_ConvertsCorrectly()
        {
            // Arrange & Act & Assert
            Assert.Equal(0x80u, TlvParser.TagToNumber(new byte[] { 0x80 }));
            Assert.Equal(0x9F70u, TlvParser.TagToNumber(new byte[] { 0x9F, 0x70 }));
            Assert.Equal(0x9F7F2Au, TlvParser.TagToNumber(new byte[] { 0x9F, 0x7F, 0x2A }));
        }

        [Fact]
        public void NumberToTag_ConvertsCorrectly()
        {
            // Arrange & Act & Assert
            Assert.Equal(new byte[] { 0x80 }, TlvParser.NumberToTag(0x80));
            Assert.Equal(new byte[] { 0x9F, 0x70 }, TlvParser.NumberToTag(0x9F70));
            Assert.Equal(new byte[] { 0x9F, 0x7F, 0x2A }, TlvParser.NumberToTag(0x9F7F2A));
        }

        [Fact]
        public void ParseSingle_WithOffset_ParsesFromCorrectPosition()
        {
            // Arrange
            var data = new byte[]
            {
                0xFF,
                0xFF,
                0xFF, // Junk data
                0x80,
                0x02,
                0x01,
                0x02, // Actual TLV
            };

            // Act
            var tlv = TlvParser.ParseSingle(data, 3, out int consumed);

            // Assert
            Assert.NotNull(tlv);
            Assert.Equal(new byte[] { 0x80 }, tlv.Tag);
            Assert.Equal(new byte[] { 0x01, 0x02 }, tlv.Value);
            Assert.Equal(4, consumed); // Tag(1) + Length(1) + Value(2)
        }

        [Xunit.Theory]
        [InlineData(new byte[] { }, null)] // Empty data
        [InlineData(new byte[] { 0x80 }, null)] // Only tag, no length
        [InlineData(new byte[] { 0x80, 0x82 }, null)] // Long form length incomplete
        [InlineData(new byte[] { 0x9F }, null)] // Multi-byte tag incomplete
        public void ParseSingle_WithInvalidFormats_ReturnsNull(byte[] data, object expected)
        {
            // Act
            var tlv = TlvParser.ParseSingle(data);

            // Assert
            Assert.Null(tlv);
        }
    }
}
