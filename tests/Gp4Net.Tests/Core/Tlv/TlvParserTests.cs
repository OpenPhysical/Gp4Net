using Gp4Net.Core.Tlv;
using NUnit.Framework;

namespace Gp4Net.Tests.Core.Tlv
{
    /// <summary>
    /// Tests for the TLV parser functionality.
    /// </summary>
    [TestFixture]
    public class TlvParserTests
    {
        [Test]
        public void ParseSingle_WithSimpleTlv_ParsesCorrectly()
        {
            // Arrange - Simple TLV: Tag=0x80, Length=2, Value=0x0102
            var data = new byte[] { 0x80, 0x02, 0x01, 0x02 };

            // Act
            var tlv = TlvParser.ParseSingle(data);

            // Assert
            Assert.That(tlv, Is.Not.Null);
            Assert.That(tlv.Tag, Is.EqualTo(new byte[] { 0x80 }));
            Assert.That(tlv.Length, Is.EqualTo(2));
            Assert.That(tlv.Value, Is.EqualTo(new byte[] { 0x01, 0x02 }));
        }

        [Test]
        public void ParseSingle_WithMultiByteTag_ParsesCorrectly()
        {
            // Arrange - Multi-byte tag: 0x9F70
            var data = new byte[] { 0x9F, 0x70, 0x03, 0x01, 0x02, 0x03 };

            // Act
            var tlv = TlvParser.ParseSingle(data);

            // Assert
            Assert.That(tlv, Is.Not.Null);
            Assert.That(tlv.Tag, Is.EqualTo(new byte[] { 0x9F, 0x70 }));
            Assert.That(tlv.Length, Is.EqualTo(3));
            Assert.That(tlv.Value, Is.EqualTo(new byte[] { 0x01, 0x02, 0x03 }));
        }

        [Test]
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
            Assert.That(tlv, Is.Not.Null);
            Assert.That(tlv.Tag, Is.EqualTo(new byte[] { 0x80 }));
            Assert.That(tlv.Length, Is.EqualTo(128));
            Assert.That(tlv.Value.Length, Is.EqualTo(128));
        }

        [Test]
        public void ParseSingle_WithEmptyValue_ParsesCorrectly()
        {
            // Arrange - TLV with zero-length value
            var data = new byte[] { 0x80, 0x00 };

            // Act
            var tlv = TlvParser.ParseSingle(data);

            // Assert
            Assert.That(tlv, Is.Not.Null);
            Assert.That(tlv.Tag, Is.EqualTo(new byte[] { 0x80 }));
            Assert.That(tlv.Length, Is.EqualTo(0));
            Assert.That(tlv.Value, Is.Empty);
        }

        [Test]
        public void ParseSingle_WithInvalidData_ReturnsNull()
        {
            // Arrange - Incomplete TLV (missing value bytes)
            var data = new byte[] { 0x80, 0x05, 0x01, 0x02 }; // Says 5 bytes but only has 2

            // Act
            var tlv = TlvParser.ParseSingle(data);

            // Assert
            Assert.That(tlv, Is.Null);
        }

        [Test]
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
            Assert.That(tlvList.Count, Is.EqualTo(3));
            Assert.That(tlvList[0].Tag, Is.EqualTo(new byte[] { 0x80 }));
            Assert.That(tlvList[1].Tag, Is.EqualTo(new byte[] { 0x81 }));
            Assert.That(tlvList[2].Tag, Is.EqualTo(new byte[] { 0x82 }));
        }

        [Test]
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
            Assert.That(tlvList.Count, Is.EqualTo(1));
            Assert.That(tlvList[0].Tag, Is.EqualTo(new byte[] { 0x80 }));
            Assert.That(tlvList[0].Length, Is.EqualTo(5));

            // Parse nested content
            var nested = tlvList[0].ParseNestedTlv();
            Assert.That(nested.Count, Is.EqualTo(2));
        }

        [Test]
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
            Assert.That(found, Is.Not.Null);
            Assert.That(found.Tag, Is.EqualTo(new byte[] { 0x81 }));
            Assert.That(found.Value, Is.EqualTo(new byte[] { 0x03 }));
        }

        [Test]
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
            Assert.That(found, Is.Not.Null);
            Assert.That(found.Tag, Is.EqualTo(new byte[] { 0x9F, 0x70 }));
            Assert.That(found.Value, Is.EqualTo(new byte[] { 0x03 }));
        }

        [Test]
        public void TlvObject_GetValueAsNumber_ConvertsCorrectly()
        {
            // Arrange
            var tlv = new TlvObject(new byte[] { 0x80 }, new byte[] { 0x01, 0x23, 0x45 });

            // Act
            var number = tlv.GetValueAsNumber();

            // Assert
            Assert.That(number, Is.Not.Null);
            Assert.That(number.Value, Is.EqualTo(0x012345u));
        }

        [Test]
        public void TlvObject_GetValueAsHexString_FormatsCorrectly()
        {
            // Arrange
            var tlv = new TlvObject(new byte[] { 0x80 }, new byte[] { 0x01, 0x23, 0x45, 0x67 });

            // Act
            var hexString = tlv.GetValueAsHexString();

            // Assert
            Assert.That(hexString, Is.EqualTo("01234567"));
        }

        [Test]
        public void TagToNumber_ConvertsCorrectly()
        {
            // Arrange & Act & Assert
            Assert.That(TlvParser.TagToNumber(new byte[] { 0x80 }), Is.EqualTo(0x80u));
            Assert.That(TlvParser.TagToNumber(new byte[] { 0x9F, 0x70 }), Is.EqualTo(0x9F70u));
            Assert.That(TlvParser.TagToNumber(new byte[] { 0x9F, 0x7F, 0x2A }), Is.EqualTo(0x9F7F2Au));
        }

        [Test]
        public void NumberToTag_ConvertsCorrectly()
        {
            // Arrange & Act & Assert
            Assert.That(TlvParser.NumberToTag(0x80), Is.EqualTo(new byte[] { 0x80 }));
            Assert.That(TlvParser.NumberToTag(0x9F70), Is.EqualTo(new byte[] { 0x9F, 0x70 }));
            Assert.That(TlvParser.NumberToTag(0x9F7F2A), Is.EqualTo(new byte[] { 0x9F, 0x7F, 0x2A }));
        }

        [Test]
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
            Assert.That(tlv, Is.Not.Null);
            Assert.That(tlv.Tag, Is.EqualTo(new byte[] { 0x80 }));
            Assert.That(tlv.Value, Is.EqualTo(new byte[] { 0x01, 0x02 }));
            Assert.That(consumed, Is.EqualTo(4)); // Tag(1) + Length(1) + Value(2)
        }

        [Test]
        [TestCase(new byte[] { })] // Empty data
        [TestCase(new byte[] { 0x80 })] // Only tag, no length
        [TestCase(new byte[] { 0x80, 0x82 })] // Long form length incomplete
        [TestCase(new byte[] { 0x9F })] // Multi-byte tag incomplete
        public void ParseSingle_WithInvalidFormats_ReturnsNull(byte[] data)
        {
            // Act
            var tlv = TlvParser.ParseSingle(data);

            // Assert
            Assert.That(tlv, Is.Null);
        }
    }
}
