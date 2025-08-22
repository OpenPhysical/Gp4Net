using AwesomeAssertions;
using Gp4Net.Core.Tlv;
using NUnit.Framework;

namespace Gp4Net.Tests.Core.Tlv;

/// <summary>
/// Tests for the TLV parser functionality.
/// </summary>
[TestFixture]
[Category("Unit")]
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
        _ = tlv.HasValue.Should().BeTrue();
        _ = tlv.Value.Tag.Should().BeEquivalentTo(new byte[] { 0x80 });
        _ = tlv.Value.Length.Should().Be(2);
        _ = tlv.Value.Value.Should().BeEquivalentTo(new byte[] { 0x01, 0x02 });
    }

    [Test]
    public void ParseSingle_WithMultiByteTag_ParsesCorrectly()
    {
        // Arrange - Multi-byte tag: 0x9F70
        var data = new byte[] { 0x9F, 0x70, 0x03, 0x01, 0x02, 0x03 };

        // Act
        var tlv = TlvParser.ParseSingle(data);

        // Assert
        _ = tlv.HasValue.Should().BeTrue();
        _ = tlv.Value.Tag.Should().BeEquivalentTo(new byte[] { 0x9F, 0x70 });
        _ = tlv.Value.Length.Should().Be(3);
        _ = tlv.Value.Value.Should().BeEquivalentTo(new byte[] { 0x01, 0x02, 0x03 });
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
        for (var i = 0; i < 128; i++)
        {
            data[3 + i] = (byte)(i & 0xFF);
        }

        // Act
        var tlv = TlvParser.ParseSingle(data);

        // Assert
        _ = tlv.HasValue.Should().BeTrue();
        _ = tlv.Value.Tag.Should().BeEquivalentTo(new byte[] { 0x80 });
        _ = tlv.Value.Length.Should().Be(128);
        _ = tlv.Value.Length.Should().Be(128);
        // Verify actual pattern in value matches expected sequence
        for (var i = 0; i < 128; i++)
        {
            _ = tlv.Value.Value[i].Should().Be((byte)(i & 0xFF));
        }
    }

    [Test]
    public void ParseSingle_WithEmptyValue_ParsesCorrectly()
    {
        // Arrange - TLV with zero-length value
        var data = new byte[] { 0x80, 0x00 };

        // Act
        var tlv = TlvParser.ParseSingle(data);

        // Assert
        _ = tlv.HasValue.Should().BeTrue();
        _ = tlv.Value.Tag.Should().BeEquivalentTo(new byte[] { 0x80 });
        _ = tlv.Value.Length.Should().Be(0);
        _ = tlv.Value.Value.Should().BeEmpty();
    }

    [Test]
    public void ParseSingle_WithInvalidData_ReturnsNull()
    {
        // Arrange - Incomplete TLV (missing value bytes)
        var data = new byte[] { 0x80, 0x05, 0x01, 0x02 }; // Says 5 bytes but only has 2

        // Act
        var tlv = TlvParser.ParseSingle(data);

        // Assert
        _ = tlv.HasValue.Should().BeFalse();
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
        _ = tlvList.Should().NotBeNull();
        _ = tlvList.Should().HaveCount(3);
        _ = tlvList![0].Tag.Should().BeEquivalentTo(new byte[] { 0x80 });
        _ = tlvList[1].Tag.Should().BeEquivalentTo(new byte[] { 0x81 });
        _ = tlvList[2].Tag.Should().BeEquivalentTo(new byte[] { 0x82 });
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
        _ = tlvList.Should().NotBeNull();
        _ = tlvList.Should().HaveCount(1);
        _ = tlvList![0].Tag.Should().BeEquivalentTo(new byte[] { 0x80 });
        _ = tlvList[0].Length.Should().Be(5);

        // Parse nested content
        var nested = tlvList[0].ParseNestedTlv();
        _ = nested.Should().HaveCount(2);
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
        _ = found.HasValue.Should().BeTrue();
        _ = found.Value.Tag.Should().BeEquivalentTo(new byte[] { 0x81 });
        _ = found.Value.Value.Should().BeEquivalentTo(new byte[] { 0x03 });
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
        _ = found.HasValue.Should().BeTrue();
        _ = found.Value.Tag.Should().BeEquivalentTo(new byte[] { 0x9F, 0x70 });
        _ = found.Value.Value.Should().BeEquivalentTo(new byte[] { 0x03 });
    }

    [Test]
    public void TlvObject_GetValueAsNumber_ConvertsCorrectly()
    {
        // Arrange
        var tlv = new TlvObject([0x80], [0x01, 0x23, 0x45]);

        // Act
        var number = tlv.GetValueAsNumber();

        // Assert
        _ = number.HasValue.Should().BeTrue();
        _ = number.Value.Should().Be(0x012345);
    }

    [Test]
    public void TlvObject_GetValueAsHexString_FormatsCorrectly()
    {
        // Arrange
        var tlv = new TlvObject([0x80], [0x01, 0x23, 0x45, 0x67]);

        // Act
        var hexString = tlv.GetValueAsHexString();

        // Assert
        _ = hexString.Should().Be("01234567");
    }

    [Test]
    public void TagToNumber_ConvertsCorrectly()
    {
        // Arrange & Act & Assert
        _ = TlvParser.TagToNumber([0x80]).Should().Be(0x80u);
        _ = TlvParser.TagToNumber([0x9F, 0x70]).Should().Be(0x9F70u);
        _ = TlvParser.TagToNumber([0x9F, 0x7F, 0x2A]).Should().Be(0x9F7F2Au);
    }

    [Test]
    public void NumberToTag_ConvertsCorrectly()
    {
        // Arrange & Act & Assert
        _ = TlvParser.NumberToTag(0x80).Should().BeEquivalentTo(new byte[] { 0x80 });
        _ = TlvParser.NumberToTag(0x9F70).Should().BeEquivalentTo(new byte[] { 0x9F, 0x70 });
        _ = TlvParser.NumberToTag(0x9F7F2A).Should().BeEquivalentTo(new byte[] { 0x9F, 0x7F, 0x2A });
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
        var tlv = TlvParser.ParseSingle(data, 3, out var consumed);

        // Assert
        _ = tlv.HasValue.Should().BeTrue();
        _ = tlv.Value.Tag.Should().BeEquivalentTo(new byte[] { 0x80 });
        _ = tlv.Value.Value.Should().BeEquivalentTo(new byte[] { 0x01, 0x02 });
        _ = consumed.Should().Be(4); // Tag(1) + Length(1) + Value(2)
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
        _ = tlv.HasValue.Should().BeFalse();
    }
}
