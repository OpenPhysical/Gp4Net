using System.Collections.Generic;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
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
        byte[] data = [0x80, 0x02, 0x01, 0x02];

        // Act
        Maybe<TlvObject> tlv = TlvParser.ParseSingle(data);

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
        byte[] data = [0x9F, 0x70, 0x03, 0x01, 0x02, 0x03];

        // Act
        Maybe<TlvObject> tlv = TlvParser.ParseSingle(data);

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
        byte[] data = new byte[131]; // Tag(1) + Length(2) + Value(128)
        data[0] = 0x80; // Tag
        data[1] = 0x81; // Long form, 1 byte follows
        data[2] = 0x80; // Length = 128
        // Fill value with test pattern
        for (int i = 0; i < 128; i++)
        {
            data[3 + i] = (byte)(i & 0xFF);
        }

        // Act
        Maybe<TlvObject> tlv = TlvParser.ParseSingle(data);

        // Assert
        _ = tlv.HasValue.Should().BeTrue();
        _ = tlv.Value.Tag.Should().BeEquivalentTo(new byte[] { 0x80 });
        _ = tlv.Value.Length.Should().Be(128);
        _ = tlv.Value.Length.Should().Be(128);
        // Verify actual pattern in value matches expected sequence
        for (int i = 0; i < 128; i++)
        {
            _ = tlv.Value.Value[i].Should().Be((byte)(i & 0xFF));
        }
    }

    [Test]
    public void ParseSingle_WithEmptyValue_ParsesCorrectly()
    {
        // Arrange - TLV with zero-length value
        byte[] data = [0x80, 0x00];

        // Act
        Maybe<TlvObject> tlv = TlvParser.ParseSingle(data);

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
        byte[] data = [0x80, 0x05, 0x01, 0x02]; // Says 5 bytes but only has 2

        // Act
        Maybe<TlvObject> tlv = TlvParser.ParseSingle(data);

        // Assert
        _ = tlv.HasValue.Should().BeFalse();
    }

    [Test]
    public void ParseAll_WithMultipleTlvObjects_ParsesAll()
    {
        // Arrange - Multiple TLV objects
        byte[] data =
        [
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
            0x06 // Third TLV
        ];

        // Act
        IReadOnlyList<TlvObject>? tlvList = TlvParser.ParseAll(data);

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
        byte[] nestedData = [0x81, 0x01, 0xFF];
        byte[] data =
        [
            0x80,
            0x05, // Container tag
            0x81,
            0x01,
            0xFF, // Nested TLV
            0x82,
            0x00 // Empty nested TLV
        ];

        // Act
        IReadOnlyList<TlvObject>? tlvList = TlvParser.ParseAll(data);

        // Assert
        _ = tlvList.Should().NotBeNull();
        _ = tlvList.Should().HaveCount(1);
        _ = tlvList![0].Tag.Should().BeEquivalentTo(new byte[] { 0x80 });
        _ = tlvList[0].Length.Should().Be(5);

        // Parse nested content
        IReadOnlyList<TlvObject>? nested = tlvList[0].ParseNestedTlv();
        _ = nested.Should().HaveCount(2);
    }

    [Test]
    public void FindByTag_WithSingleByteTag_FindsCorrectObject()
    {
        // Arrange
        byte[] data =
        [
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
            0x06
        ];

        // Act
        Maybe<TlvObject> found = TlvParser.FindByTag(data, 0x81);

        // Assert
        _ = found.HasValue.Should().BeTrue();
        _ = found.Value.Tag.Should().BeEquivalentTo(new byte[] { 0x81 });
        _ = found.Value.Value.Should().BeEquivalentTo(new byte[] { 0x03 });
    }

    [Test]
    public void FindByTag_WithTwoByteTag_FindsCorrectObject()
    {
        // Arrange
        byte[] data =
        [
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
            0x06
        ];

        // Act
        Maybe<TlvObject> found = TlvParser.FindByTag(data, (ushort)0x9F70);

        // Assert
        _ = found.HasValue.Should().BeTrue();
        _ = found.Value.Tag.Should().BeEquivalentTo(new byte[] { 0x9F, 0x70 });
        _ = found.Value.Value.Should().BeEquivalentTo(new byte[] { 0x03 });
    }

    [Test]
    public void TlvObject_GetValueAsNumber_ConvertsCorrectly()
    {
        // Arrange
        TlvObject tlv = new TlvObject([0x80], [0x01, 0x23, 0x45]);

        // Act
        Maybe<uint> number = tlv.GetValueAsNumber();

        // Assert
        _ = number.HasValue.Should().BeTrue();
        _ = number.Value.Should().Be(0x012345);
    }

    [Test]
    public void TlvObject_GetValueAsHexString_FormatsCorrectly()
    {
        // Arrange
        TlvObject tlv = new TlvObject([0x80], [0x01, 0x23, 0x45, 0x67]);

        // Act
        string? hexString = tlv.GetValueAsHexString();

        // Assert
        _ = hexString.Should().Be("01234567");
    }

    [Test]
    public void TagToNumber_ConvertsCorrectly()
    {
        // Arrange & Act & Assert
        Result<uint, SmartCardError> result1 = TlvParser.TagToNumber([0x80]);
        _ = result1.IsSuccess.Should().BeTrue();
        _ = result1.Value.Should().Be(0x80u);

        Result<uint, SmartCardError> result2 = TlvParser.TagToNumber([0x9F, 0x70]);
        _ = result2.IsSuccess.Should().BeTrue();
        _ = result2.Value.Should().Be(0x9F70u);

        Result<uint, SmartCardError> result3 = TlvParser.TagToNumber([0x9F, 0x7F, 0x2A]);
        _ = result3.IsSuccess.Should().BeTrue();
        _ = result3.Value.Should().Be(0x9F7F2Au);
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
        byte[] data =
        [
            0xFF,
            0xFF,
            0xFF, // Junk data
            0x80,
            0x02,
            0x01,
            0x02 // Actual TLV
        ];

        // Act
        Maybe<TlvObject> tlv = TlvParser.ParseSingle(data, 3, out int consumed);

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
        Maybe<TlvObject> tlv = TlvParser.ParseSingle(data);

        // Assert
        _ = tlv.HasValue.Should().BeFalse();
    }
}
