using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.CardInfo;

[TestFixture]
public class KeyInformationTemplateTests
{
    [Test]
    public void Parse_WithSingleKey_ParsesCorrectly()
    {
        // Arrange - Single key with 3DES
        byte[] data =
        [
            0xC0,
            0x04, // Tag C0, length 4
            0x01, // Key ID = 1
            0x01, // Key version = 1
            0x82, // 3DES-3KEY
            0xFF, // Not available
        ];

        // Act
        Result<KeyInformationTemplate, SmartCardError> template = KeyInformationTemplate.Parse(
            data
        );

        // Assert
        _ = template.IsSuccess.Should().BeTrue();
        _ = template.Value.Keys.Should().HaveCount(1);

        KeyEntry? key = template.Value.Keys.First();
        _ = key.KeyId.Should().Be(1);
        _ = key.KeyVersion.Should().Be(1);
        _ = key.KeyTypes.Should().HaveCount(2);
        _ = key.KeyTypes[0].Should().Be(KeyType.TripleDes3Key);
        _ = key.KeyTypes[1].Should().Be(KeyType.NotAvailable);
        _ = key.KeyLength.Should().Be(192);
    }

    [Test]
    public void Parse_WithAesKey_ParsesCorrectly()
    {
        // Arrange - AES key
        byte[] data =
        [
            0xC0,
            0x03, // Tag C0, length 3
            0x10, // Key ID = 16
            0x02, // Key version = 2
            0x88, // AES
        ];

        // Act
        Result<KeyInformationTemplate, SmartCardError> template = KeyInformationTemplate.Parse(
            data
        );

        // Assert
        _ = template.Should().NotBeNull();
        KeyEntry? key = template.Value.Keys.First();
        _ = key.KeyId.Should().Be(16);
        _ = key.KeyVersion.Should().Be(2);
        _ = key.PrimaryKeyType.Should().Be(KeyType.Aes);
        _ = key.KeyLength.Should().Be(128); // Default AES length
    }

    [Test]
    public void Parse_WithMultipleKeyTypes_ParsesAllTypes()
    {
        // Arrange - Key supporting multiple types
        byte[] data =
        [
            0xC0,
            0x05, // Tag C0, length 5
            0x20, // Key ID = 32
            0x03, // Key version = 3
            0x80, // DES
            0x81, // 3DES-2KEY
            0x82, // 3DES-3KEY
        ];

        // Act
        Result<KeyInformationTemplate, SmartCardError> template = KeyInformationTemplate.Parse(
            data
        );

        // Assert
        KeyEntry? key = template.Value.Keys.First();
        _ = key.KeyTypes.Should().HaveCount(3);
        _ = key.KeyTypes.Should().Contain(KeyType.Des);
        _ = key.KeyTypes.Should().Contain(KeyType.TripleDes2Key);
        _ = key.KeyTypes.Should().Contain(KeyType.TripleDes3Key);
        _ = key.PrimaryKeyType.Should().Be(KeyType.Des); // First type
        _ = key.KeyLength.Should().Be(64); // DES length
    }

    [Test]
    public void Parse_RealWorldExample_ParsesCorrectly()
    {
        // Arrange - Real world example from trace
        byte[] data =
        [
            0xE0,
            0x1A, // Tag E0, length 26
            0xC0,
            0x04,
            0x01,
            0x01,
            0x88,
            0xFF, // Key 1, version 1, AES
            0xC0,
            0x04,
            0x01,
            0x02,
            0x88,
            0xFF, // Key 1, version 2, AES
            0xC0,
            0x04,
            0x01,
            0x03,
            0x88,
            0xFF, // Key 1, version 3, AES
            0xC0,
            0x04,
            0x02,
            0x01,
            0x88,
            0xFF, // Key 2, version 1, AES
        ];

        // Act - Parse the value inside E0 tag
        Result<KeyInformationTemplate, SmartCardError> template = KeyInformationTemplate.Parse(
            data[2..]
        );

        // Assert
        _ = template.Value.Keys.Should().HaveCount(4);

        // First three keys have same ID but different versions
        _ = template.Value.Keys[0].KeyId.Should().Be(1);
        _ = template.Value.Keys[0].KeyVersion.Should().Be(1);

        _ = template.Value.Keys[1].KeyId.Should().Be(1);
        _ = template.Value.Keys[1].KeyVersion.Should().Be(2);

        _ = template.Value.Keys[2].KeyId.Should().Be(1);
        _ = template.Value.Keys[2].KeyVersion.Should().Be(3);

        // Fourth key has different ID
        _ = template.Value.Keys[3].KeyId.Should().Be(2);
        _ = template.Value.Keys[3].KeyVersion.Should().Be(1);

        // All are AES keys
        foreach (KeyEntry? key in template.Value.Keys)
        {
            _ = key.PrimaryKeyType.Should().Be(KeyType.Aes);
        }
    }

    [Test]
    public void KeyEntry_ToString_FormatsCorrectly()
    {
        // Arrange
        byte[] data =
        [
            0xC0,
            0x03,
            0x01,
            0x02,
            0x88, // Key 1, version 2, AES
        ];

        // Act
        Result<KeyInformationTemplate, SmartCardError> template = KeyInformationTemplate.Parse(
            data
        );
        string? output = template.Value.Keys.First().ToString();

        // Assert
        _ = output.Should().Contain("Version: 2 (0x02)");
        _ = output.Should().Contain("ID: 1 (0x01)");
        _ = output.Should().Contain("type: AES");
        _ = output.Should().Contain("length: 16"); // 128 bits / 8
    }

    [Test]
    public void KeyInformationTemplate_ToString_FormatsCorrectly()
    {
        // Arrange
        byte[] data = [0xC0, 0x04, 0x01, 0x01, 0x82, 0xFF, 0xC0, 0x04, 0x02, 0x01, 0x88, 0xFF];

        // Act
        Result<KeyInformationTemplate, SmartCardError> template = KeyInformationTemplate.Parse(
            data
        );
        string? output = template.ToString();

        // Assert
        _ = output.Should().Contain("Key Information Template:");
        _ = output.Should().Contain("Version: 1");
        _ = output.Should().Contain("3DES");
        _ = output.Should().Contain("AES");
    }

    [Test]
    public void KeyTypeExtensions_ToFriendlyString_ReturnsCorrectNames()
    {
        // Assert various key types format correctly
        _ = KeyType.Des.ToFriendlyString().Should().BeEquivalentTo("DES");
        _ = KeyType.TripleDes2Key.ToFriendlyString().Should().BeEquivalentTo("3DES-2KEY");
        _ = KeyType.TripleDes3Key.ToFriendlyString().Should().BeEquivalentTo("3DES-3KEY");
        _ = KeyType.Des3.ToFriendlyString().Should().BeEquivalentTo("3DES");
        _ = KeyType.Aes.ToFriendlyString().Should().BeEquivalentTo("AES");
        _ = KeyType.NotAvailable.ToFriendlyString().Should().BeEquivalentTo("N/A");
        _ = KeyType.Unknown.ToFriendlyString().Should().BeEquivalentTo("Unknown(0x00)");
    }

    [Test]
    public void Parse_EmptyData_ReturnsFailure()
    {
        // Arrange
        byte[] emptyData = [];

        // Act
        Result<KeyInformationTemplate, SmartCardError> result = KeyInformationTemplate.Parse(
            emptyData
        );

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        // This should ideally be EmptyDataError for empty data validation
    }

    [Test]
    public void Parse_ShortKeyData_HandlesGracefully()
    {
        // Arrange - Key data too short (less than 3 bytes)
        byte[] data =
        [
            0xC0,
            0x02, // Tag C0, length 2
            0x01,
            0x01, // Only ID and version, no type
        ];

        // Act
        Result<KeyInformationTemplate, SmartCardError> template = KeyInformationTemplate.Parse(
            data
        );

        // Assert
        _ = template.Value.Keys.Should().BeEmpty(); // Should not add incomplete key
    }
}
