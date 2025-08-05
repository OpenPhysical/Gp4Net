using System.Linq;
using AwesomeAssertions;
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
        var data = new byte[]
        {
            0xC0,
            0x04, // Tag C0, length 4
            0x01, // Key ID = 1
            0x01, // Key version = 1
            0x82, // 3DES-3KEY
            0xFF // Not available
        };

        // Act
        var template = KeyInformationTemplate.Parse(data);

        // Assert
        template.IsSuccess.Should().BeTrue();
        template.Value.Keys.Should().HaveCount(1);

        var key = template.Value.Keys.First();
        key.KeyId.Should().Be(1);
        key.KeyVersion.Should().Be(1);
        key.KeyTypes.Should().HaveCount(2);
        key.KeyTypes[0].Should().Be(KeyType.TripleDes3Key);
        key.KeyTypes[1].Should().Be(KeyType.NotAvailable);
        key.KeyLength.Should().Be(192);
    }

    [Test]
    public void Parse_WithAesKey_ParsesCorrectly()
    {
        // Arrange - AES key
        var data = new byte[]
        {
            0xC0,
            0x03, // Tag C0, length 3
            0x10, // Key ID = 16
            0x02, // Key version = 2
            0x88 // AES
        };

        // Act
        var template = KeyInformationTemplate.Parse(data);

        // Assert
        template.Should().NotBeNull();
        var key = template.Value.Keys.First();
        key.KeyId.Should().Be(16);
        key.KeyVersion.Should().Be(2);
        key.PrimaryKeyType.Should().Be(KeyType.Aes);
        key.KeyLength.Should().Be(128); // Default AES length
    }

    [Test]
    public void Parse_WithMultipleKeyTypes_ParsesAllTypes()
    {
        // Arrange - Key supporting multiple types
        var data = new byte[]
        {
            0xC0,
            0x05, // Tag C0, length 5
            0x20, // Key ID = 32
            0x03, // Key version = 3
            0x80, // DES
            0x81, // 3DES-2KEY
            0x82 // 3DES-3KEY
        };

        // Act
        var template = KeyInformationTemplate.Parse(data);

        // Assert
        var key = template.Value.Keys.First();
        key.KeyTypes.Should().HaveCount(3);
        key.KeyTypes.Should().Contain(KeyType.Des);
        key.KeyTypes.Should().Contain(KeyType.TripleDes2Key);
        key.KeyTypes.Should().Contain(KeyType.TripleDes3Key);
        key.PrimaryKeyType.Should().Be(KeyType.Des); // First type
        key.KeyLength.Should().Be(64); // DES length
    }

    [Test]
    public void Parse_RealWorldExample_ParsesCorrectly()
    {
        // Arrange - Real world example from trace
        var data = new byte[]
        {
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
            0xFF // Key 2, version 1, AES
        };

        // Act - Parse the value inside E0 tag
        var template = KeyInformationTemplate.Parse(data[2..]);

        // Assert
        template.Value.Keys.Should().HaveCount(4);

        // First three keys have same ID but different versions
        template.Value.Keys[0].KeyId.Should().Be(1);
        template.Value.Keys[0].KeyVersion.Should().Be(1);

        template.Value.Keys[1].KeyId.Should().Be(1);
        template.Value.Keys[1].KeyVersion.Should().Be(2);

        template.Value.Keys[2].KeyId.Should().Be(1);
        template.Value.Keys[2].KeyVersion.Should().Be(3);

        // Fourth key has different ID
        template.Value.Keys[3].KeyId.Should().Be(2);
        template.Value.Keys[3].KeyVersion.Should().Be(1);

        // All are AES keys
        foreach (var key in template.Value.Keys)
        {
            key.PrimaryKeyType.Should().Be(KeyType.Aes);
        }
    }

    [Test]
    public void KeyEntry_ToString_FormatsCorrectly()
    {
        // Arrange
        var data = new byte[]
        {
            0xC0,
            0x03,
            0x01,
            0x02,
            0x88 // Key 1, version 2, AES
        };

        // Act
        var template = KeyInformationTemplate.Parse(data);
        var output = template.Value.Keys.First().ToString();

        // Assert
        output.Should().Contain("Version: 2 (0x02)");
        output.Should().Contain("ID: 1 (0x01)");
        output.Should().Contain("type: AES");
        output.Should().Contain("length: 16"); // 128 bits / 8
    }

    [Test]
    public void KeyInformationTemplate_ToString_FormatsCorrectly()
    {
        // Arrange
        var data = new byte[]
        {
            0xC0,
            0x04,
            0x01,
            0x01,
            0x82,
            0xFF,
            0xC0,
            0x04,
            0x02,
            0x01,
            0x88,
            0xFF
        };

        // Act
        var template = KeyInformationTemplate.Parse(data);
        var output = template.ToString();

        // Assert
        output.Should().Contain("Key Information Template:");
        output.Should().Contain("Version: 1");
        output.Should().Contain("3DES");
        output.Should().Contain("AES");
    }

    [Test]
    public void KeyTypeExtensions_ToFriendlyString_ReturnsCorrectNames()
    {
        // Assert various key types format correctly
        KeyType.Des.ToFriendlyString().Should().BeEquivalentTo("DES");
        KeyType.TripleDes2Key.ToFriendlyString().Should().BeEquivalentTo("3DES-2KEY");
        KeyType.TripleDes3Key.ToFriendlyString().Should().BeEquivalentTo("3DES-3KEY");
        KeyType.Des3.ToFriendlyString().Should().BeEquivalentTo("3DES");
        KeyType.Aes.ToFriendlyString().Should().BeEquivalentTo("AES");
        KeyType.NotAvailable.ToFriendlyString().Should().BeEquivalentTo("N/A");
        KeyType.Unknown.ToFriendlyString().Should().BeEquivalentTo("Unknown(0x00)");
    }

    [Test]
    public void Parse_EmptyData_ReturnsFailure()
    {
        // Arrange
        var emptyData = new byte[0];

        // Act
        var result = KeyInformationTemplate.Parse(emptyData);

        // Assert
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
    }

    [Test]
    public void Parse_ShortKeyData_HandlesGracefully()
    {
        // Arrange - Key data too short (less than 3 bytes)
        var data = new byte[]
        {
            0xC0,
            0x02, // Tag C0, length 2
            0x01,
            0x01 // Only ID and version, no type
        };

        // Act
        var template = KeyInformationTemplate.Parse(data);

        // Assert
        template.Value.Keys.Should().BeEmpty(); // Should not add incomplete key
    }
}