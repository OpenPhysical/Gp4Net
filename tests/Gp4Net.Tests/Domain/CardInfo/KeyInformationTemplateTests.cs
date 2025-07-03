using System.Linq;
using Gp4Net.Domain.CardInfo;
using Xunit;

namespace Gp4Net.Tests.Domain.CardInfo
{
    public class KeyInformationTemplateTests
    {
        [Fact]
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
            Assert.NotNull(template);
            _ = Assert.Single(template.Keys);

            var key = template.Keys.First();
            Assert.Equal(1, key.KeyId);
            Assert.Equal(1, key.KeyVersion);
            Assert.Equal(2, key.KeyTypes.Count);
            Assert.Equal(KeyType.TripleDes3Key, key.KeyTypes[0]);
            Assert.Equal(KeyType.NotAvailable, key.KeyTypes[1]);
            Assert.Equal(192, key.KeyLength);
        }

        [Fact]
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
            Assert.NotNull(template);
            var key = template.Keys.First();
            Assert.Equal(16, key.KeyId);
            Assert.Equal(2, key.KeyVersion);
            Assert.Equal(KeyType.Aes, key.PrimaryKeyType);
            Assert.Equal(128, key.KeyLength); // Default AES length
        }

        [Fact]
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
            var key = template.Keys.First();
            Assert.Equal(3, key.KeyTypes.Count);
            Assert.Contains(KeyType.Des, key.KeyTypes);
            Assert.Contains(KeyType.TripleDes2Key, key.KeyTypes);
            Assert.Contains(KeyType.TripleDes3Key, key.KeyTypes);
            Assert.Equal(KeyType.Des, key.PrimaryKeyType); // First type
            Assert.Equal(64, key.KeyLength); // DES length
        }

        [Fact]
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
            Assert.Equal(4, template.Keys.Count);

            // First three keys have same ID but different versions
            Assert.Equal(1, template.Keys[0].KeyId);
            Assert.Equal(1, template.Keys[0].KeyVersion);

            Assert.Equal(1, template.Keys[1].KeyId);
            Assert.Equal(2, template.Keys[1].KeyVersion);

            Assert.Equal(1, template.Keys[2].KeyId);
            Assert.Equal(3, template.Keys[2].KeyVersion);

            // Fourth key has different ID
            Assert.Equal(2, template.Keys[3].KeyId);
            Assert.Equal(1, template.Keys[3].KeyVersion);

            // All are AES keys
            Assert.All(template.Keys, k => Assert.Equal(KeyType.Aes, k.PrimaryKeyType));
        }

        [Fact]
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
            var output = template.Keys.First().ToString();

            // Assert
            Assert.Contains("Version: 2 (0x02)", output);
            Assert.Contains("ID: 1 (0x01)", output);
            Assert.Contains("type: AES", output);
            Assert.Contains("length: 16", output); // 128 bits / 8
        }

        [Fact]
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
            Assert.Contains("Key Information Template:", output);
            Assert.Contains("Version: 1", output);
            Assert.Contains("3DES", output);
            Assert.Contains("AES", output);
        }

        [Fact]
        public void KeyTypeExtensions_ToFriendlyString_ReturnsCorrectNames()
        {
            // Assert various key types format correctly
            Assert.Equal("DES", KeyType.Des.ToFriendlyString());
            Assert.Equal("3DES-2KEY", KeyType.TripleDes2Key.ToFriendlyString());
            Assert.Equal("3DES-3KEY", KeyType.TripleDes3Key.ToFriendlyString());
            Assert.Equal("3DES", KeyType.Des3.ToFriendlyString());
            Assert.Equal("AES", KeyType.Aes.ToFriendlyString());
            Assert.Equal("N/A", KeyType.NotAvailable.ToFriendlyString());
            Assert.Equal("Unknown(0x00)", KeyType.Unknown.ToFriendlyString());
        }

        [Fact]
        public void Parse_EmptyData_ThrowsException()
        {
            // Arrange
            var emptyData = new byte[0];

            // Act & Assert
            _ = Assert.Throws<System.ArgumentException>(
                () => KeyInformationTemplate.Parse(emptyData)
            );
        }

        [Fact]
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
            Assert.Empty(template.Keys); // Should not add incomplete key
        }
    }
}
