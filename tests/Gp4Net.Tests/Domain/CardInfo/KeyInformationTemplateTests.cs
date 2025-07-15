using System.Linq;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.CardInfo
{
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
            Assert.That(template, Is.Not.Null);
            Assert.That(template.Keys.Count, Is.EqualTo(1));

            var key = template.Keys.First();
            Assert.That(key.KeyId, Is.EqualTo(1));
            Assert.That(key.KeyVersion, Is.EqualTo(1));
            Assert.That(key.KeyTypes.Count, Is.EqualTo(2));
            Assert.That(key.KeyTypes[0], Is.EqualTo(KeyType.TripleDes3Key));
            Assert.That(key.KeyTypes[1], Is.EqualTo(KeyType.NotAvailable));
            Assert.That(key.KeyLength, Is.EqualTo(192));
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
            Assert.That(template, Is.Not.Null);
            var key = template.Keys.First();
            Assert.That(key.KeyId, Is.EqualTo(16));
            Assert.That(key.KeyVersion, Is.EqualTo(2));
            Assert.That(key.PrimaryKeyType, Is.EqualTo(KeyType.Aes));
            Assert.That(key.KeyLength, Is.EqualTo(128)); // Default AES length
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
            var key = template.Keys.First();
            Assert.That(key.KeyTypes.Count, Is.EqualTo(3));
            Assert.That(key.KeyTypes, Does.Contain(KeyType.Des));
            Assert.That(key.KeyTypes, Does.Contain(KeyType.TripleDes2Key));
            Assert.That(key.KeyTypes, Does.Contain(KeyType.TripleDes3Key));
            Assert.That(key.PrimaryKeyType, Is.EqualTo(KeyType.Des)); // First type
            Assert.That(key.KeyLength, Is.EqualTo(64)); // DES length
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
            Assert.That(template.Keys.Count, Is.EqualTo(4));

            // First three keys have same ID but different versions
            Assert.That(template.Keys[0].KeyId, Is.EqualTo(1));
            Assert.That(template.Keys[0].KeyVersion, Is.EqualTo(1));

            Assert.That(template.Keys[1].KeyId, Is.EqualTo(1));
            Assert.That(template.Keys[1].KeyVersion, Is.EqualTo(2));

            Assert.That(template.Keys[2].KeyId, Is.EqualTo(1));
            Assert.That(template.Keys[2].KeyVersion, Is.EqualTo(3));

            // Fourth key has different ID
            Assert.That(template.Keys[3].KeyId, Is.EqualTo(2));
            Assert.That(template.Keys[3].KeyVersion, Is.EqualTo(1));

            // All are AES keys
            foreach (var key in template.Keys)
            {
                Assert.That(key.PrimaryKeyType, Is.EqualTo(KeyType.Aes));
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
            var output = template.Keys.First().ToString();

            // Assert
            Assert.That(output, Does.Contain("Version: 2 (0x02)"));
            Assert.That(output, Does.Contain("ID: 1 (0x01)"));
            Assert.That(output, Does.Contain("type: AES"));
            Assert.That(output, Does.Contain("length: 16")); // 128 bits / 8
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
            Assert.That(output, Does.Contain("Key Information Template:"));
            Assert.That(output, Does.Contain("Version: 1"));
            Assert.That(output, Does.Contain("3DES"));
            Assert.That(output, Does.Contain("AES"));
        }

        [Test]
        public void KeyTypeExtensions_ToFriendlyString_ReturnsCorrectNames()
        {
            // Assert various key types format correctly
            Assert.That(KeyType.Des.ToFriendlyString(), Is.EqualTo("DES"));
            Assert.That(KeyType.TripleDes2Key.ToFriendlyString(), Is.EqualTo("3DES-2KEY"));
            Assert.That(KeyType.TripleDes3Key.ToFriendlyString(), Is.EqualTo("3DES-3KEY"));
            Assert.That(KeyType.Des3.ToFriendlyString(), Is.EqualTo("3DES"));
            Assert.That(KeyType.Aes.ToFriendlyString(), Is.EqualTo("AES"));
            Assert.That(KeyType.NotAvailable.ToFriendlyString(), Is.EqualTo("N/A"));
            Assert.That(KeyType.Unknown.ToFriendlyString(), Is.EqualTo("Unknown(0x00)"));
        }

        [Test]
        public void Parse_EmptyData_ThrowsException()
        {
            // Arrange
            var emptyData = new byte[0];

            // Act & Assert
            _ = Assert.Throws<System.ArgumentException>(
                () => KeyInformationTemplate.Parse(emptyData)
            );
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
            Assert.That(template.Keys, Is.Empty); // Should not add incomplete key
        }
    }
}
