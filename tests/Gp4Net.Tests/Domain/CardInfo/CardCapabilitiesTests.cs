using System.Linq;
using Gp4Net.Core;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.CardInfo
{
    [TestFixture]
    public class CardCapabilitiesTests
    {
        [Test]
        public void Parse_WithScpOptions_ParsesCorrectly()
        {
            // Arrange - SCP03 with i=70 and AES-128/192/256 support
            var data = new byte[]
            {
                0xA0,
                0x09, // Tag A0, length 9
                0x80,
                0x01,
                0x03, // SCP type = 03
                0x81,
                0x01,
                0x70, // Supported options = 70
                0x82,
                0x01,
                0x07, // Supported keys = 07 (all AES lengths)
            };

            // Act
            var capabilities = CardCapabilities.Parse(data);

            // Assert
            Assert.That(capabilities, Is.Not.Null);
            Assert.That(capabilities.ScpOptions.Count, Is.EqualTo(1));

            var scpOption = capabilities.ScpOptions.First();
            Assert.That(scpOption.ScpId, Is.EqualTo(0x03));
            Assert.That(scpOption.Implementation, Is.EqualTo(0x70));

            Assert.That(capabilities.SupportedKeyLengths.ContainsKey(0x03), Is.True);
            var keyLengths = capabilities.SupportedKeyLengths[0x03];
            Assert.That(keyLengths, Does.Contain(128));
            Assert.That(keyLengths, Does.Contain(192));
            Assert.That(keyLengths, Does.Contain(256));
        }

        [Test]
        public void Parse_WithSecurityDomainPrivileges_ParsesCorrectly()
        {
            // Arrange
            var data = new byte[]
            {
                0x80,
                0x03, // Tag 80, length 3
                0xC0,
                0x00,
                0x00 // SD privileges
            };

            // Act
            var capabilities = CardCapabilities.Parse(data);

            // Assert
            Assert.That(capabilities.SdPrivileges, Is.Not.Null);
            Assert.That(capabilities.SdPrivileges.SecurityDomain, Is.True);
            Assert.That(capabilities.SdPrivileges.DapVerification, Is.True);
            Assert.That(capabilities.SdPrivileges.CardLock, Is.False);
        }

        [Test]
        public void Parse_WithApplicationPrivileges_ParsesCorrectly()
        {
            // Arrange
            var data = new byte[]
            {
                0x81,
                0x03, // Tag 81, length 3
                0x00,
                0x02,
                0x00 // App privileges with FinalApplication
            };

            // Act
            var capabilities = CardCapabilities.Parse(data);

            // Assert
            Assert.That(capabilities.AppPrivileges, Is.Not.Null);
            Assert.That(capabilities.AppPrivileges.FinalApplication, Is.True);
            Assert.That(capabilities.AppPrivileges.CardLock, Is.False);
        }

        [Test]
        public void Parse_WithSupportedAlgorithms_ParsesCorrectly()
        {
            // Arrange
            var data = new byte[]
            {
                0x82,
                0x02, // Tag 82, length 2
                0x03,
                0x00 // SHA-1 and SHA-256 supported
            };

            // Act
            var capabilities = CardCapabilities.Parse(data);

            // Assert
            Assert.That(capabilities.Algorithms, Is.Not.Null);
            var hashAlgs = capabilities.Algorithms.GetHashAlgorithms();
            Assert.That(hashAlgs, Does.Contain("SHA-1"));
            Assert.That(hashAlgs, Does.Contain("SHA-256"));
        }

        [Test]
        public void Parse_WithCipherSuites_ParsesCorrectly()
        {
            // Arrange
            var data = new byte[]
            {
                0x86,
                0x02, // Tag 86 (DAP verification), length 2
                0x01,
                0x02 // DES_MAC and AES_CMAC_128
            };

            // Act
            var capabilities = CardCapabilities.Parse(data);

            // Assert
            Assert.That(capabilities.CipherSuites.ContainsKey(CipherUsage.DapVerification), Is.True);
            var ciphers = capabilities.CipherSuites[CipherUsage.DapVerification];
            Assert.That(ciphers, Does.Contain(CipherSuite.Des3Mac));
            Assert.That(ciphers, Does.Contain(CipherSuite.AesCmac128));
        }

        [Test]
        public void Parse_ComplexCapabilities_ParsesAllSections()
        {
            // Arrange - Complex capabilities like from the trace
            var data = new byte[]
            {
                // SCP options
                0xA0,
                0x09,
                0x80,
                0x01,
                0x03,
                0x81,
                0x01,
                0x70,
                0x82,
                0x01,
                0x07,
                // SD privileges
                0x80,
                0x03,
                0xFF,
                0xFF,
                0xE0,
                // App privileges
                0x81,
                0x03,
                0x00,
                0x00,
                0x02,
                // Supported algorithms
                0x82,
                0x02,
                0x0F,
                0x00,
                // Cipher suites
                0x86,
                0x04,
                0x01,
                0x02,
                0x03,
                0x04
            };

            // Act
            var capabilities = CardCapabilities.Parse(data);

            // Assert
            Assert.That(capabilities, Is.Not.Null);
            Assert.That(capabilities.ScpOptions, Is.Not.Empty);
            Assert.That(capabilities.SdPrivileges, Is.Not.Null);
            Assert.That(capabilities.AppPrivileges, Is.Not.Null);
            Assert.That(capabilities.Algorithms, Is.Not.Null);
            Assert.That(capabilities.CipherSuites, Is.Not.Empty);

            // Verify the ToString() method produces readable output
            var output = capabilities.ToString();
            Assert.That(output, Does.Contain("SCP03"));
            Assert.That(output, Does.Contain("AES"));
            Assert.That(output, Does.Contain("SecurityDomain"));
        }

        [Test]
        public void ToString_FormatsOutputCorrectly()
        {
            // Arrange
            var data = new byte[]
            {
                0xA0,
                0x09,
                0x80,
                0x01,
                0x03,
                0x81,
                0x01,
                0x70,
                0x82,
                0x01,
                0x07,
                0x80,
                0x03,
                0xC0,
                0x00,
                0x00
            };

            // Act
            var capabilities = CardCapabilities.Parse(data);
            var output = capabilities.ToString();

            // Assert
            Assert.That(output, Does.Contain("Card Capabilities:"));
            Assert.That(output, Does.Contain("Supports SCP03 i=70 with AES-128 AES-192 AES-256"));
            Assert.That(output, Does.Contain("DAP"));
            Assert.That(output, Does.Contain("SecurityDomain"));
        }
    }
}
