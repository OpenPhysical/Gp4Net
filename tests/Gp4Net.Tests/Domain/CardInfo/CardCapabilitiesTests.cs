using System.Linq;
using Gp4Net.Domain.CardInfo;
using Xunit;

namespace Gp4Net.Tests.Domain.CardInfo
{
    public class CardCapabilitiesTests
    {
        [Fact]
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
            Assert.NotNull(capabilities);
            _ = Assert.Single(capabilities.ScpOptions);

            var scpOption = capabilities.ScpOptions.First();
            Assert.Equal(0x03, scpOption.ScpId);
            Assert.Equal(0x70, scpOption.Implementation);

            Assert.True(capabilities.SupportedKeyLengths.ContainsKey(0x03));
            var keyLengths = capabilities.SupportedKeyLengths[0x03];
            Assert.Contains(128, keyLengths);
            Assert.Contains(192, keyLengths);
            Assert.Contains(256, keyLengths);
        }

        [Fact]
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
            Assert.NotNull(capabilities.SdPrivileges);
            Assert.True(capabilities.SdPrivileges.SecurityDomain);
            Assert.True(capabilities.SdPrivileges.DapVerification);
            Assert.False(capabilities.SdPrivileges.CardLock);
        }

        [Fact]
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
            Assert.NotNull(capabilities.AppPrivileges);
            Assert.True(capabilities.AppPrivileges.FinalApplication);
            Assert.False(capabilities.AppPrivileges.CardLock);
        }

        [Fact]
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
            Assert.NotNull(capabilities.Algorithms);
            var hashAlgs = capabilities.Algorithms.GetHashAlgorithms();
            Assert.Contains("SHA-1", hashAlgs);
            Assert.Contains("SHA-256", hashAlgs);
        }

        [Fact]
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
            Assert.True(capabilities.CipherSuites.ContainsKey(CipherUsage.DapVerification));
            var ciphers = capabilities.CipherSuites[CipherUsage.DapVerification];
            Assert.Contains(CipherSuite.Des3Mac, ciphers);
            Assert.Contains(CipherSuite.AesCmac128, ciphers);
        }

        [Fact]
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
            Assert.NotNull(capabilities);
            Assert.NotEmpty(capabilities.ScpOptions);
            Assert.NotNull(capabilities.SdPrivileges);
            Assert.NotNull(capabilities.AppPrivileges);
            Assert.NotNull(capabilities.Algorithms);
            Assert.NotEmpty(capabilities.CipherSuites);

            // Verify the ToString() method produces readable output
            var output = capabilities.ToString();
            Assert.Contains("SCP03", output);
            Assert.Contains("AES", output);
            Assert.Contains("SecurityDomain", output);
        }

        [Fact]
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
            Assert.Contains("Card Capabilities:", output);
            Assert.Contains("Supports SCP03 i=70 with AES-128 AES-192 AES-256", output);
            Assert.Contains("Supported DOM privileges: SecurityDomain, DAPVerification", output);
        }
    }
}
