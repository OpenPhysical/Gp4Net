using System.Linq;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;
using AwesomeAssertions;

namespace Gp4Net.Tests.Domain.CardInfo;

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
        capabilities.Should().NotBeNull();
        capabilities.ScpOptions.Should().HaveCount(1);

        var scpOption = capabilities.ScpOptions.First();
        scpOption.ScpId.Should().Be(0x03);
        scpOption.Implementation.Should().Be(0x70);

        capabilities.SupportedKeyLengths.ContainsKey(0x03).Should().BeTrue();
        var keyLengths = capabilities.SupportedKeyLengths[0x03];
        keyLengths.Should().Contain(128);
        keyLengths.Should().Contain(192);
        keyLengths.Should().Contain(256);
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
        capabilities.SdPrivileges.HasValue.Should().BeTrue();
        capabilities.SdPrivileges.Value.SecurityDomain.Should().BeTrue();
        capabilities.SdPrivileges.Value.DapVerification.Should().BeTrue();
        capabilities.SdPrivileges.Value.CardLock.Should().BeFalse();
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
        capabilities.AppPrivileges.HasValue.Should().BeTrue();
        capabilities.AppPrivileges.Value.FinalApplication.Should().BeTrue();
        capabilities.AppPrivileges.Value.CardLock.Should().BeFalse();
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
        capabilities.Algorithms.HasValue.Should().BeTrue();
        var hashAlgs = capabilities.Algorithms.Value.GetHashAlgorithms();
        hashAlgs.Should().Contain("SHA-1");
        hashAlgs.Should().Contain("SHA-256");
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
        capabilities.CipherSuites.ContainsKey(CipherUsage.DapVerification).Should().BeTrue();
        var ciphers = capabilities.CipherSuites[CipherUsage.DapVerification];
        ciphers.Should().Contain(CipherSuite.Des3Mac);
        ciphers.Should().Contain(CipherSuite.AesCmac128);
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
        capabilities.Should().NotBeNull();
        capabilities.ScpOptions.Should().NotBeEmpty();
        capabilities.SdPrivileges.Should().NotBeNull();
        capabilities.AppPrivileges.Should().NotBeNull();
        capabilities.Algorithms.Should().NotBeNull();
        capabilities.CipherSuites.Should().NotBeEmpty();

        // Verify the ToString() method produces readable output
        var output = capabilities.ToString();
        output.Should().Contain("SCP03");
        output.Should().Contain("AES");
        output.Should().Contain("SecurityDomain");
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
        output.Should().Contain("Card Capabilities:");
        output.Should().Contain("Supports SCP03 i=70 with AES-128 AES-192 AES-256");
        output.Should().Contain("DAP");
        output.Should().Contain("SecurityDomain");
    }
}