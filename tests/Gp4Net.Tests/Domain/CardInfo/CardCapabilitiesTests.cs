using System.Collections.Immutable;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.CardInfo;

[TestFixture]
public class CardCapabilitiesTests
{
    [Test]
    public void Parse_WithScpOptions_ParsesCorrectly()
    {
        // Arrange - SCP03 with i=70 and AES-128/192/256 support
        byte[] data =
        [
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
        ];

        // Act
        Result<CardCapabilities, SmartCardError> result = CardCapabilities.TryParse(
            Maybe<byte[]>.From(data)
        );
        _ = result.IsSuccess.Should().BeTrue();
        CardCapabilities? capabilities = result.Value;

        // Assert
        _ = capabilities.Should().NotBeNull();
        _ = capabilities.ScpOptions.Should().HaveCount(1);

        ScpOption? scpOption = capabilities.ScpOptions.First();
        _ = scpOption.ScpId.Should().Be(0x03);
        _ = scpOption.Implementation.Should().Be(0x70);

        _ = capabilities.SupportedKeyLengths.ContainsKey(0x03).Should().BeTrue();
        ImmutableList<int>? keyLengths = capabilities.SupportedKeyLengths[0x03];
        _ = keyLengths.Should().Contain(128);
        _ = keyLengths.Should().Contain(192);
        _ = keyLengths.Should().Contain(256);
    }

    [Test]
    public void Parse_WithSecurityDomainPrivileges_ParsesCorrectly()
    {
        // Arrange
        byte[] data =
        [
            0x80,
            0x03, // Tag 80, length 3
            0xC0,
            0x00,
            0x00, // SD privileges
        ];

        // Act
        Result<CardCapabilities, SmartCardError> result = CardCapabilities.TryParse(
            Maybe<byte[]>.From(data)
        );
        _ = result.IsSuccess.Should().BeTrue();
        CardCapabilities? capabilities = result.Value;

        // Assert
        _ = capabilities.SdPrivileges.HasValue.Should().BeTrue();
        _ = capabilities.SdPrivileges.Value.SecurityDomain.Should().BeTrue();
        _ = capabilities.SdPrivileges.Value.DapVerification.Should().BeTrue();
        _ = capabilities.SdPrivileges.Value.CardLock.Should().BeFalse();
    }

    [Test]
    public void Parse_WithApplicationPrivileges_ParsesCorrectly()
    {
        // Arrange
        byte[] data =
        [
            0x81,
            0x03, // Tag 81, length 3
            0x00,
            0x02,
            0x00, // App privileges with FinalApplication
        ];

        // Act
        Result<CardCapabilities, SmartCardError> result = CardCapabilities.TryParse(
            Maybe<byte[]>.From(data)
        );
        _ = result.IsSuccess.Should().BeTrue();
        CardCapabilities? capabilities = result.Value;

        // Assert
        _ = capabilities.AppPrivileges.HasValue.Should().BeTrue();
        _ = capabilities.AppPrivileges.Value.FinalApplication.Should().BeTrue();
        _ = capabilities.AppPrivileges.Value.CardLock.Should().BeFalse();
    }

    [Test]
    public void Parse_WithSupportedAlgorithms_ParsesCorrectly()
    {
        // Arrange
        byte[] data =
        [
            0x82,
            0x02, // Tag 82, length 2
            0x03,
            0x00, // SHA-1 and SHA-256 supported
        ];

        // Act
        Result<CardCapabilities, SmartCardError> result = CardCapabilities.TryParse(
            Maybe<byte[]>.From(data)
        );
        _ = result.IsSuccess.Should().BeTrue();
        CardCapabilities? capabilities = result.Value;

        // Assert
        _ = capabilities.Algorithms.HasValue.Should().BeTrue();
        string? hashAlgs = capabilities.Algorithms.Value.GetHashAlgorithms();
        _ = hashAlgs.Should().Contain("SHA-1");
        _ = hashAlgs.Should().Contain("SHA-256");
    }

    [Test]
    public void Parse_WithCipherSuites_ParsesCorrectly()
    {
        // Arrange
        byte[] data =
        [
            0x86,
            0x02, // Tag 86 (DAP verification), length 2
            0x01,
            0x02, // DES_MAC and AES_CMAC_128
        ];

        // Act
        Result<CardCapabilities, SmartCardError> result = CardCapabilities.TryParse(
            Maybe<byte[]>.From(data)
        );
        _ = result.IsSuccess.Should().BeTrue();
        CardCapabilities? capabilities = result.Value;

        // Assert
        _ = capabilities.CipherSuites.ContainsKey(CipherUsage.DapVerification).Should().BeTrue();
        ImmutableList<CipherSuite>? ciphers = capabilities.CipherSuites[
            CipherUsage.DapVerification
        ];
        _ = ciphers.Should().Contain(CipherSuite.Des3Mac);
        _ = ciphers.Should().Contain(CipherSuite.AesCmac128);
    }

    [Test]
    public void Parse_ComplexCapabilities_ParsesAllSections()
    {
        // Arrange - Complex capabilities like from the trace
        byte[] data =
        [
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
            0x04,
        ];

        // Act
        Result<CardCapabilities, SmartCardError> result = CardCapabilities.TryParse(
            Maybe<byte[]>.From(data)
        );
        _ = result.IsSuccess.Should().BeTrue();
        CardCapabilities? capabilities = result.Value;

        // Assert
        _ = capabilities.Should().NotBeNull();
        _ = capabilities.ScpOptions.Should().NotBeEmpty();
        _ = capabilities.SdPrivileges.Should().NotBeNull();
        _ = capabilities.AppPrivileges.Should().NotBeNull();
        _ = capabilities.Algorithms.Should().NotBeNull();
        _ = capabilities.CipherSuites.Should().NotBeEmpty();

        // Verify the ToString() method produces readable output
        string? output = capabilities.ToString();
        _ = output.Should().Contain("SCP03");
        _ = output.Should().Contain("AES");
        _ = output.Should().Contain("SecurityDomain");
    }

    [Test]
    public void ToString_FormatsOutputCorrectly()
    {
        // Arrange
        byte[] data =
        [
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
            0x00,
        ];

        // Act
        Result<CardCapabilities, SmartCardError> result = CardCapabilities.TryParse(
            Maybe<byte[]>.From(data)
        );
        _ = result.IsSuccess.Should().BeTrue();
        CardCapabilities? capabilities = result.Value;
        string? output = capabilities.ToString();

        // Assert
        _ = output.Should().Contain("Card Capabilities:");
        _ = output.Should().Contain("Supports SCP03 i=70 with AES-128 AES-192 AES-256");
        _ = output.Should().Contain("DAP");
        _ = output.Should().Contain("SecurityDomain");
    }
}
