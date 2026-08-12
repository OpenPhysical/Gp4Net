using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;
using static Gp4Net.Constants.Constants.GlobalPlatform;

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
        var capabilities = result.Value;

        // Assert
        _ = capabilities.Should().NotBeNull();
        _ = capabilities.ScpOptions.Should().HaveCount(1);

        var scpOption = capabilities.ScpOptions.First();
        _ = scpOption.ScpId.Should().Be(0x03);
        _ = scpOption.Implementation.Should().Be(0x70);

        _ = capabilities.SupportedKeyLengths.ContainsKey(0x03).Should().BeTrue();
        var keyLengths = capabilities.SupportedKeyLengths[0x03];
        _ = keyLengths.Should().Contain(128);
        _ = keyLengths.Should().Contain(192);
        _ = keyLengths.Should().Contain(256);
    }

    [Test]
    public void Parse_WithSecurityDomainPrivileges_ParsesCorrectly()
    {
        // GP Card Specification v2.3.1, Table H-5: tag 81 contains SSD privileges.
        byte[] data =
        [
            0x81,
            0x03,
            0xC0,
            0x00,
            0x00, // SD privileges
        ];

        // Act
        Result<CardCapabilities, SmartCardError> result = CardCapabilities.TryParse(
            Maybe<byte[]>.From(data)
        );
        _ = result.IsSuccess.Should().BeTrue();
        var capabilities = result.Value;

        // Assert
        _ = capabilities.SdPrivileges.HasValue.Should().BeTrue();
        _ = capabilities.SdPrivileges.Value.SecurityDomain.Should().BeTrue();
        _ = capabilities.SdPrivileges.Value.DapVerification.Should().BeTrue();
        _ = capabilities.SdPrivileges.Value.CardLock.Should().BeFalse();
    }

    [Test]
    public void Parse_WithApplicationPrivileges_ParsesCorrectly()
    {
        // GP Card Specification v2.3.1, Table H-5: tag 82 contains Application privileges.
        byte[] data =
        [
            0x82,
            0x03,
            0x00,
            0x02,
            0x00, // App privileges with FinalApplication
        ];

        // Act
        Result<CardCapabilities, SmartCardError> result = CardCapabilities.TryParse(
            Maybe<byte[]>.From(data)
        );
        _ = result.IsSuccess.Should().BeTrue();
        if (result.IsSuccess)
        {
            var capabilities = result.Value;

            // Assert
            _ = capabilities.AppPrivileges.HasValue.Should().BeTrue();
            capabilities.AppPrivileges.Map(appPrivileges =>
            {
                _ = appPrivileges.HasFlag(Privilege.FinalApplication).Should().BeTrue();
                _ = appPrivileges.HasFlag(Privilege.CardLock).Should().BeFalse();
                return appPrivileges;
            });
        }
    }

    [Test]
    public void Parse_WithSupportedAlgorithms_ParsesCorrectly()
    {
        // GP Card Specification v2.3.1, Table H-5: tag 83 is a sequence of
        // LFDBH algorithm identifiers, where 01 is SHA-1 and 02 is SHA-256.
        byte[] data = [0x83, 0x02, 0x01, 0x02,];

        // Act
        Result<CardCapabilities, SmartCardError> result = CardCapabilities.TryParse(
            Maybe<byte[]>.From(data)
        );
        _ = result.IsSuccess.Should().BeTrue();
        var capabilities = result.Value;

        // Assert
        _ = capabilities.Algorithms.HasValue.Should().BeTrue();
        string? hashAlgs = capabilities.Algorithms.Value.GetHashAlgorithms();
        _ = hashAlgs.Should().Contain("SHA-1");
        _ = hashAlgs.Should().Contain("SHA-256");
    }

    [Test]
    public void Parse_WithCipherSuites_ParsesCorrectly()
    {
        // GP Card Specification v2.3.1, Tables H-5 and H-9: tag 87 contains
        // the DAP signature-suite bitmap; b3 is DES MAC and b4 is AES-128 CMAC.
        byte[] data = [0x87, 0x01, 0x0C,];

        // Act
        Result<CardCapabilities, SmartCardError> result = CardCapabilities.TryParse(
            Maybe<byte[]>.From(data)
        );
        _ = result.IsSuccess.Should().BeTrue();
        var capabilities = result.Value;

        // Assert
        _ = capabilities.CipherSuites.ContainsKey(CipherUsage.DapVerification).Should().BeTrue();
        var ciphers = capabilities.CipherSuites[CipherUsage.DapVerification];
        _ = ciphers.Should().Contain(CipherSuite.Des3Mac);
        _ = ciphers.Should().Contain(CipherSuite.AesCmac128);
    }

    [Test]
    public void Parse_CipherSuiteBitmapsAndKeyReferences_UsesTablesH8ThroughH10()
    {
        // GP Card Specification v2.3.1, Tables H-5 and H-8 through H-10.
        byte[] data = [0x84, 0x01, 0x8F, 0x85, 0x02, 0xC0, 0x03, 0x88, 0x02, 0x01, 0x02,];

        var result = CardCapabilities.TryParse(Maybe<byte[]>.From(data));

        _ = result.IsSuccess.Should().BeTrue();
        var capabilities = result.Value;
        _ = capabilities.SupportsLfdbEncryptionIcv.Should().BeTrue();
        _ = capabilities
            .CipherSuites[CipherUsage.LfdbEncryption]
            .Should()
            .Contain(
                [
                    CipherSuite.TripleDes16,
                    CipherSuite.Aes128,
                    CipherSuite.Aes192,
                    CipherSuite.Aes256,
                ]
            );
        _ = capabilities
            .CipherSuites[CipherUsage.TokenVerification]
            .Should()
            .Contain(
                [
                    CipherSuite.EcdsaP256Sha256,
                    CipherSuite.EcdsaP384Sha384,
                    CipherSuite.EcdsaP512Sha512,
                    CipherSuite.EcdsaP521Sha512,
                ]
            );
        _ = capabilities.KeyParameterReferences.Should().Equal(0x01, 0x02);
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
            0x81,
            0x03,
            0xFF,
            0xFF,
            0xE0,
            // App privileges
            0x82,
            0x03,
            0x00,
            0x00,
            0x02,
            // Supported algorithms
            0x83,
            0x04,
            0x01,
            0x02,
            0x03,
            0x04,
            // Cipher suites
            0x87,
            0x01,
            0x0F,
        ];

        // Act
        Result<CardCapabilities, SmartCardError> result = CardCapabilities.TryParse(
            Maybe<byte[]>.From(data)
        );
        _ = result.IsSuccess.Should().BeTrue();
        var capabilities = result.Value;

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
            0x81,
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
        var capabilities = result.Value;
        string? output = capabilities.ToString();

        // Assert
        _ = output.Should().Contain("Card Capabilities:");
        _ = output.Should().Contain("Supports SCP03 i=70 with AES-128 AES-192 AES-256");
        _ = output.Should().Contain("DAP");
        _ = output.Should().Contain("SecurityDomain");
    }
}
