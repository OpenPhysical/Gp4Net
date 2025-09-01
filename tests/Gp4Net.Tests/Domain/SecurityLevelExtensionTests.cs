using AwesomeAssertions;
using Gp4Net.Domain;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain;

/// <summary>
/// Tests for SecurityLevel extension methods.
/// GP Card Specification v2.3.1: Validates security level flag handling and combinations.
/// </summary>
[TestFixture]
[Category("Unit")]
[Category("GpCompliance")]
public class SecurityLevelExtensionTests
{
    [Test]
    public void HasCMac_WithCMacFlag_ReturnsTrue()
    {
        // Arrange
        SecurityLevel level = SecurityLevel.CMac;

        // Act & Assert
        _ = level.HasCMac().Should().BeTrue();
    }

    [Test]
    public void HasCMac_WithoutCMacFlag_ReturnsFalse()
    {
        // Arrange
        SecurityLevel level = SecurityLevel.RMac;

        // Act & Assert
        _ = level.HasCMac().Should().BeFalse();
    }

    [Test]
    public void HasCDecryption_WithCDecryptionFlag_ReturnsTrue()
    {
        // Arrange
        SecurityLevel level = SecurityLevel.CDecryption;

        // Act & Assert
        _ = level.HasCDecryption().Should().BeTrue();
    }

    [Test]
    public void HasCDecryption_WithOnlyCMacFlag_ReturnsFalse()
    {
        // Arrange - C-MAC alone doesn't imply C-DECRYPTION
        SecurityLevel level = SecurityLevel.CMac;

        // Act & Assert
        _ = level.HasCDecryption().Should().BeFalse();
    }

    [Test]
    public void HasCEncryption_WithCEncryptionFlag_ReturnsTrue()
    {
        // Arrange
        SecurityLevel level = SecurityLevel.CEncryption;

        // Act & Assert
        _ = level.HasCEncryption().Should().BeTrue();
    }

    [Test]
    public void HasCEncryption_WithCDecryptionFlag_ReturnsTrue()
    {
        // Arrange - CDecryption (0x03) includes CEncryption bit (0x02)
        // GP Card Specification v2.3.1: CDecryption is a composite flag including encryption capability
        SecurityLevel level = SecurityLevel.CDecryption;

        // Act & Assert - CDecryption includes the encryption bit, so this should be true
        _ = level.HasCEncryption().Should().BeTrue();
    }

    [Test]
    public void HasCEncryption_And_HasCDecryption_Should_Have_Correct_Relationships()
    {
        // Arrange - Test the correct relationships between flags
        SecurityLevel encryptionOnly = SecurityLevel.CEncryption; // 0x02 - just encryption
        SecurityLevel decryptionComposite = SecurityLevel.CDecryption; // 0x03 - MAC + encryption

        // Act & Assert
        // CEncryption (0x02) should only have encryption, not full decryption capability
        _ = encryptionOnly.HasCEncryption().Should().BeTrue();
        _ = encryptionOnly.HasCDecryption().Should().BeFalse(); // Needs both MAC (0x01) and encryption (0x02)

        // CDecryption (0x03) should have both capabilities
        _ = decryptionComposite.HasCDecryption().Should().BeTrue(); // Has both MAC and encryption bits
        _ = decryptionComposite.HasCEncryption().Should().BeTrue(); // Includes encryption bit (0x02)
        _ = decryptionComposite.HasCMac().Should().BeTrue(); // Includes MAC bit (0x01)
    }

    [Test]
    public void HasCDecryption_Should_Require_Both_CMac_And_Decryption_Bits()
    {
        // Arrange - CDecryption = 0x03 = CMac (0x01) + Decryption (0x02)
        SecurityLevel cMacOnly = SecurityLevel.CMac; // 0x01
        SecurityLevel encryptionOnly = SecurityLevel.CEncryption; // 0x02
        SecurityLevel combined = SecurityLevel.CDecryption; // 0x03

        // Act & Assert
        _ = cMacOnly.HasCDecryption().Should().BeFalse();
        _ = encryptionOnly.HasCDecryption().Should().BeFalse();
        _ = combined.HasCDecryption().Should().BeTrue();
    }

    [Test]
    public void HasRMac_WithRMacFlag_ReturnsTrue()
    {
        // Arrange
        SecurityLevel level = SecurityLevel.RMac;

        // Act & Assert
        _ = level.HasRMac().Should().BeTrue();
    }

    [Test]
    public void HasREncryption_WithREncryptionFlag_ReturnsTrue()
    {
        // Arrange
        SecurityLevel level = SecurityLevel.REncryption;

        // Act & Assert
        _ = level.HasREncryption().Should().BeTrue();
    }

    [Test]
    public void Combine_Should_Union_Flags()
    {
        // Arrange
        SecurityLevel level1 = SecurityLevel.CMac;
        SecurityLevel level2 = SecurityLevel.RMac;

        // Act
        SecurityLevel combined = level1.Combine(level2);

        // Assert
        _ = combined.HasCMac().Should().BeTrue();
        _ = combined.HasRMac().Should().BeTrue();
        _ = combined.HasCDecryption().Should().BeFalse();
        _ = combined.HasCEncryption().Should().BeFalse();
    }

    [Test]
    public void Remove_Should_Clear_Specified_Flags()
    {
        // Arrange
        SecurityLevel level = SecurityLevel.CDecryption | SecurityLevel.RMac;

        // Act
        SecurityLevel result = level.Remove(SecurityLevel.RMac);

        // Assert
        _ = result.HasCDecryption().Should().BeTrue();
        _ = result.HasRMac().Should().BeFalse();
    }

    [Test]
    public void HasSecureMessaging_WithAnyFlag_ReturnsTrue()
    {
        // Arrange & Act & Assert
        _ = SecurityLevel.CMac.HasSecureMessaging().Should().BeTrue();
        _ = SecurityLevel.CEncryption.HasSecureMessaging().Should().BeTrue();
        _ = SecurityLevel.CDecryption.HasSecureMessaging().Should().BeTrue();
        _ = SecurityLevel.RMac.HasSecureMessaging().Should().BeTrue();
        _ = SecurityLevel.REncryption.HasSecureMessaging().Should().BeTrue();
    }

    [Test]
    public void HasSecureMessaging_WithNone_ReturnsFalse()
    {
        // Arrange
        SecurityLevel level = SecurityLevel.None;

        // Act & Assert
        _ = level.HasSecureMessaging().Should().BeFalse();
    }

    [Test]
    public void ToDescription_Should_Return_Correct_Descriptions()
    {
        // Act & Assert
        _ = SecurityLevel.None.ToDescription().Should().Be("No security");
        _ = SecurityLevel.CMac.ToDescription().Should().Be("C-MAC");
        _ = SecurityLevel.CEncryption.ToDescription().Should().Be("C-ENCRYPTION");
        _ = SecurityLevel.CDecryption.ToDescription().Should().Be("C-MAC + C-DECRYPTION");
        _ = SecurityLevel.RMac.ToDescription().Should().Be("R-MAC");
        _ = SecurityLevel.REncryption.ToDescription().Should().Be("R-ENCRYPTION");
    }

    [Test]
    public void ToDescription_WithCombinedFlags_ReturnsHexFormat()
    {
        // Arrange
        SecurityLevel combined = SecurityLevel.CMac | SecurityLevel.RMac;

        // Act
        string? description = combined.ToDescription();

        // Assert
        _ = description.Should().Be("Combined security level: 11");
    }

    [Test]
    public void Original_Bug_Should_Be_Fixed()
    {
        // This test specifically validates that the original bug is fixed
        // Original bug: HasCEncryption() incorrectly checked CDecryption flag

        // Before the fix, both methods returned the same result (both checked CDecryption)
        // After the fix, they should check different flags and return different results for some inputs

        SecurityLevel encryptionOnly = SecurityLevel.CEncryption; // 0x02
        SecurityLevel macOnly = SecurityLevel.CMac; // 0x01

        // These should be different - proving the methods check different flags
        _ = encryptionOnly.HasCEncryption().Should().BeTrue(); // Checks CEncryption (0x02)
        _ = encryptionOnly.HasCDecryption().Should().BeFalse(); // Checks CDecryption (0x03)

        _ = macOnly.HasCEncryption().Should().BeFalse(); // Checks CEncryption (0x02)
        _ = macOnly.HasCDecryption().Should().BeFalse(); // Checks CDecryption (0x03)

        // This proves they're checking different flags and the bug is fixed
    }

    /// <summary>
    /// Property-based test to ensure security level flag relationships are correct.
    /// GP Card Specification v2.3.1: Validates security level flag relationships.
    /// </summary>
    [Test]
    public void SecurityLevel_Flag_Relationships_Should_Be_Consistent(
        [Values(
            SecurityLevel.None,
            SecurityLevel.CMac,
            SecurityLevel.CEncryption,
            SecurityLevel.CDecryption,
            SecurityLevel.RMac,
            SecurityLevel.REncryption,
            SecurityLevel.CMac | SecurityLevel.RMac,
            SecurityLevel.CDecryption | SecurityLevel.REncryption
        )]
            SecurityLevel level
    )
    {
        // Act
        bool hasCMac = level.HasCMac();
        bool hasCEncryption = level.HasCEncryption();
        bool hasCDecryption = level.HasCDecryption();
        bool hasRMac = level.HasRMac();
        bool hasREncryption = level.HasREncryption();

        // Assert - Basic flag consistency
        if ((level & SecurityLevel.CMac) != 0)
            _ = hasCMac.Should().BeTrue();
        else
            _ = hasCMac.Should().BeFalse();

        if ((level & SecurityLevel.CEncryption) != 0)
            _ = hasCEncryption.Should().BeTrue();

        // CDecryption requires BOTH CMac and CEncryption bits (0x03 = 0x01 | 0x02)
        if ((level & SecurityLevel.CDecryption) == SecurityLevel.CDecryption)
            _ = hasCDecryption.Should().BeTrue();
        else
            _ = hasCDecryption.Should().BeFalse();
    }
}
