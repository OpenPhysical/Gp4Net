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
        var level = SecurityLevel.CMac;

        // Act & Assert
        level.HasCMac().Should().BeTrue();
    }

    [Test] 
    public void HasCMac_WithoutCMacFlag_ReturnsFalse()
    {
        // Arrange
        var level = SecurityLevel.RMac;

        // Act & Assert
        level.HasCMac().Should().BeFalse();
    }

    [Test]
    public void HasCDecryption_WithCDecryptionFlag_ReturnsTrue()
    {
        // Arrange
        var level = SecurityLevel.CDecryption;

        // Act & Assert  
        level.HasCDecryption().Should().BeTrue();
    }

    [Test]
    public void HasCDecryption_WithOnlyCMacFlag_ReturnsFalse()
    {
        // Arrange - C-MAC alone doesn't imply C-DECRYPTION
        var level = SecurityLevel.CMac;

        // Act & Assert
        level.HasCDecryption().Should().BeFalse();
    }

    [Test]
    public void HasCEncryption_WithCEncryptionFlag_ReturnsTrue()
    {
        // Arrange
        var level = SecurityLevel.CEncryption;

        // Act & Assert
        level.HasCEncryption().Should().BeTrue();
    }

    [Test]
    public void HasCEncryption_WithCDecryptionFlag_ReturnsTrue()
    {
        // Arrange - CDecryption (0x03) includes CEncryption bit (0x02) 
        // GP Card Specification v2.3.1: CDecryption is a composite flag including encryption capability
        var level = SecurityLevel.CDecryption;

        // Act & Assert - CDecryption includes the encryption bit, so this should be true
        level.HasCEncryption().Should().BeTrue();
    }

    [Test]
    public void HasCEncryption_And_HasCDecryption_Should_Have_Correct_Relationships()
    {
        // Arrange - Test the correct relationships between flags
        var encryptionOnly = SecurityLevel.CEncryption;      // 0x02 - just encryption
        var decryptionComposite = SecurityLevel.CDecryption; // 0x03 - MAC + encryption

        // Act & Assert
        // CEncryption (0x02) should only have encryption, not full decryption capability
        encryptionOnly.HasCEncryption().Should().BeTrue();
        encryptionOnly.HasCDecryption().Should().BeFalse();  // Needs both MAC (0x01) and encryption (0x02)
        
        // CDecryption (0x03) should have both capabilities  
        decryptionComposite.HasCDecryption().Should().BeTrue();   // Has both MAC and encryption bits
        decryptionComposite.HasCEncryption().Should().BeTrue();   // Includes encryption bit (0x02)
        decryptionComposite.HasCMac().Should().BeTrue();          // Includes MAC bit (0x01)
    }

    [Test] 
    public void HasCDecryption_Should_Require_Both_CMac_And_Decryption_Bits()
    {
        // Arrange - CDecryption = 0x03 = CMac (0x01) + Decryption (0x02)
        var cMacOnly = SecurityLevel.CMac;           // 0x01
        var encryptionOnly = SecurityLevel.CEncryption; // 0x02  
        var combined = SecurityLevel.CDecryption;         // 0x03

        // Act & Assert
        cMacOnly.HasCDecryption().Should().BeFalse();
        encryptionOnly.HasCDecryption().Should().BeFalse();
        combined.HasCDecryption().Should().BeTrue();
    }

    [Test]
    public void HasRMac_WithRMacFlag_ReturnsTrue()
    {
        // Arrange
        var level = SecurityLevel.RMac;

        // Act & Assert
        level.HasRMac().Should().BeTrue();
    }

    [Test]
    public void HasREncryption_WithREncryptionFlag_ReturnsTrue()
    {
        // Arrange
        var level = SecurityLevel.REncryption;

        // Act & Assert
        level.HasREncryption().Should().BeTrue();
    }

    [Test]
    public void Combine_Should_Union_Flags()
    {
        // Arrange
        var level1 = SecurityLevel.CMac;
        var level2 = SecurityLevel.RMac;

        // Act
        var combined = level1.Combine(level2);

        // Assert
        combined.HasCMac().Should().BeTrue();
        combined.HasRMac().Should().BeTrue();
        combined.HasCDecryption().Should().BeFalse();
        combined.HasCEncryption().Should().BeFalse();
    }

    [Test]
    public void Remove_Should_Clear_Specified_Flags()
    {
        // Arrange
        var level = SecurityLevel.CDecryption | SecurityLevel.RMac;

        // Act
        var result = level.Remove(SecurityLevel.RMac);

        // Assert
        result.HasCDecryption().Should().BeTrue();
        result.HasRMac().Should().BeFalse();
    }

    [Test]
    public void HasSecureMessaging_WithAnyFlag_ReturnsTrue()
    {
        // Arrange & Act & Assert
        SecurityLevel.CMac.HasSecureMessaging().Should().BeTrue();
        SecurityLevel.CEncryption.HasSecureMessaging().Should().BeTrue();
        SecurityLevel.CDecryption.HasSecureMessaging().Should().BeTrue();
        SecurityLevel.RMac.HasSecureMessaging().Should().BeTrue();
        SecurityLevel.REncryption.HasSecureMessaging().Should().BeTrue();
    }

    [Test]
    public void HasSecureMessaging_WithNone_ReturnsFalse()
    {
        // Arrange
        var level = SecurityLevel.None;

        // Act & Assert
        level.HasSecureMessaging().Should().BeFalse();
    }

    [Test]
    public void ToDescription_Should_Return_Correct_Descriptions()
    {
        // Act & Assert
        SecurityLevel.None.ToDescription().Should().Be("No security");
        SecurityLevel.CMac.ToDescription().Should().Be("C-MAC");
        SecurityLevel.CEncryption.ToDescription().Should().Be("C-ENCRYPTION");
        SecurityLevel.CDecryption.ToDescription().Should().Be("C-MAC + C-DECRYPTION");
        SecurityLevel.RMac.ToDescription().Should().Be("R-MAC");
        SecurityLevel.REncryption.ToDescription().Should().Be("R-ENCRYPTION");
    }

    [Test]
    public void ToDescription_WithCombinedFlags_ReturnsHexFormat()
    {
        // Arrange
        var combined = SecurityLevel.CMac | SecurityLevel.RMac;

        // Act
        var description = combined.ToDescription();

        // Assert
        description.Should().Be("Combined security level: 11");
    }

    [Test]
    public void Original_Bug_Should_Be_Fixed()
    {
        // This test specifically validates that the original bug is fixed
        // Original bug: HasCEncryption() incorrectly checked CDecryption flag
        
        // Before the fix, both methods returned the same result (both checked CDecryption)
        // After the fix, they should check different flags and return different results for some inputs
        
        var encryptionOnly = SecurityLevel.CEncryption; // 0x02
        var macOnly = SecurityLevel.CMac;               // 0x01
        
        // These should be different - proving the methods check different flags
        encryptionOnly.HasCEncryption().Should().BeTrue();   // Checks CEncryption (0x02)
        encryptionOnly.HasCDecryption().Should().BeFalse();  // Checks CDecryption (0x03)
        
        macOnly.HasCEncryption().Should().BeFalse();         // Checks CEncryption (0x02) 
        macOnly.HasCDecryption().Should().BeFalse();         // Checks CDecryption (0x03)
        
        // This proves they're checking different flags and the bug is fixed
    }

    /// <summary>
    /// Property-based test to ensure security level flag relationships are correct.
    /// GP Card Specification v2.3.1: Validates security level flag relationships.
    /// </summary>
    [Test]
    public void SecurityLevel_Flag_Relationships_Should_Be_Consistent([Values(
        SecurityLevel.None,
        SecurityLevel.CMac, 
        SecurityLevel.CEncryption,
        SecurityLevel.CDecryption,
        SecurityLevel.RMac,
        SecurityLevel.REncryption,
        SecurityLevel.CMac | SecurityLevel.RMac,
        SecurityLevel.CDecryption | SecurityLevel.REncryption
    )] SecurityLevel level)
    {
        // Act
        var hasCMac = level.HasCMac();
        var hasCEncryption = level.HasCEncryption();
        var hasCDecryption = level.HasCDecryption();
        var hasRMac = level.HasRMac();
        var hasREncryption = level.HasREncryption();

        // Assert - Basic flag consistency
        if ((level & SecurityLevel.CMac) != 0)
            hasCMac.Should().BeTrue();
        else
            hasCMac.Should().BeFalse();

        if ((level & SecurityLevel.CEncryption) != 0)
            hasCEncryption.Should().BeTrue();
        
        // CDecryption requires BOTH CMac and CEncryption bits (0x03 = 0x01 | 0x02)
        if ((level & SecurityLevel.CDecryption) == SecurityLevel.CDecryption)
            hasCDecryption.Should().BeTrue();
        else
            hasCDecryption.Should().BeFalse();
    }
}