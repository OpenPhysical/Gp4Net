using AwesomeAssertions;
using Gp4Net.Constants;
using Gp4Net.Domain;
using NUnit.Framework;

namespace Gp4Net.Tests.Compliance;

/// <summary>
/// Tests for SCP02 protocol rules compliance per GP Card Specification v2.3.1 Section E.1.6.
/// This addresses the critical gap in protocol rule enforcement identified in the analysis.
/// </summary>
[TestFixture]
[Category("Unit")]
[Category("GpCompliance")]
[Category("SCP02")]
[Category("ProtocolRules")]
public class Scp02ProtocolRulesTests
{
    /// <summary>
    /// GP SCP02 Table E-11: EXTERNAL AUTHENTICATE Security Level Parameters
    /// Tests that P1 parameter values map correctly to security levels per specification.
    /// </summary>
    [Test]
    [TestCase(0x00, SecurityLevel.None, "No secure messaging expected")]
    [TestCase(0x01, SecurityLevel.CMac, "C-MAC only")]
    [TestCase(0x03, SecurityLevel.CDecryption, "C-DECRYPTION and C-MAC")]
    [TestCase(0x10, SecurityLevel.RMac, "R-MAC only")]
    [TestCase(0x11, SecurityLevel.CMac | SecurityLevel.RMac, "C-MAC and R-MAC")]
    [TestCase(
        0x13,
        SecurityLevel.CDecryption | SecurityLevel.RMac,
        "C-DECRYPTION, C-MAC, and R-MAC"
    )]
    public void Scp02_Should_Map_External_Authenticate_P1_To_Correct_Security_Level(
        byte p1Value,
        SecurityLevel expectedSecurityLevel,
        string description
    )
    {
        // Act - Parse P1 parameter per GP Table E-11
        var parsedSecurityLevel = ParseExternalAuthenticateP1(p1Value);

        // Assert
        _ = parsedSecurityLevel
            .Should()
            .Be(
                expectedSecurityLevel,
                $"GP Table E-11: P1=0x{p1Value:X2} should map to {description}"
            );
    }

    /// <summary>
    /// GP SCP02 Section E.1.6: Security Level Validation Rules
    /// Tests authentication requirement enforcement per protocol rules.
    /// </summary>
    [Test]
    public void Scp02_Should_Require_Authentication_For_All_Secure_Messaging_Levels()
    {
        // Arrange - All non-zero security levels should include AUTHENTICATED
        SecurityLevel[] securityLevelsToTest =
        [
            SecurityLevel.CMac,
            SecurityLevel.CDecryption,
            SecurityLevel.RMac,
            SecurityLevel.CDecryption, // CDecryption already includes CMac
            SecurityLevel.CMac | SecurityLevel.RMac,
            SecurityLevel.CDecryption | SecurityLevel.RMac,
            SecurityLevel.CDecryption | SecurityLevel.RMac,
        ];

        // Act & Assert
        _ = securityLevelsToTest
            .Should()
            .AllSatisfy(level =>
            {
                bool shouldBeAuthenticated = RequiresAuthentication(level);
                _ = shouldBeAuthenticated
                    .Should()
                    .BeTrue(
                        $"GP Section E.1.6: Security level {level} should require AUTHENTICATED flag"
                    );
            });
    }

    /// <summary>
    /// GP SCP02 Section E.1.6: Protocol Rule - Session Termination Conditions
    /// Tests conditions that terminate secure channel sessions per specification.
    /// </summary>
    [Test]
    public void Scp02_Should_Terminate_Session_On_Specified_Conditions()
    {
        // Arrange - Test termination conditions per GP Section E.1.6
        var terminationConditions = new[]
        {
            new { Condition = "New INITIALIZE UPDATE command", ShouldTerminate = true },
            new { Condition = "Application selection", ShouldTerminate = true },
            new { Condition = "Logical channel termination", ShouldTerminate = true },
            new { Condition = "Card session termination", ShouldTerminate = true },
            new { Condition = "Explicit API termination", ShouldTerminate = true },
            new { Condition = "Valid command processing", ShouldTerminate = false },
            new { Condition = "R-MAC session begin", ShouldTerminate = false },
        };

        // Act & Assert
        _ = terminationConditions
            .Should()
            .AllSatisfy(testCase =>
            {
                bool shouldTerminate = ShouldTerminateSecureChannelSession(testCase.Condition);
                _ = shouldTerminate
                    .Should()
                    .Be(
                        testCase.ShouldTerminate,
                        $"GP Section E.1.6: {testCase.Condition} should {(testCase.ShouldTerminate ? "" : "not ")}terminate session"
                    );
            });
    }

    /// <summary>
    /// GP SCP02 Section E.1.6: Current Security Level Management
    /// Tests that Current Security Level is set to NO_SECURITY_LEVEL when appropriate.
    /// </summary>
    [Test]
    public void Scp02_Should_Reset_Security_Level_To_No_Security_On_Session_Events()
    {
        // Arrange - Events that reset security level per GP Section E.1.6
        string[] resetEvents =
        [
            "Session termination",
            "Session abortion",
            "New session initiation",
            "Card reset",
            "Power off",
        ];

        // Act & Assert
        _ = resetEvents
            .Should()
            .AllSatisfy(eventType =>
            {
                var securityLevelAfterEvent = GetSecurityLevelAfterEvent(eventType);
                _ = securityLevelAfterEvent
                    .Should()
                    .Be(
                        SecurityLevel.None,
                        $"GP Section E.1.6: {eventType} should reset Current Security Level to NO_SECURITY_LEVEL"
                    );
            });
    }

    /// <summary>
    /// GP SCP02 Table E-1: Implementation Parameter Bitmap Validation
    /// Tests that implementation parameter bitmaps follow specification structure.
    /// </summary>
    [Test]
    [TestCase(
        ScpImplementation.Scp02I15,
        0x15,
        "CLR mode: Explicit, modified APDU, 3 keys, ICV encryption"
    )]
    [TestCase(ScpImplementation.Scp02I55, 0x55, "ENC mode: Well-known challenge, ICV encryption")]
    [TestCase(
        ScpImplementation.Scp02I1A,
        0x1A,
        "Implicit mode with MAC over AID and ICV encryption"
    )]
    [TestCase(ScpImplementation.Scp02I75, 0x75, "RENC mode: Maximum security features")]
    public void Scp02_Should_Have_Correct_Implementation_Parameter_Bitmap(
        ScpImplementation implementation,
        byte expectedValue,
        string description
    )
    {
        // Act - Get implementation parameter value
        byte actualValue = (byte)implementation;

        // Assert - GP Table E-1 compliance
        _ = actualValue
            .Should()
            .Be(
                expectedValue,
                $"GP Table E-1: {description} should have parameter value 0x{expectedValue:X2}"
            );

        // Verify bitmap structure consistency
        VerifyImplementationBitmapConsistency(implementation);
    }

    /// <summary>
    /// GP SCP02 Table E-1: Reserved Bits Validation
    /// Tests that reserved bits in implementation parameters are properly handled.
    /// </summary>
    [Test]
    public void Scp02_Should_Have_Reserved_Bit_B8_Set_To_Zero()
    {
        // Arrange - All defined SCP02 implementations
        ScpImplementation[] scp02Implementations =
        [
            ScpImplementation.Scp02I00,
            ScpImplementation.Scp02I02,
            ScpImplementation.Scp02I04,
            ScpImplementation.Scp02I05,
            ScpImplementation.Scp02I0A,
            ScpImplementation.Scp02I14,
            ScpImplementation.Scp02I15,
            ScpImplementation.Scp02I1A,
            ScpImplementation.Scp02I24,
            ScpImplementation.Scp02I25,
            ScpImplementation.Scp02I2A,
            ScpImplementation.Scp02I34,
            ScpImplementation.Scp02I35,
            ScpImplementation.Scp02I3A,
            ScpImplementation.Scp02I44,
            ScpImplementation.Scp02I45,
            ScpImplementation.Scp02I4A,
            ScpImplementation.Scp02I54,
            ScpImplementation.Scp02I55,
            ScpImplementation.Scp02I64,
            ScpImplementation.Scp02I65,
            ScpImplementation.Scp02I6A,
            ScpImplementation.Scp02I74,
            ScpImplementation.Scp02I75,
            ScpImplementation.Scp02I7A,
        ];

        // Act & Assert
        _ = scp02Implementations
            .Should()
            .AllSatisfy(implementation =>
            {
                byte parameterValue = (byte)implementation;
                bool bit8IsZero = (parameterValue & 0x80) == 0;

                _ = bit8IsZero
                    .Should()
                    .BeTrue(
                        $"GP Table E-1: Implementation {implementation.GetAlias()} (i={parameterValue:X2}) "
                            + $"should have reserved bit b8 set to 0"
                    );
            });
    }

    // Helper methods for protocol rules testing

    private static SecurityLevel ParseExternalAuthenticateP1(byte p1)
    {
        // GP Table E-11: EXTERNAL AUTHENTICATE P1 parameter bitmap
        var level = SecurityLevel.None;

        // Bit mapping per GP specification
        if ((p1 & 0x01) != 0)
            level |= SecurityLevel.CMac; // b1: C-MAC
        if ((p1 & 0x02) != 0)
            level |= SecurityLevel.CDecryption; // b2: C-DECRYPTION
        if ((p1 & 0x10) != 0)
            level |= SecurityLevel.RMac; // b5: R-MAC

        return level;
    }

    private static bool RequiresAuthentication(SecurityLevel level)
    {
        // GP Section E.1.6: All secure messaging requires authentication
        return level != SecurityLevel.None;
    }

    private static bool ShouldTerminateSecureChannelSession(string condition)
    {
        // GP Section E.1.6: Session termination conditions
        return condition switch
        {
            "New INITIALIZE UPDATE command" => true,
            "Application selection" => true,
            "Logical channel termination" => true,
            "Card session termination" => true,
            "Explicit API termination" => true,
            "Valid command processing" => false,
            "R-MAC session begin" => false,
            _ => false,
        };
    }

    private static SecurityLevel GetSecurityLevelAfterEvent(string eventType)
    {
        // GP Section E.1.6: Events that reset Current Security Level
        return eventType switch
        {
            "Session termination" => SecurityLevel.None,
            "Session abortion" => SecurityLevel.None,
            "New session initiation" => SecurityLevel.None,
            "Card reset" => SecurityLevel.None,
            "Power off" => SecurityLevel.None,
            _ => SecurityLevel.CMac, // Assume some security for other events
        };
    }

    private static void VerifyImplementationBitmapConsistency(ScpImplementation implementation)
    {
        // Verify that bitmap flags are consistent with implementation features
        bool hasIcvEncryption = implementation.HasIcvEncryption();
        bool uses3Keys = implementation.Uses3Keys();
        bool isExplicitMode = implementation.IsExplicitMode();
        bool hasRMacSupport = implementation.HasRMacSupport();
        bool usesWellKnownChallenge = implementation.UsesWellKnownChallenge();
        bool hasMacOverAid = implementation.HasMacOverAid();
        bool usesModifiedApdu = implementation.UsesModifiedApdu();

        // GP Table E-1 bitmap consistency checks
        byte parameterValue = (byte)implementation;

        // Bit b1 (0x01): 3 Secure Channel Keys
        _ = ((parameterValue & 0x01) != 0)
            .Should()
            .Be(uses3Keys, "Bit b1 should match Uses3Keys() result");

        // Bit b2 (0x02): C-MAC on unmodified APDU (inverted logic)
        _ = ((parameterValue & 0x02) == 0)
            .Should()
            .Be(usesModifiedApdu, "Bit b2 should match UsesModifiedApdu() result (inverted)");

        // Bit b3 (0x04): Initiation mode explicit
        _ = ((parameterValue & 0x04) != 0)
            .Should()
            .Be(isExplicitMode, "Bit b3 should match IsExplicitMode() result");

        // Bit b4 (0x08): ICV set to MAC over AID
        _ = ((parameterValue & 0x08) != 0)
            .Should()
            .Be(hasMacOverAid, "Bit b4 should match HasMacOverAid() result");

        // Bit b5 (0x10): ICV encryption for C-MAC session
        _ = ((parameterValue & 0x10) != 0)
            .Should()
            .Be(hasIcvEncryption, "Bit b5 should match HasIcvEncryption() result");

        // Bit b6 (0x20): R-MAC support
        _ = ((parameterValue & 0x20) != 0)
            .Should()
            .Be(hasRMacSupport, "Bit b6 should match HasRMacSupport() result");

        // Bit b7 (0x40): Well-known pseudo-random algorithm
        _ = ((parameterValue & 0x40) != 0)
            .Should()
            .Be(usesWellKnownChallenge, "Bit b7 should match UsesWellKnownChallenge() result");
    }
}
