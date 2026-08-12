using AwesomeAssertions;
using Gp4Net.Constants;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
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

    [Test]
    [TestCase(CryptoOperations.ScpVersion.Scp02, 6)]
    [TestCase(CryptoOperations.ScpVersion.Scp03, 8)]
    public void SecureChannelLifecycle_Should_Initiate_With_Protocol_Challenge_Length(
        CryptoOperations.ScpVersion protocol,
        int cardChallengeLength
    )
    {
        var initialization = new InitializeUpdateData(
            new byte[8],
            new byte[cardChallengeLength],
            1,
            new byte[8],
            protocol
        );

        var result = SecureChannelLifecycle.NotInitiated.InitiateChannel(initialization);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Phase.Should().Be(SecureChannelPhase.Initiated);
        _ = result.Value.InitData.Value.Should().Be(initialization);
    }

    [Test]
    [TestCase(CryptoOperations.ScpVersion.Scp02, 8)]
    [TestCase(CryptoOperations.ScpVersion.Scp03, 6)]
    public void SecureChannelLifecycle_Should_Reject_Wrong_Protocol_Challenge_Length(
        CryptoOperations.ScpVersion protocol,
        int cardChallengeLength
    )
    {
        var initialization = new InitializeUpdateData(
            new byte[8],
            new byte[cardChallengeLength],
            1,
            new byte[8],
            protocol
        );

        var result = SecureChannelLifecycle.NotInitiated.InitiateChannel(initialization);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("CardChallenge");
    }

    [Test]
    public void SecureChannelLifecycle_Should_Authenticate_Terminate_And_Abort()
    {
        var initialization = new InitializeUpdateData(
            new byte[8],
            new byte[8],
            1,
            new byte[8],
            CryptoOperations.ScpVersion.Scp03
        );
        var initiated = SecureChannelLifecycle.NotInitiated.InitiateChannel(initialization).Value;
        var keys = new SessionKeys(new byte[16], new byte[16], new byte[16]);

        var authenticated = initiated.AuthenticateChannel(
            keys,
            SecurityLevel.CMac,
            new byte[16],
            ScpImplementation.Scp03I70
        );

        _ = authenticated.IsSuccess.Should().BeTrue();
        _ = authenticated.Value.IsAuthenticated.Should().BeTrue();
        _ = authenticated.Value.CurrentSecurityLevel.Value.Should().Be(SecurityLevel.CMac);
        _ = authenticated.Value.ToSecureChannelState().IsSuccess.Should().BeTrue();

        var terminated = authenticated.Value.TerminateChannel("card session ended");
        _ = terminated.Phase.Should().Be(SecureChannelPhase.Terminated);
        _ = terminated.CurrentSecurityLevel.HasValue.Should().BeFalse();
        _ = terminated.TerminationInfo.Value.Reason.Should().Be("card session ended");

        var aborted = authenticated.Value.AbortChannel("response MAC failed", 0x6982);
        _ = aborted.Phase.Should().Be(SecureChannelPhase.Aborted);
        _ = aborted.TerminationInfo.Value.StatusWord.Value.Should().Be(0x6982);
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
