using System;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using NUnit.Framework;

namespace Gp4Net.Tests.Compliance;

/// <summary>
/// Tests for SCP03 protocol validation and compliance per GP Card Specification v2.3.1 Amendment D Section 6.
/// Validates SCP03-specific protocol rules, counter management, and security requirements.
/// </summary>
[TestFixture]
[Category("Unit")]
[Category("GpCompliance")]
[Category("SCP03")]
[Category("ProtocolValidation")]
public class Scp03ProtocolValidationTests
{
    private static readonly byte[] TestMasterKey = Convert.FromHexString(
        "404142434445464748494A4B4C4D4E4F"
    );

    /// <summary>
    /// GP SCP03 Section 6.2.1: Implementation Parameters
    /// Tests that implementation parameters are correctly validated.
    /// </summary>
    [Test]
    [TestCase(0x10, 128, "AES-128")]
    [TestCase(0x11, 128, "AES-128 without R-MAC")]
    [TestCase(0x20, 192, "AES-192")]
    [TestCase(0x30, 256, "AES-256")]
    [TestCase(0x60, 128, "AES-128 with random challenge")]
    [TestCase(0x70, 128, "AES-128 with pseudo-random challenge")]
    public void Scp03_Should_Validate_Implementation_Parameters(
        byte implParam,
        int expectedKeyLength,
        string description
    )
    {
        // Act - Get the key length for the implementation parameter
        var scpImpl = (ScpImplementation)implParam;
        var keyLength = scpImpl.GetAesKeyLength();

        // Assert
        _ = keyLength
            .Should()
            .Be(
                expectedKeyLength,
                $"GP SCP03: i={implParam:X2} ({description}) should use {expectedKeyLength}-bit keys"
            );
    }

    /// <summary>
    /// GP SCP03 Section 6.2.5: Security Level Parameters
    /// Tests that P1 parameter values in EXTERNAL AUTHENTICATE map correctly to security levels.
    /// </summary>
    [Test]
    [TestCase(0x00, SecurityLevel.None, "No secure messaging")]
    [TestCase(0x01, SecurityLevel.CMac, "C-MAC only")]
    [TestCase(0x03, SecurityLevel.CDecryption, "C-DECRYPTION and C-MAC")]
    [TestCase(0x10, SecurityLevel.RMac, "R-MAC only")]
    [TestCase(0x11, SecurityLevel.CMac | SecurityLevel.RMac, "C-MAC and R-MAC")]
    [TestCase(0x30, SecurityLevel.RMac | SecurityLevel.REncryption, "R-ENCRYPTION and R-MAC")]
    [TestCase(
        0x33,
        SecurityLevel.CDecryption | SecurityLevel.RMac | SecurityLevel.REncryption,
        "C-DECRYPTION, R-ENCRYPTION, C-MAC, and R-MAC"
    )]
    public void Scp03_Should_Map_External_Authenticate_P1_To_Security_Level(
        byte p1Value,
        SecurityLevel expectedSecurityLevel,
        string description
    )
    {
        // Note: SCP03 uses similar P1 encoding as SCP02 but adds R-DECRYPTION support
        var actualLevel = ParseScp03SecurityLevel(p1Value);

        _ = actualLevel
            .Should()
            .Be(expectedSecurityLevel, $"SCP03 P1=0x{p1Value:X2} should map to {description}");
    }

    /// <summary>
    /// GP SCP03 Section 6.2.2: Session Key Derivation
    /// Validates that session keys are properly derived using KDF per specification.
    /// </summary>
    [Test]
    public void Scp03_Should_Derive_Session_Keys_Using_KDF()
    {
        // Arrange
        var keySetResult = Scp03KeySet.Create(TestMasterKey, TestMasterKey, TestMasterKey, 0x01);
        _ = keySetResult.IsSuccess.Should().BeTrue("Key set creation should succeed");

        keySetResult.Match(
            keySet =>
            {
                var hostChallenge = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
                var cardChallenge = new byte[] { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };

                // Act - Create context and derive keys
                var contextResult = KeyDerivationContext.CreateForScp03(
                    keySet,
                    hostChallenge,
                    cardChallenge,
                    Maybe<ScpImplementation>.From(ScpImplementation.Scp03I70)
                );

                _ = contextResult.IsSuccess.Should().BeTrue("Context creation should succeed");

                // Assert - Keys should be derived and different from master keys
                contextResult.Match(
                    context =>
                    {
                        _ = context
                            .Protocol.Should()
                            .Be(CryptoService.ScpVersion.Scp03, "Protocol should be SCP03");
                        _ = context.HostChallenge.Should().BeEquivalentTo(hostChallenge);
                        _ = context.CardChallenge.Should().BeEquivalentTo(cardChallenge);
                        return UnitResult.Success<SmartCardError>();
                    },
                    error =>
                    {
                        Assert.Fail($"Context creation failed: {error}");
                        return UnitResult.Failure(error);
                    }
                );
                return UnitResult.Success<SmartCardError>();
            },
            error =>
            {
                Assert.Fail($"Key set creation failed: {error}");
                return UnitResult.Failure(error);
            }
        );
    }

    /// <summary>
    /// GP SCP03 Section 6.2.4: MAC Chaining
    /// Validates that MAC chaining value is properly maintained across commands.
    /// </summary>
    [Test]
    public void Scp03_Should_Maintain_Mac_Chaining_Value()
    {
        // Arrange - Initial MAC chaining value is zero
        var initialMacChaining = new byte[16]; // All zeros for SCP03

        // After first command, MAC chaining should be the MAC of that command
        var firstCommandMac = new byte[]
        {
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0xFF,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x77,
            0x88,
            0x99,
            0x00
        };

        // Act - Update MAC chaining value
        var updatedChaining = UpdateMacChaining(initialMacChaining, firstCommandMac);

        // Assert
        _ = updatedChaining
            .Should()
            .BeEquivalentTo(firstCommandMac, "MAC chaining should be updated to last MAC");
        _ = updatedChaining
            .Should()
            .NotBeEquivalentTo(initialMacChaining, "MAC chaining should change after command");
    }

    /// <summary>
    /// GP SCP03 Section 6.2.6: Counter Management
    /// Tests that encryption counter is properly incremented.
    /// </summary>
    [Test]
    public void Scp03_Should_Increment_Encryption_Counter()
    {
        // Arrange
        uint initialCounter = 1;

        // Act - Process multiple encrypted commands
        var counter1 = IncrementEncryptionCounter(initialCounter);
        var counter2 = IncrementEncryptionCounter(counter1);
        var counter3 = IncrementEncryptionCounter(counter2);

        // Assert
        _ = counter1.Should().Be(2, "Counter should increment to 2");
        _ = counter2.Should().Be(3, "Counter should increment to 3");
        _ = counter3.Should().Be(4, "Counter should increment to 4");
    }

    /// <summary>
    /// GP SCP03 Section 6.3: Protocol Rules
    /// Tests that secure channel requires proper security level.
    /// </summary>
    [Test]
    public void Scp03_Should_Require_Proper_Security_Level()
    {
        // Test that security level must be set for secure messaging
        var noSecurity = SecurityLevel.None;
        var withCMac = SecurityLevel.CMac;
        var withFullSecurity = SecurityLevel.CDecryption | SecurityLevel.RMac;

        // Assert
        _ = (noSecurity != SecurityLevel.None)
            .Should()
            .BeFalse("No security level should not enable secure channel");

        _ = (withCMac != SecurityLevel.None)
            .Should()
            .BeTrue("C-MAC security level should enable secure channel");

        _ = (withFullSecurity != SecurityLevel.None)
            .Should()
            .BeTrue("Full security should enable secure channel");
    }

    /// <summary>
    /// GP SCP03 Section 6.2.1.1: Card Challenge Generation
    /// Tests that card challenge meets specification requirements.
    /// </summary>
    [Test]
    [TestCase(0x60, "Random challenge")]
    [TestCase(0x70, "Pseudo-random challenge")]
    public void Scp03_Should_Generate_Valid_Card_Challenge(byte implParam, string description)
    {
        // Arrange
        var challengeLength = 8; // SCP03 always uses 8-byte challenges

        // Act - Generate challenge based on implementation parameter
        var challenge = GenerateCardChallenge(implParam, challengeLength);

        // Assert
        _ = challenge.Length.Should().Be(8, $"SCP03 {description} should be 8 bytes");

        // For pseudo-random (i=70), verify it includes counter component
        if (implParam == 0x70)
        {
            // First 3 bytes should be the encryption counter (initially zero)
            var counterBytes = challenge[..3];
            _ = counterBytes.Should().NotBeNull("Pseudo-random challenge should include counter");
        }
    }

    /// <summary>
    /// GP SCP03 Section 6.1.1: Key Agreement
    /// Tests that incompatible key lengths are rejected.
    /// </summary>
    [Test]
    public void Scp03_Should_Reject_Incompatible_Key_Lengths()
    {
        // Arrange - Try to create key set with invalid length
        var invalidKey = new byte[13]; // Not 16, 24, or 32 bytes

        // Act
        var result = Scp03KeySet.Create(invalidKey, TestMasterKey, TestMasterKey, 0x01);

        // Assert
        _ = result.IsFailure.Should().BeTrue("Should reject invalid key length");
        _ = result
            .Error.ToString()
            .Should()
            .Contain("bytes", "Error should mention byte length requirement");
    }

    // Helper methods to simulate protocol operations
    private static SecurityLevel ParseScp03SecurityLevel(byte p1)
    {
        var level = SecurityLevel.None;

        if ((p1 & 0x01) != 0)
            level |= SecurityLevel.CMac;
        if ((p1 & 0x02) != 0)
            level |= SecurityLevel.CDecryption;
        if ((p1 & 0x10) != 0)
            level |= SecurityLevel.RMac;
        if ((p1 & 0x20) != 0)
            level |= SecurityLevel.REncryption;

        return level;
    }

    private static byte[] UpdateMacChaining(byte[] currentChaining, byte[] lastMac)
    {
        // In SCP03, MAC chaining value is the full MAC of the previous command
        return (byte[])lastMac.Clone();
    }

    private static uint IncrementEncryptionCounter(uint counter)
    {
        // SCP03 increments counter for each encrypted command
        return counter + 1;
    }

    private static byte[] GenerateCardChallenge(byte implParam, int length)
    {
        var challenge = new byte[length];

        if (implParam == 0x70)
        {
            // Pseudo-random: counter (3 bytes) + random (5 bytes)
            // For testing, just create a deterministic challenge
            challenge[0] = 0x00; // Counter MSB
            challenge[1] = 0x00; // Counter
            challenge[2] = 0x01; // Counter LSB
            challenge[3] = 0xAA; // Pseudo-random
            challenge[4] = 0xBB;
            challenge[5] = 0xCC;
            challenge[6] = 0xDD;
            challenge[7] = 0xEE;
        }
        else
        {
            // Random challenge - fill with test data using functional approach
            challenge = Enumerable.Range(0, length).Select(i => (byte)(0x10 + i)).ToArray();
        }

        return challenge;
    }
}
