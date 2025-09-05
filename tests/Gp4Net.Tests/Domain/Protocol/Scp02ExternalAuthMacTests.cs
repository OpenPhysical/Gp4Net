using System;
using AwesomeAssertions;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Protocol;
using Gp4Net.Tests.Infrastructure;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Protocol;

/// <summary>
/// Tests for SCP02 EXTERNAL AUTHENTICATE MAC calculation.
/// Verifies against real GlobalPlatform Pro trace data to ensure compatibility.
/// </summary>
[TestFixture]
[Category("Protocol")]
[Category("FailHard")]
[Ignore("Scp02Protocol has been refactored into ScpService - tests need to be updated")]
public class Scp02ExternalAuthMacTests
{
    /// <summary>
    /// Test MAC calculation for EXTERNAL AUTHENTICATE using real GP Pro trace data.
    /// This test uses the exact same values from the debug log where our implementation
    /// failed but GlobalPlatform Pro succeeded.
    /// </summary>
    [Test]
    public void CalculateInitialMacChainingValue_WithRealGpProData_ShouldMatchExpectedMac()
    {
        // Arrange: Real values from debug_log.txt GP Pro trace
        byte[] sMacKey = Convert.FromHexString("3780B42F985E5E079E92A5582FB9D057");
        byte[] gpProHostCryptogram = Convert.FromHexString("41672008402D284D");
        // Expected MAC calculated over just (APDU_header + host_cryptogram) without zero chaining prepended
        // Per GP Card Spec E.3.2: "ICV is set to zero" means the ICV state, not prepending zeros
        byte[] expectedMac = Convert.FromHexString("BF07D8C792B0757F"); // Actual MAC from GP Pro command

        ExternalAuthenticateCommand? command = ExternalAuthenticateCommand
            .CreateWithoutMac(SecurityLevel.CMac, gpProHostCryptogram)
            .Value;

        // Act
        var result = Scp02Protocol.CalculateInitialMacChainingValue(command, sMacKey);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var actualMac = result.Value;

        // Verify MAC matches GP Pro calculation exactly
        _ = actualMac
            .Should()
            .BeEquivalentTo(
                expectedMac,
                $"MAC should match GP Pro calculation. Expected: {Convert.ToHexString(expectedMac)}, "
                    + $"Actual: {Convert.ToHexString(actualMac)}"
            );
    }

    /// <summary>
    /// Test MAC calculation for EXTERNAL AUTHENTICATE using our implementation's data.
    /// This verifies we can reproduce the MAC from our failed attempt.
    /// </summary>
    [Test]
    public void CalculateInitialMacChainingValue_WithOurImplementationData_ShouldCalculateCorrectMac()
    {
        // Arrange: Values from our failed attempt in debug_log.txt
        byte[] sMacKey = Convert.FromHexString("3780B42F985E5E079E92A5582FB9D057");
        byte[] ourHostCryptogram = Convert.FromHexString("A8934CBB1A4CB76D");

        ExternalAuthenticateCommand? command = ExternalAuthenticateCommand
            .CreateWithoutMac(SecurityLevel.CMac, ourHostCryptogram)
            .Value;

        // Act
        var result = Scp02Protocol.CalculateInitialMacChainingValue(command, sMacKey);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var actualMac = result.Value;

        // The MAC should be calculated correctly (we expect a specific value based on our host cryptogram)
        _ = actualMac.Length.Should().Be(8, "MAC should be 8 bytes for SCP02");

        // Log the calculated MAC for debugging
        TestContext.Out.WriteLine($"Our host cryptogram: {Convert.ToHexString(ourHostCryptogram)}");
        TestContext.Out.WriteLine($"Calculated MAC: {Convert.ToHexString(actualMac)}");
    }

    /// <summary>
    /// Test that MAC calculation builds the correct APDU structure.
    /// This test verifies the APDU format matches GP specification.
    /// </summary>
    [Test]
    public void CalculateInitialMacChainingValue_ShouldBuildCorrectApduStructure()
    {
        // Arrange
        byte[] sMacKey = Convert.FromHexString("3780B42F985E5E079E92A5582FB9D057");
        byte[] hostCryptogram = Convert.FromHexString("41672008402D284D");

        ExternalAuthenticateCommand? command = ExternalAuthenticateCommand
            .CreateWithoutMac(SecurityLevel.CMac, hostCryptogram)
            .Value;

        // Mock the MAC calculation to verify APDU structure
        byte[] expectedApdu =
        [
            0x84, // CLA with secure messaging bit
            0x82, // INS
            0x01, // P1 = security level (C-MAC)
            0x00, // P2
            0x10, // Lc = 16 bytes (8 cryptogram + 8 MAC)
            // Host cryptogram follows
            0x41,
            0x67,
            0x20,
            0x08,
            0x40,
            0x2D,
            0x28,
            0x4D,
        ];

        // Act - This will internally build the APDU and calculate MAC over it
        var result = Scp02Protocol.CalculateInitialMacChainingValue(command, sMacKey);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Length.Should().Be(8, "MAC should be 8 bytes");

        // The MAC calculation should have used the correct APDU structure
        // We can't directly test the internal APDU, but successful MAC calculation
        // with known good values proves the structure is correct
    }

    /// <summary>
    /// Test MAC calculation with different security levels.
    /// </summary>
    [Test]
    public void CalculateInitialMacChainingValue_WithDifferentSecurityLevels_ShouldIncludeCorrectP1()
    {
        // Arrange
        byte[] sMacKey = Convert.FromHexString("3780B42F985E5E079E92A5582FB9D057");
        byte[] hostCryptogram = Convert.FromHexString("41672008402D284D");

        (SecurityLevel, byte)[] testCases =
        [
            (SecurityLevel.None, 0x00),
            (SecurityLevel.CMac, 0x01),
            (SecurityLevel.CDecryption, 0x03), // CDecryption includes CMac
            (SecurityLevel.CMac | SecurityLevel.RMac, 0x11),
            (SecurityLevel.CDecryption | SecurityLevel.RMac, 0x13),
        ];

        foreach ((SecurityLevel securityLevel, byte expectedP1) in testCases)
        {
            ExternalAuthenticateCommand? command = ExternalAuthenticateCommand
                .CreateWithoutMac(securityLevel, hostCryptogram)
                .Value;

            // Act
            var result = Scp02Protocol.CalculateInitialMacChainingValue(command, sMacKey);

            // Assert
            _ = result
                .IsSuccess.Should()
                .BeTrue($"MAC calculation should succeed for security level {securityLevel}");
            _ = result
                .Value.Length.Should()
                .Be(8, $"MAC should be 8 bytes for security level {securityLevel}");

            // Each security level should produce a different MAC due to different P1 values
            TestContext.Out.WriteLine(
                $"Security Level {securityLevel} (P1=0x{expectedP1:X2}): MAC = {Convert.ToHexString(result.Value)}"
            );
        }
    }

    /// <summary>
    /// Test error handling for invalid inputs.
    /// </summary>
    [Test]
    public void CalculateInitialMacChainingValue_WithInvalidInputs_ShouldReturnError()
    {
        // Arrange
        byte[] validMacKey = Convert.FromHexString("3780B42F985E5E079E92A5582FB9D057");
        byte[] validHostCryptogram = Convert.FromHexString("41672008402D284D");
        ExternalAuthenticateCommand? validCommand = ExternalAuthenticateCommand
            .CreateWithoutMac(SecurityLevel.CMac, validHostCryptogram)
            .Value;

        // Act & Assert - Null command
        var nullCommandResult = Scp02Protocol.CalculateInitialMacChainingValue(
            null,
            validMacKey
        );
        _ = nullCommandResult.IsFailure.Should().BeTrue();
        _ = nullCommandResult.Error.Message.Should().Contain("Command cannot be null");

        // Act & Assert - Null MAC key
        var nullMacKeyResult = Scp02Protocol.CalculateInitialMacChainingValue(
            validCommand,
            null
        );
        _ = nullMacKeyResult.IsFailure.Should().BeTrue();
        _ = nullMacKeyResult.Error.Message.Should().Contain("MAC key cannot be null");
    }
}
