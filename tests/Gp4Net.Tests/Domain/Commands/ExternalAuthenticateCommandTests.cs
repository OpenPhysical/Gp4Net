using System;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

[TestFixture]
public class ExternalAuthenticateCommandTests
{
    [Test]
    public void CreateWithMac_WithValidParameters_CreatesCommand()
    {
        // Arrange
        var securityLevel = SecurityLevel.CMac;
        byte[] hostCryptogram = Convert.FromHexString("0102030405060708");
        byte[] mac = Convert.FromHexString("1112131415161718");

        // Act
        Result<ExternalAuthenticateCommand, SmartCardError> result =
            ExternalAuthenticateCommand.CreateWithMac(securityLevel, hostCryptogram, mac);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.SecurityLevel.Should().Be(securityLevel);
        _ = command.HostCryptogram.Should().BeEquivalentTo(hostCryptogram);
        _ = command.Mac.Should().BeEquivalentTo(mac);
    }

    [Test]
    public void CreateWithMac_WithNullHostCryptogram_ReturnsFailure()
    {
        // Act
        Result<ExternalAuthenticateCommand, SmartCardError> result =
            ExternalAuthenticateCommand.CreateWithMac(SecurityLevel.CMac, null!, new byte[8]);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Host cryptogram cannot be null");
    }

    [Test]
    [TestCase(0)]
    [TestCase(7)]
    [TestCase(9)]
    [TestCase(16)]
    public void CreateWithoutMac_WithInvalidHostCryptogramLength_ReturnsFailure(int length)
    {
        // Arrange
        byte[] hostCryptogram = new byte[length];

        // Act
        Result<ExternalAuthenticateCommand, SmartCardError> result =
            ExternalAuthenticateCommand.CreateWithoutMac(SecurityLevel.CMac, hostCryptogram);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Host cryptogram must be 8 bytes");
    }

    [Test]
    [TestCase(0)]
    [TestCase(7)]
    [TestCase(9)]
    [TestCase(16)]
    public void CreateWithMac_WithInvalidMacLength_ReturnsFailure(int length)
    {
        // Arrange
        byte[] hostCryptogram = new byte[8];
        byte[] mac = new byte[length];

        // Act
        Result<ExternalAuthenticateCommand, SmartCardError> result =
            ExternalAuthenticateCommand.CreateWithMac(SecurityLevel.CMac, hostCryptogram, mac);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("MAC must be 8 bytes");
    }

    [Test]
    public void CreateWithoutMac_WithValidParameters_CreatesCommandWithEmptyMac()
    {
        // Arrange
        var securityLevel = SecurityLevel.None;
        byte[] hostCryptogram = new byte[8];

        // Act
        Result<ExternalAuthenticateCommand, SmartCardError> result =
            ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, hostCryptogram);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Mac.Should().BeEmpty();
    }

    [Test]
    public void GetApdu_WithoutMac_ReturnsCorrectStructure()
    {
        // Arrange
        var securityLevel = SecurityLevel.None;
        byte[] hostCryptogram = Convert.FromHexString("0102030405060708");

        // Act & Assert
        ExternalAuthenticateCommand
            .CreateWithoutMac(securityLevel, hostCryptogram)
            .Map(command => command.ToBytes())
            .Match(
                apdu =>
                {
                    _ = apdu[0].Should().Be(0x00); // CLA - No secure messaging for no MAC
                    _ = apdu[1].Should().Be(0x82); // INS - EXTERNAL AUTHENTICATE
                    _ = apdu[2].Should().Be((byte)securityLevel); // P1 - Security Level
                    _ = apdu[3].Should().Be(0x00); // P2 - RFU
                    _ = apdu[4].Should().Be(0x08); // Lc - Data length (8 bytes cryptogram)
                    _ = apdu[5..13].Should().BeEquivalentTo(hostCryptogram); // Data - Host Cryptogram
                    // No Le byte for EXTERNAL AUTHENTICATE
                    _ = apdu.Length.Should().Be(13); // 5 header + 8 data
                },
                error =>
                    Result
                        .Success()
                        .IsSuccess.Should()
                        .BeTrue($"Command creation or APDU building failed: {error}")
            );
    }

    [Test]
    public void GetApdu_WithMac_ReturnsCorrectStructure()
    {
        // Arrange
        var securityLevel = SecurityLevel.CMac;
        byte[] hostCryptogram = Convert.FromHexString("0102030405060708");
        byte[] mac = Convert.FromHexString("1112131415161718");

        // Act & Assert
        ExternalAuthenticateCommand
            .CreateWithMac(securityLevel, hostCryptogram, mac)
            .Map(command => command.ToBytes())
            .Match(
                apdu =>
                {
                    _ = apdu[0].Should().Be(0x84); // CLA - Secure messaging
                    _ = apdu[1].Should().Be(0x82); // INS - EXTERNAL AUTHENTICATE
                    _ = apdu[2].Should().Be((byte)securityLevel); // P1 - Security Level
                    _ = apdu[3].Should().Be(0x00); // P2 - RFU
                    _ = apdu[4].Should().Be(0x10); // Lc - Data length (8 cryptogram + 8 MAC)
                    _ = apdu[5..13].Should().BeEquivalentTo(hostCryptogram); // Host Cryptogram
                    _ = apdu[13..21].Should().BeEquivalentTo(mac); // MAC
                    _ = apdu.Length.Should().Be(21); // 5 header + 8 cryptogram + 8 MAC
                },
                error =>
                    Result.Success().IsSuccess.Should().BeTrue($"Command creation failed: {error}")
            );
    }

    [Test]
    [TestCase(SecurityLevel.None, 0x00)]
    [TestCase(SecurityLevel.CMac, 0x01)]
    [TestCase(SecurityLevel.CDecryption, 0x03)]
    public void GetApdu_WithDifferentSecurityLevels_SetsP1Correctly(
        SecurityLevel securityLevel,
        byte expectedP1
    )
    {
        // Arrange
        byte[] hostCryptogram = new byte[8];

        // Act & Assert
        ExternalAuthenticateCommand
            .CreateWithoutMac(securityLevel, hostCryptogram)
            .Map(command => command.ToBytes())
            .Match(
                apdu =>
                {
                    _ = apdu[2].Should().Be(expectedP1); // P1
                },
                error =>
                    Result.Success().IsSuccess.Should().BeTrue($"Command creation failed: {error}")
            );
    }

    [Test]
    public void GetApdu_AlwaysReturnsNewArray()
    {
        // Arrange & Act
        ExternalAuthenticateCommand
            .CreateWithMac(SecurityLevel.CMac, new byte[8], new byte[8])
            .Match(
                command =>
                {
                    byte[] apdu1 = command.ToBytes();
                    byte[] apdu2 = command.ToBytes();

                    // Assert
                    _ = apdu1.Should().NotBeSameAs(apdu2); // Should be different array instances
                    _ = apdu2.Should().BeEquivalentTo(apdu1); // But with same content
                },
                error =>
                    Result.Success().IsSuccess.Should().BeTrue($"Command creation failed: {error}")
            );
    }

    [Test]
    public void ToString_ReturnsDescriptiveString()
    {
        // Arrange
        byte[] hostCryptogram = Convert.FromHexString("0102030405060708");
        byte[] mac = Convert.FromHexString("1112131415161718");
        Result<ExternalAuthenticateCommand, SmartCardError> commandResult =
            ExternalAuthenticateCommand.CreateWithMac(SecurityLevel.CMac, hostCryptogram, mac);
        _ = commandResult.IsSuccess.Should().BeTrue();
        var command = commandResult.Value;

        // Act
        string? result = command.ToString();

        // Assert
        _ = result.Should().Contain("EXTERNAL AUTHENTICATE");
    }

    [Test]
    public void Command_FollowsGlobalPlatformSpecification()
    {
        // This test documents that the command follows GlobalPlatform Card Specification
        // EXTERNAL AUTHENTICATE command format:
        // CLA: 0x84 (Secure messaging)
        // INS: 0x82 (EXTERNAL AUTHENTICATE)
        // P1: Security Level
        // P2: 0x00 (RFU)
        // Lc: Variable (8 for cryptogram only, 16 for cryptogram + MAC)
        // Data: Host Cryptogram [+ MAC]
        // No Le byte

        ExternalAuthenticateCommand
            .CreateWithMac(SecurityLevel.CMac, new byte[8], new byte[8])
            .Map(command => command.ToBytes())
            .Match(
                apdu =>
                {
                    _ = apdu.Length.Should().Be(21); // 5 header + 8 cryptogram + 8 MAC
                    _ = apdu[0].Should().Be(0x84); // CLA
                    _ = apdu[1].Should().Be(0x82); // INS
                    _ = apdu[3].Should().Be(0x00); // P2
                    _ = apdu[4].Should().Be(0x10); // Lc
                },
                error =>
                    Result.Success().IsSuccess.Should().BeTrue($"Command creation failed: {error}")
            );
    }

    [Test]
    public void SecurityLevel_ForScp03_MapsCorrectly()
    {
        // According to SCP03 spec, P1 parameter encoding:
        // Bit 1: C-MAC on unmodified APDU
        // Bit 2: C-DECRYPTION and C-MAC on modified APDU
        // For SCP03: 0x00 = No Security, 0x01 = C-MAC, 0x03 = C-MAC + C-DEC

        (SecurityLevel, byte)[] testCases =
        [
            (SecurityLevel.None, 0x00),
            (SecurityLevel.CMac, 0x01),
            (SecurityLevel.CDecryption, 0x03), // C-DEC implies C-MAC
            (SecurityLevel.CDecryption, 0x03),
        ];

        testCases
            .Select(testCase =>
                ExternalAuthenticateCommand
                    .CreateWithoutMac(testCase.Item1, new byte[8])
                    .Map(command => command.ToBytes())
                    .Match(
                        apdu =>
                        {
                            _ = apdu[2].Should().Be(testCase.Item2);
                            return Result.Success();
                        },
                        error => Result.Failure($"Command creation failed: {error}")
                    )
            )
            .ToList(); // Execute all tests
    }
}
