using System;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Protocol;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands
{
    [TestFixture]
    public class ExternalAuthenticateCommandTests
    {
        [Test]
        public void CreateWithMac_WithValidParameters_CreatesCommand()
        {
            // Arrange
            var securityLevel = SecurityLevel.CMac;
            var hostCryptogram = Convert.FromHexString("0102030405060708");
            var mac = Convert.FromHexString("1112131415161718");

            // Act
            var result = ExternalAuthenticateCommand.CreateWithMac(securityLevel, hostCryptogram, mac);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;
            Assert.That(command.SecurityLevel, Is.EqualTo(securityLevel));
            Assert.That(command.HostCryptogram, Is.EqualTo(hostCryptogram));
            Assert.That(command.Mac, Is.EqualTo(mac));
        }

        [Test]
        public void CreateWithMac_WithNullHostCryptogram_ReturnsFailure()
        {
            // Act
            var result = ExternalAuthenticateCommand.CreateWithMac(SecurityLevel.CMac, null!, new byte[8]);

            // Assert
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Does.Contain("Host cryptogram cannot be null"));
        }

        [Test]
        [TestCase(0)]
        [TestCase(7)]
        [TestCase(9)]
        [TestCase(16)]
        public void CreateWithoutMac_WithInvalidHostCryptogramLength_ReturnsFailure(int length)
        {
            // Arrange
            var hostCryptogram = new byte[length];

            // Act
            var result = ExternalAuthenticateCommand.CreateWithoutMac(SecurityLevel.CMac, hostCryptogram);

            // Assert
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Does.Contain("Host cryptogram must be 8 bytes"));
        }

        [Test]
        [TestCase(0)]
        [TestCase(7)]
        [TestCase(9)]
        [TestCase(16)]
        public void CreateWithMac_WithInvalidMacLength_ReturnsFailure(int length)
        {
            // Arrange
            var hostCryptogram = new byte[8];
            var mac = new byte[length];

            // Act
            var result = ExternalAuthenticateCommand.CreateWithMac(SecurityLevel.CMac, hostCryptogram, mac);

            // Assert
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Does.Contain("MAC must be 8 bytes"));
        }

        [Test]
        public void CreateWithoutMac_WithValidParameters_CreatesCommandWithEmptyMac()
        {
            // Arrange
            var securityLevel = SecurityLevel.None;
            var hostCryptogram = new byte[8];

            // Act
            var result = ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, hostCryptogram);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;
            Assert.That(command.Mac, Is.Empty);
        }

        [Test]
        public void GetApdu_WithoutMac_ReturnsCorrectStructure()
        {
            // Arrange
            var securityLevel = SecurityLevel.None;
            var hostCryptogram = Convert.FromHexString("0102030405060708");
            var result = ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, hostCryptogram);
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;

            // Act
            var apdu = command.GetApdu();

            // Assert
            Assert.That(apdu[0], Is.EqualTo(0x84)); // CLA - Secure messaging
            Assert.That(apdu[1], Is.EqualTo(0x82)); // INS - EXTERNAL AUTHENTICATE
            Assert.That(apdu[2], Is.EqualTo((byte)securityLevel)); // P1 - Security Level
            Assert.That(apdu[3], Is.EqualTo(0x00)); // P2 - RFU
            Assert.That(apdu[4], Is.EqualTo(0x08)); // Lc - Data length (8 bytes cryptogram)
            Assert.That(apdu[5..13], Is.EqualTo(hostCryptogram)); // Data - Host Cryptogram
            // No Le byte for EXTERNAL AUTHENTICATE
            Assert.That(apdu.Length, Is.EqualTo(13)); // 5 header + 8 data
        }

        [Test]
        public void GetApdu_WithMac_ReturnsCorrectStructure()
        {
            // Arrange
            var securityLevel = SecurityLevel.CMac;
            var hostCryptogram = Convert.FromHexString("0102030405060708");
            var mac = Convert.FromHexString("1112131415161718");
            var result = ExternalAuthenticateCommand.CreateWithMac(securityLevel, hostCryptogram, mac);
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;

            // Act
            var apdu = command.GetApdu();

            // Assert
            Assert.That(apdu[0], Is.EqualTo(0x84)); // CLA - Secure messaging
            Assert.That(apdu[1], Is.EqualTo(0x82)); // INS - EXTERNAL AUTHENTICATE
            Assert.That(apdu[2], Is.EqualTo((byte)securityLevel)); // P1 - Security Level
            Assert.That(apdu[3], Is.EqualTo(0x00)); // P2 - RFU
            Assert.That(apdu[4], Is.EqualTo(0x10)); // Lc - Data length (8 cryptogram + 8 MAC)
            Assert.That(apdu[5..13], Is.EqualTo(hostCryptogram)); // Host Cryptogram
            Assert.That(apdu[13..21], Is.EqualTo(mac)); // MAC
            Assert.That(apdu.Length, Is.EqualTo(21)); // 5 header + 8 cryptogram + 8 MAC
        }

        [Test]
        [TestCase(SecurityLevel.None, 0x00)]
        [TestCase(SecurityLevel.CMac, 0x01)]
        [TestCase(SecurityLevel.CDecryption, 0x03)]
        [TestCase(SecurityLevel.CDecryption, 0x03)]
        public void GetApdu_WithDifferentSecurityLevels_SetsP1Correctly(
            SecurityLevel securityLevel, byte expectedP1)
        {
            // Arrange
            var hostCryptogram = new byte[8];
            var result = ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, hostCryptogram);
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;

            // Act
            var apdu = command.GetApdu();

            // Assert
            Assert.That(apdu[2], Is.EqualTo(expectedP1)); // P1
        }

        [Test]
        public void GetApdu_AlwaysReturnsNewArray()
        {
            // Arrange
            var result = ExternalAuthenticateCommand.CreateWithMac(
                SecurityLevel.CMac, 
                new byte[8], 
                new byte[8]);
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;

            // Act
            var apdu1 = command.GetApdu();
            var apdu2 = command.GetApdu();

            // Assert
            Assert.That(apdu1, Is.Not.SameAs(apdu2)); // Should be different array instances
            Assert.That(apdu2, Is.EqualTo(apdu1)); // But with same content
        }

        [Test]
        public void ToString_ReturnsDescriptiveString()
        {
            // Arrange
            var hostCryptogram = Convert.FromHexString("0102030405060708");
            var mac = Convert.FromHexString("1112131415161718");
            var commandResult = ExternalAuthenticateCommand.CreateWithMac(SecurityLevel.CMac, hostCryptogram, mac);
            Assert.That(commandResult.IsSuccess, Is.True);
            var command = commandResult.Value;

            // Act
            var result = command.ToString();

            // Assert
            Assert.That(result, Does.Contain("EXTERNAL AUTHENTICATE"));
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

            var result = ExternalAuthenticateCommand.CreateWithMac(
                SecurityLevel.CMac,
                new byte[8],
                new byte[8]);
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;
            var apdu = command.GetApdu();

            Assert.That(apdu.Length, Is.EqualTo(21)); // 5 header + 8 cryptogram + 8 MAC
            Assert.That(apdu[0], Is.EqualTo(0x84)); // CLA
            Assert.That(apdu[1], Is.EqualTo(0x82)); // INS
            Assert.That(apdu[3], Is.EqualTo(0x00)); // P2
            Assert.That(apdu[4], Is.EqualTo(0x10)); // Lc
        }

        [Test]
        public void SecurityLevel_ForScp03_MapsCorrectly()
        {
            // According to SCP03 spec, P1 parameter encoding:
            // Bit 1: C-MAC on unmodified APDU
            // Bit 2: C-DECRYPTION and C-MAC on modified APDU
            // For SCP03: 0x00 = No Security, 0x01 = C-MAC, 0x03 = C-MAC + C-DEC

            var testCases = new[]
            {
                (SecurityLevel.None, (byte)0x00),
                (SecurityLevel.CMac, (byte)0x01),
                (SecurityLevel.CDecryption, (byte)0x03), // C-DEC implies C-MAC
                (SecurityLevel.CDecryption, (byte)0x03)
            };

            foreach (var (securityLevel, expectedP1) in testCases)
            {
                var result = ExternalAuthenticateCommand.CreateWithoutMac(securityLevel, new byte[8]);
                Assert.That(result.IsSuccess, Is.True);
                var command = result.Value;
                var apdu = command.GetApdu();
                Assert.That(apdu[2], Is.EqualTo(expectedP1));
            }
        }
    }
}