using System;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Protocol;
using Xunit;

namespace Gp4Net.Tests.Domain.Commands
{
    public class ExternalAuthenticateCommandTests
    {
        [Fact]
        public void Constructor_WithValidParameters_CreatesCommand()
        {
            // Arrange
            var securityLevel = SecurityLevel.CMac;
            var hostCryptogram = Convert.FromHexString("0102030405060708");
            var mac = Convert.FromHexString("1112131415161718");

            // Act
            var command = new ExternalAuthenticateCommand(securityLevel, hostCryptogram, mac);

            // Assert
            Assert.Equal(securityLevel, command.SecurityLevel);
            Assert.Equal(hostCryptogram, command.HostCryptogram);
            Assert.Equal(mac, command.Mac);
        }

        [Fact]
        public void Constructor_WithNullHostCryptogram_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new ExternalAuthenticateCommand(SecurityLevel.CMac, null!, null));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(7)]
        [InlineData(9)]
        [InlineData(16)]
        public void Constructor_WithInvalidHostCryptogramLength_ThrowsArgumentException(int length)
        {
            // Arrange
            var hostCryptogram = new byte[length];

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => 
                new ExternalAuthenticateCommand(SecurityLevel.CMac, hostCryptogram, null));
            Assert.Contains("Host cryptogram must be 8 bytes", ex.Message);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(7)]
        [InlineData(9)]
        [InlineData(16)]
        public void Constructor_WithInvalidMacLength_ThrowsArgumentException(int length)
        {
            // Arrange
            var hostCryptogram = new byte[8];
            var mac = new byte[length];

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => 
                new ExternalAuthenticateCommand(SecurityLevel.CMac, hostCryptogram, mac));
            Assert.Contains("MAC must be 8 bytes", ex.Message);
        }

        [Fact]
        public void Constructor_WithoutMac_AllowsNullMac()
        {
            // Arrange
            var securityLevel = SecurityLevel.NoSecurity;
            var hostCryptogram = new byte[8];

            // Act
            var command = new ExternalAuthenticateCommand(securityLevel, hostCryptogram, null);

            // Assert
            Assert.Null(command.Mac);
        }

        [Fact]
        public void GetApdu_WithoutMac_ReturnsCorrectStructure()
        {
            // Arrange
            var securityLevel = SecurityLevel.NoSecurity;
            var hostCryptogram = Convert.FromHexString("0102030405060708");
            var command = new ExternalAuthenticateCommand(securityLevel, hostCryptogram, null);

            // Act
            var apdu = command.GetApdu();

            // Assert
            Assert.Equal(0x84, apdu[0]); // CLA - Secure messaging
            Assert.Equal(0x82, apdu[1]); // INS - EXTERNAL AUTHENTICATE
            Assert.Equal((byte)securityLevel, apdu[2]); // P1 - Security Level
            Assert.Equal(0x00, apdu[3]); // P2 - RFU
            Assert.Equal(0x08, apdu[4]); // Lc - Data length (8 bytes cryptogram)
            Assert.Equal(hostCryptogram, apdu[5..13]); // Data - Host Cryptogram
            // No Le byte for EXTERNAL AUTHENTICATE
            Assert.Equal(13, apdu.Length); // 5 header + 8 data
        }

        [Fact]
        public void GetApdu_WithMac_ReturnsCorrectStructure()
        {
            // Arrange
            var securityLevel = SecurityLevel.CMac;
            var hostCryptogram = Convert.FromHexString("0102030405060708");
            var mac = Convert.FromHexString("1112131415161718");
            var command = new ExternalAuthenticateCommand(securityLevel, hostCryptogram, mac);

            // Act
            var apdu = command.GetApdu();

            // Assert
            Assert.Equal(0x84, apdu[0]); // CLA - Secure messaging
            Assert.Equal(0x82, apdu[1]); // INS - EXTERNAL AUTHENTICATE
            Assert.Equal((byte)securityLevel, apdu[2]); // P1 - Security Level
            Assert.Equal(0x00, apdu[3]); // P2 - RFU
            Assert.Equal(0x10, apdu[4]); // Lc - Data length (8 cryptogram + 8 MAC)
            Assert.Equal(hostCryptogram, apdu[5..13]); // Host Cryptogram
            Assert.Equal(mac, apdu[13..21]); // MAC
            Assert.Equal(21, apdu.Length); // 5 header + 8 cryptogram + 8 MAC
        }

        [Theory]
        [InlineData(SecurityLevel.NoSecurity, 0x00)]
        [InlineData(SecurityLevel.CMac, 0x01)]
        [InlineData(SecurityLevel.CDecryption, 0x03)]
        [InlineData(SecurityLevel.CMacAndCDecryption, 0x03)]
        public void GetApdu_WithDifferentSecurityLevels_SetsP1Correctly(
            SecurityLevel securityLevel, byte expectedP1)
        {
            // Arrange
            var hostCryptogram = new byte[8];
            var command = new ExternalAuthenticateCommand(securityLevel, hostCryptogram, null);

            // Act
            var apdu = command.GetApdu();

            // Assert
            Assert.Equal(expectedP1, apdu[2]); // P1
        }

        [Fact]
        public void GetApdu_AlwaysReturnsNewArray()
        {
            // Arrange
            var command = new ExternalAuthenticateCommand(
                SecurityLevel.CMac, 
                new byte[8], 
                new byte[8]);

            // Act
            var apdu1 = command.GetApdu();
            var apdu2 = command.GetApdu();

            // Assert
            Assert.NotSame(apdu1, apdu2); // Should be different array instances
            Assert.Equal(apdu1, apdu2); // But with same content
        }

        [Fact]
        public void ToString_ReturnsDescriptiveString()
        {
            // Arrange
            var hostCryptogram = Convert.FromHexString("0102030405060708");
            var mac = Convert.FromHexString("1112131415161718");
            var command = new ExternalAuthenticateCommand(SecurityLevel.CMac, hostCryptogram, mac);

            // Act
            var result = command.ToString();

            // Assert
            Assert.Contains("EXTERNAL AUTHENTICATE", result);
            Assert.Contains("C-MAC", result); // Security level
        }

        [Fact]
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

            var command = new ExternalAuthenticateCommand(
                SecurityLevel.CMac,
                new byte[8],
                new byte[8]);
            var apdu = command.GetApdu();

            Assert.Equal(21, apdu.Length); // 5 header + 8 cryptogram + 8 MAC
            Assert.Equal(0x84, apdu[0]); // CLA
            Assert.Equal(0x82, apdu[1]); // INS
            Assert.Equal(0x00, apdu[3]); // P2
            Assert.Equal(0x10, apdu[4]); // Lc
        }

        [Fact]
        public void SecurityLevel_ForScp03_MapsCorrectly()
        {
            // According to SCP03 spec, P1 parameter encoding:
            // Bit 1: C-MAC on unmodified APDU
            // Bit 2: C-DECRYPTION and C-MAC on modified APDU
            // For SCP03: 0x00 = No Security, 0x01 = C-MAC, 0x03 = C-MAC + C-DEC

            var testCases = new[]
            {
                (SecurityLevel.NoSecurity, (byte)0x00),
                (SecurityLevel.CMac, (byte)0x01),
                (SecurityLevel.CDecryption, (byte)0x03), // C-DEC implies C-MAC
                (SecurityLevel.CMacAndCDecryption, (byte)0x03)
            };

            foreach (var (securityLevel, expectedP1) in testCases)
            {
                var command = new ExternalAuthenticateCommand(securityLevel, new byte[8], null);
                var apdu = command.GetApdu();
                Assert.Equal(expectedP1, apdu[2]);
            }
        }
    }
}