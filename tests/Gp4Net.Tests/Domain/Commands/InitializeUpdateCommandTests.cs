using System;
using Gp4Net.Domain.Commands;
using Xunit;

namespace Gp4Net.Tests.Domain.Commands
{
    public class InitializeUpdateCommandTests
    {
        [Fact]
        public void Constructor_WithValidParameters_CreatesCommand()
        {
            // Arrange
            byte keyVersion = 0x01;
            byte keyId = 0x00;
            var hostChallenge = Convert.FromHexString("0102030405060708");

            // Act
            var command = new InitializeUpdateCommand(keyVersion, keyId, hostChallenge);

            // Assert
            Assert.Equal(keyVersion, command.KeyVersion);
            Assert.Equal(keyId, command.KeyIdentifier);
            Assert.Equal(hostChallenge, command.HostChallenge);
        }

        [Fact]
        public void Constructor_WithNullHostChallenge_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new InitializeUpdateCommand(0x01, 0x00, null!));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(7)]
        [InlineData(9)]
        [InlineData(16)]
        public void Constructor_WithInvalidHostChallengeLength_ThrowsArgumentException(int length)
        {
            // Arrange
            var hostChallenge = new byte[length];

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => 
                new InitializeUpdateCommand(0x01, 0x00, hostChallenge));
            Assert.Contains("Host challenge must be 8 bytes", ex.Message);
        }

        [Fact]
        public void GetApdu_ReturnsCorrectApduStructure()
        {
            // Arrange
            var keyVersion = (byte)0x01;
            var keyId = (byte)0x00;
            var hostChallenge = Convert.FromHexString("0102030405060708");
            var command = new InitializeUpdateCommand(keyVersion, keyId, hostChallenge);

            // Act
            var apdu = command.GetApdu();

            // Assert
            Assert.Equal(0x80, apdu[0]); // CLA - GlobalPlatform
            Assert.Equal(0x50, apdu[1]); // INS - INITIALIZE UPDATE
            Assert.Equal(keyVersion, apdu[2]); // P1 - Key Version
            Assert.Equal(keyId, apdu[3]); // P2 - Key Identifier
            Assert.Equal(0x08, apdu[4]); // Lc - Data length
            Assert.Equal(hostChallenge, apdu[5..13]); // Data - Host Challenge
            Assert.Equal(0x00, apdu[13]); // Le - Expected response length
        }

        [Fact]
        public void GetApdu_WithDifferentKeyVersions_SetsP1Correctly()
        {
            // Arrange
            var testCases = new byte[] { 0x00, 0x01, 0x7F, 0xFF };
            var hostChallenge = Convert.FromHexString("0102030405060708");

            foreach (var keyVersion in testCases)
            {
                // Act
                var command = new InitializeUpdateCommand(keyVersion, 0x00, hostChallenge);
                var apdu = command.GetApdu();

                // Assert
                Assert.Equal(keyVersion, apdu[2]); // P1
            }
        }

        [Fact]
        public void GetApdu_WithDifferentKeyIds_SetsP2Correctly()
        {
            // Arrange
            var testCases = new byte[] { 0x00, 0x01, 0x02, 0xFF };
            var hostChallenge = Convert.FromHexString("0102030405060708");

            foreach (var keyId in testCases)
            {
                // Act
                var command = new InitializeUpdateCommand(0x01, keyId, hostChallenge);
                var apdu = command.GetApdu();

                // Assert
                Assert.Equal(keyId, apdu[3]); // P2
            }
        }

        [Fact]
        public void GetApdu_ForScp03_UsesKeyId00()
        {
            // According to SCP03 spec, key identifier must be 0x00
            // Arrange
            var hostChallenge = Convert.FromHexString("0102030405060708");
            var command = new InitializeUpdateCommand(0x01, 0x00, hostChallenge);

            // Act
            var apdu = command.GetApdu();

            // Assert
            Assert.Equal(0x00, apdu[3]); // P2 must be 0x00 for SCP03
        }

        [Fact]
        public void GetApdu_AlwaysReturnsNewArray()
        {
            // Arrange
            var command = new InitializeUpdateCommand(0x01, 0x00, new byte[8]);

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
            var hostChallenge = Convert.FromHexString("0102030405060708");
            var command = new InitializeUpdateCommand(0x01, 0x00, hostChallenge);

            // Act
            var result = command.ToString();

            // Assert
            Assert.Contains("INITIALIZE UPDATE", result);
            Assert.Contains("0102030405060708", result); // Host challenge
        }

        [Fact]
        public void Command_FollowsGlobalPlatformSpecification()
        {
            // This test documents that the command follows GlobalPlatform Card Specification
            // INITIALIZE UPDATE command format:
            // CLA: 0x80 (GlobalPlatform)
            // INS: 0x50 (INITIALIZE UPDATE)
            // P1: Key Version Number
            // P2: Key Identifier (0x00 for SCP03)
            // Lc: 0x08 (8 bytes of host challenge)
            // Data: 8-byte host challenge
            // Le: 0x00 (receive all available bytes)

            var command = new InitializeUpdateCommand(0x01, 0x00, new byte[8]);
            var apdu = command.GetApdu();

            Assert.Equal(14, apdu.Length); // 5 header + 8 data + 1 Le
            Assert.Equal(0x80, apdu[0]); // CLA
            Assert.Equal(0x50, apdu[1]); // INS
            Assert.Equal(0x08, apdu[4]); // Lc
            Assert.Equal(0x00, apdu[13]); // Le
        }
    }
}