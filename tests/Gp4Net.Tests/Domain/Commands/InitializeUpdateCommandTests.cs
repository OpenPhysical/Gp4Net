using System;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands
{
    [TestFixture]
    public class InitializeUpdateCommandTests
    {
        [Test]
        public void Create_WithValidParameters_ReturnsSuccessResult()
        {
            byte keyVersion = 0x01;
            byte keyId = 0x00;
            var hostChallenge = Convert.FromHexString("0102030405060708");

            var result = InitializeUpdateCommand.Create(keyVersion, keyId, hostChallenge);

            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.KeyVersion, Is.EqualTo(keyVersion));
            Assert.That(result.Value.KeyIdentifier, Is.EqualTo(keyId));
            Assert.That(result.Value.HostChallenge, Is.EqualTo(hostChallenge));
        }

        [Test]
        [TestCase(0)]
        [TestCase(7)]
        [TestCase(9)]
        [TestCase(16)]
        public void Create_WithInvalidHostChallengeLength_ReturnsFailureResult(int length)
        {
            var hostChallenge = new byte[length];

            var result = InitializeUpdateCommand.Create(0x01, 0x00, hostChallenge);

            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Message, Does.Contain("Host challenge must be 8 bytes"));
            Assert.That(result.Error.Message, Does.Contain($"got {length}"));
        }

        [Test]
        public void GetApdu_ReturnsCorrectApduStructure()
        {
            var keyVersion = (byte)0x01;
            var keyId = (byte)0x00;
            var hostChallenge = Convert.FromHexString("0102030405060708");
            var result = InitializeUpdateCommand.Create(keyVersion, keyId, hostChallenge);
            var command = result.Value;

            var apdu = command.GetApdu();

            Assert.That(apdu[0], Is.EqualTo(0x80)); // CLA - GlobalPlatform
            Assert.That(apdu[1], Is.EqualTo(0x50)); // INS - INITIALIZE UPDATE
            Assert.That(apdu[2], Is.EqualTo(keyVersion)); // P1 - Key Version
            Assert.That(apdu[3], Is.EqualTo(keyId)); // P2 - Key Identifier
            Assert.That(apdu[4], Is.EqualTo(0x08)); // Lc - Data length
            Assert.That(apdu[5..13], Is.EqualTo(hostChallenge)); // Data - Host Challenge
            Assert.That(apdu[13], Is.EqualTo(28)); // Le - Expected response length
        }

        [Test]
        public void GetApdu_WithDifferentKeyVersions_SetsP1Correctly()
        {
            var testCases = new byte[] { 0x00, 0x01, 0x7F, 0xFF };
            var hostChallenge = Convert.FromHexString("0102030405060708");

            foreach (var keyVersion in testCases)
            {
                var result = InitializeUpdateCommand.Create(keyVersion, 0x00, hostChallenge);
                var command = result.Value;
                var apdu = command.GetApdu();

                Assert.That(apdu[2], Is.EqualTo(keyVersion)); // P1
            }
        }

        [Test]
        public void GetApdu_WithDifferentKeyIds_SetsP2Correctly()
        {
            var testCases = new byte[] { 0x00, 0x01, 0x02, 0xFF };
            var hostChallenge = Convert.FromHexString("0102030405060708");

            foreach (var keyId in testCases)
            {
                var result = InitializeUpdateCommand.Create(0x01, keyId, hostChallenge);
                var command = result.Value;
                var apdu = command.GetApdu();

                Assert.That(apdu[3], Is.EqualTo(keyId)); // P2
            }
        }

        [Test]
        public void GetApdu_ForScp03_UsesKeyId00()
        {
            // According to SCP03 spec, key identifier must be 0x00
            var hostChallenge = Convert.FromHexString("0102030405060708");
            var result = InitializeUpdateCommand.Create(0x01, 0x00, hostChallenge);
            var command = result.Value;

            var apdu = command.GetApdu();

            Assert.That(apdu[3], Is.EqualTo(0x00)); // P2 must be 0x00 for SCP03
        }

        [Test]
        public void GetApdu_AlwaysReturnsNewArray()
        {
            var result = InitializeUpdateCommand.Create(0x01, 0x00, new byte[8]);
            var command = result.Value;

            var apdu1 = command.GetApdu();
            var apdu2 = command.GetApdu();

            Assert.That(apdu1, Is.Not.SameAs(apdu2)); // Should be different array instances
            Assert.That(apdu2, Is.EqualTo(apdu1)); // But with same content
        }

        [Test]
        public void ToString_ReturnsDescriptiveString()
        {
            var hostChallenge = Convert.FromHexString("0102030405060708");
            var result = InitializeUpdateCommand.Create(0x01, 0x00, hostChallenge);
            var command = result.Value;

            var resultString = command.ToString();

            Assert.That(resultString, Is.EqualTo("INITIALIZE UPDATE"));
        }

        [Test]
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
            // Le: 0x1C (28 bytes expected response)

            var result = InitializeUpdateCommand.Create(0x01, 0x00, new byte[8]);
            var command = result.Value;
            var apdu = command.GetApdu();

            Assert.That(apdu.Length, Is.EqualTo(14)); // 5 header + 8 data + 1 Le
            Assert.That(apdu[0], Is.EqualTo(0x80)); // CLA
            Assert.That(apdu[1], Is.EqualTo(0x50)); // INS
            Assert.That(apdu[4], Is.EqualTo(0x08)); // Lc
            Assert.That(apdu[13], Is.EqualTo(28)); // Le (28 bytes expected)
        }

        [Test]
        public void Properties_UseConstantsCorrectly()
        {
            var result = InitializeUpdateCommand.Create(0x01, 0x00, new byte[8]);
            var command = result.Value;

            Assert.That(command.Cla, Is.EqualTo(InitializeUpdateCommand.ClassByte));
            Assert.That(command.Ins, Is.EqualTo(InitializeUpdateCommand.InstructionByte));
            Assert.That(InitializeUpdateCommand.ClassByte, Is.EqualTo(0x80));
            Assert.That(InitializeUpdateCommand.InstructionByte, Is.EqualTo(0x50));
        }

        [Test]
        public void HostChallenge_NeverReturnsNull()
        {
            var originalChallenge = new byte[8];
            var result = InitializeUpdateCommand.Create(0x01, 0x00, originalChallenge);
            var command = result.Value;

            Assert.That(command.HostChallenge, Is.Not.Null);
            Assert.That(command.HostChallenge.Length, Is.EqualTo(8));
        }

        [Test]
        public void HostChallenge_IsImmutable()
        {
            var originalChallenge = Convert.FromHexString("0102030405060708");
            var result = InitializeUpdateCommand.Create(0x01, 0x00, originalChallenge);
            var command = result.Value;

            // Modify the original array
            originalChallenge[0] = 0xFF;

            // Command's host challenge should not be affected
            Assert.That(command.HostChallenge[0], Is.EqualTo(0x01));
        }
    }
}