using System;
using AwesomeAssertions;
using Gp4Net.Domain.Commands;
using NUnit.Framework;
using CSharpFunctionalExtensions;

namespace Gp4Net.Tests.Domain.Commands;

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

        result.IsSuccess.Should().BeTrue();
        result.Value.KeyVersion.Should().Be(keyVersion);
        result.Value.KeyIdentifier.Should().Be(keyId);
        result.Value.HostChallenge.Should().BeEquivalentTo(hostChallenge);
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

        result.IsFailure.Should().BeTrue();
        result.Error.Message.Should().Contain("Host challenge must be 8 bytes");
        result.Error.Message.Should().Contain($"got {length}");
    }

    [Test]
    public void GetApdu_ReturnsCorrectApduStructure()
    {
        var keyVersion = (byte)0x01;
        var keyId = (byte)0x00;
        var hostChallenge = Convert.FromHexString("0102030405060708");
        var result = InitializeUpdateCommand.Create(keyVersion, keyId, hostChallenge);
        var command = result.Value;

#pragma warning disable CS0618 // Testing APDU format generation is core to this test
        var apdu = command.GetApdu();
#pragma warning restore CS0618

        apdu[0].Should().Be(0x80); // CLA - GlobalPlatform
        apdu[1].Should().Be(0x50); // INS - INITIALIZE UPDATE
        apdu[2].Should().Be(keyVersion); // P1 - Key Version
        apdu[3].Should().Be(keyId); // P2 - Key Identifier
        apdu[4].Should().Be(0x08); // Lc - Data length
        apdu[5..13].Should().BeEquivalentTo(hostChallenge); // Data - Host Challenge
        apdu[13].Should().Be(28); // Le - Expected response length
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
#pragma warning disable CS0618 // Testing APDU format generation is core to this test
            var apdu = command.GetApdu();
#pragma warning restore CS0618

            apdu[2].Should().Be(keyVersion); // P1
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
#pragma warning disable CS0618 // Testing APDU format generation is core to this test
            var apdu = command.GetApdu();
#pragma warning restore CS0618

            apdu[3].Should().Be(keyId); // P2
        }
    }

    [Test]
    public void GetApdu_ForScp03_UsesKeyId00()
    {
        // According to SCP03 spec, key identifier must be 0x00
        var hostChallenge = Convert.FromHexString("0102030405060708");
        var result = InitializeUpdateCommand.Create(0x01, 0x00, hostChallenge);
        var command = result.Value;

#pragma warning disable CS0618 // Testing APDU format generation is core to this test
        var apdu = command.GetApdu();
#pragma warning restore CS0618

        apdu[3].Should().Be(0x00); // P2 must be 0x00 for SCP03
    }

    [Test]
    public void GetApdu_AlwaysReturnsNewArray()
    {
        var result = InitializeUpdateCommand.Create(0x01, 0x00, new byte[8]);
        var command = result.Value;

#pragma warning disable CS0618 // Testing APDU format generation is core to this test
        var apdu1 = command.GetApdu();
        var apdu2 = command.GetApdu();
#pragma warning restore CS0618

        apdu1.Should().NotBeSameAs(apdu2); // Should be different array instances
        apdu2.Should().BeEquivalentTo(apdu1); // But with same content
    }

    [Test]
    public void ToString_ReturnsDescriptiveString()
    {
        var hostChallenge = Convert.FromHexString("0102030405060708");
        var result = InitializeUpdateCommand.Create(0x01, 0x00, hostChallenge);
        var command = result.Value;

        var resultString = command.ToString();

        resultString.Should().Be("INITIALIZE UPDATE");
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
#pragma warning disable CS0618 // Testing APDU format generation is core to this test
        var apdu = command.GetApdu();
#pragma warning restore CS0618

        apdu.Length.Should().Be(14); // 5 header + 8 data + 1 Le
        apdu[0].Should().Be(0x80); // CLA
        apdu[1].Should().Be(0x50); // INS
        apdu[4].Should().Be(0x08); // Lc
        apdu[13].Should().Be(28); // Le (28 bytes expected)
    }

    [Test]
    public void Properties_UseConstantsCorrectly()
    {
        var result = InitializeUpdateCommand.Create(0x01, 0x00, new byte[8]);
        var command = result.Value;

        command.Cla.Should().Be(InitializeUpdateCommand.ClassByte);
        command.Ins.Should().Be(InitializeUpdateCommand.InstructionByte);
        InitializeUpdateCommand.ClassByte.Should().Be(0x80);
        InitializeUpdateCommand.InstructionByte.Should().Be(0x50);
    }

    [Test]
    public void HostChallenge_NeverReturnsNull()
    {
        var originalChallenge = new byte[8];
        var result = InitializeUpdateCommand.Create(0x01, 0x00, originalChallenge);
        var command = result.Value;

        command.HostChallenge.Should().NotBeNull();
        command.HostChallenge.Length.Should().Be(8);
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
        command.HostChallenge[0].Should().Be(0x01);
    }
}
