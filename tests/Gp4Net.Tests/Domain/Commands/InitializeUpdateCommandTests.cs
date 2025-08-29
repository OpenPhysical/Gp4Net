using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

[TestFixture]
[Category("Unit")]
public class InitializeUpdateCommandTests
{
    [Test]
    public void Create_WithValidParameters_ReturnsSuccessResult()
    {
        byte keyVersion = 0x01;
        byte keyId = 0x00;
        byte[] hostChallenge = Convert.FromHexString("0102030405060708");

        Result<InitializeUpdateCommand, SmartCardError> result = InitializeUpdateCommand.Create(keyVersion, keyId, hostChallenge);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.KeyVersion.Should().Be(keyVersion);
        _ = result.Value.KeyIdentifier.Should().Be(keyId);
        _ = result.Value.HostChallenge.Should().BeEquivalentTo(hostChallenge);
    }

    [Test]
    [TestCase(0)]
    [TestCase(7)]
    [TestCase(9)]
    [TestCase(16)]
    public void Create_WithInvalidHostChallengeLength_ReturnsFailureResult(int length)
    {
        byte[] hostChallenge = new byte[length];

        Result<InitializeUpdateCommand, SmartCardError> result = InitializeUpdateCommand.Create(0x01, 0x00, hostChallenge);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Host challenge must be 8 bytes");
        _ = result.Error.Message.Should().Contain($"got {length}");
    }

    [Test]
    public void GetApdu_ReturnsCorrectApduStructure()
    {
        byte keyVersion = (byte)0x01;
        byte keyId = (byte)0x00;
        byte[] hostChallenge = Convert.FromHexString("0102030405060708");
        Result<InitializeUpdateCommand, SmartCardError> result = InitializeUpdateCommand.Create(keyVersion, keyId, hostChallenge);
        InitializeUpdateCommand? command = result.Value;

        byte[]? apdu = ApduBuilder.BuildApdu(command);

        _ = apdu[0].Should().Be(0x80); // CLA - GlobalPlatform
        _ = apdu[1].Should().Be(0x50); // INS - INITIALIZE UPDATE
        _ = apdu[2].Should().Be(keyVersion); // P1 - Key Version
        _ = apdu[3].Should().Be(keyId); // P2 - Key Identifier
        _ = apdu[4].Should().Be(0x08); // Lc - Data length
        _ = apdu[5..13].Should().BeEquivalentTo(hostChallenge); // Data - Host Challenge
        _ = apdu[13].Should().Be(28); // Le - Expected response length
    }

    [Test]
    public void GetApdu_WithDifferentKeyVersions_SetsP1Correctly()
    {
        byte[] testCases = [0x00, 0x01, 0x7F, 0xFF];
        byte[] hostChallenge = Convert.FromHexString("0102030405060708");

        foreach (byte keyVersion in testCases)
        {
            Result<InitializeUpdateCommand, SmartCardError> result = InitializeUpdateCommand.Create(keyVersion, 0x00, hostChallenge);
            InitializeUpdateCommand? command = result.Value;
            byte[]? apdu = ApduBuilder.BuildApdu(command);

            _ = apdu[2].Should().Be(keyVersion); // P1
        }
    }

    [Test]
    public void GetApdu_WithDifferentKeyIds_SetsP2Correctly()
    {
        byte[] testCases = [0x00, 0x01, 0x02, 0xFF];
        byte[] hostChallenge = Convert.FromHexString("0102030405060708");

        foreach (byte keyId in testCases)
        {
            Result<InitializeUpdateCommand, SmartCardError> result = InitializeUpdateCommand.Create(0x01, keyId, hostChallenge);
            InitializeUpdateCommand? command = result.Value;
            byte[]? apdu = ApduBuilder.BuildApdu(command);

            _ = apdu[3].Should().Be(keyId); // P2
        }
    }

    [Test]
    public void GetApdu_ForScp03_UsesKeyId00()
    {
        // According to SCP03 spec, key identifier must be 0x00
        byte[] hostChallenge = Convert.FromHexString("0102030405060708");
        Result<InitializeUpdateCommand, SmartCardError> result = InitializeUpdateCommand.Create(0x01, 0x00, hostChallenge);
        InitializeUpdateCommand? command = result.Value;

        byte[]? apdu = ApduBuilder.BuildApdu(command);

        _ = apdu[3].Should().Be(0x00); // P2 must be 0x00 for SCP03
    }

    [Test]
    public void GetApdu_AlwaysReturnsNewArray()
    {
        Result<InitializeUpdateCommand, SmartCardError> result = InitializeUpdateCommand.Create(0x01, 0x00, new byte[8]);
        InitializeUpdateCommand? command = result.Value;

        byte[]? apdu1 = ApduBuilder.BuildApdu(command);
        byte[]? apdu2 = ApduBuilder.BuildApdu(command);

        _ = apdu1.Should().NotBeSameAs(apdu2); // Should be different array instances
        _ = apdu2.Should().BeEquivalentTo(apdu1); // But with same content
    }

    [Test]
    public void ToString_ReturnsDescriptiveString()
    {
        byte[] hostChallenge = Convert.FromHexString("0102030405060708");
        Result<InitializeUpdateCommand, SmartCardError> result = InitializeUpdateCommand.Create(0x01, 0x00, hostChallenge);
        InitializeUpdateCommand? command = result.Value;

        string? resultString = command.ToString();

        _ = resultString.Should().Be("INITIALIZE UPDATE");
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

        Result<InitializeUpdateCommand, SmartCardError> result = InitializeUpdateCommand.Create(0x01, 0x00, new byte[8]);
        InitializeUpdateCommand? command = result.Value;
        byte[]? apdu = ApduBuilder.BuildApdu(command);

        _ = apdu.Length.Should().Be(14); // 5 header + 8 data + 1 Le
        _ = apdu[0].Should().Be(0x80); // CLA
        _ = apdu[1].Should().Be(0x50); // INS
        _ = apdu[4].Should().Be(0x08); // Lc
        _ = apdu[13].Should().Be(28); // Le (28 bytes expected)
    }

    [Test]
    public void Properties_UseConstantsCorrectly()
    {
        Result<InitializeUpdateCommand, SmartCardError> result = InitializeUpdateCommand.Create(0x01, 0x00, new byte[8]);
        InitializeUpdateCommand? command = result.Value;

        _ = command.Cla.Should().Be(InitializeUpdateCommand.ClassByte);
        _ = command.Ins.Should().Be(InitializeUpdateCommand.InstructionByte);
        _ = InitializeUpdateCommand.ClassByte.Should().Be(0x80);
        _ = InitializeUpdateCommand.InstructionByte.Should().Be(0x50);
    }

    [Test]
    public void HostChallenge_NeverReturnsNull()
    {
        byte[] originalChallenge = new byte[8];
        Result<InitializeUpdateCommand, SmartCardError> result = InitializeUpdateCommand.Create(0x01, 0x00, originalChallenge);
        InitializeUpdateCommand? command = result.Value;

        _ = command.HostChallenge.Should().NotBeNull();
        _ = command.HostChallenge.Length.Should().Be(8);
    }

    [Test]
    public void HostChallenge_IsImmutable()
    {
        byte[] originalChallenge = Convert.FromHexString("0102030405060708");
        Result<InitializeUpdateCommand, SmartCardError> result = InitializeUpdateCommand.Create(0x01, 0x00, originalChallenge);
        InitializeUpdateCommand? command = result.Value;

        // Modify the original array
        originalChallenge[0] = 0xFF;

        // Command's host challenge should not be affected
        _ = command.HostChallenge[0].Should().Be(0x01);
    }
}
