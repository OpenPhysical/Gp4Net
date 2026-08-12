using System;
using System.Collections.Generic;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Tests to validate the fixes for all identified specification compliance issues.
/// </summary>
[TestFixture]
[Category("Integration")]
[Category("Compliance")]
public class SpecificationComplianceValidationTests
{
    [Test]
    public void DeleteTokenCalculator_UsesFunctionalErrorHandling()
    {
        // Arrange: Test the functional Result<T> pattern that replaced try-catch
        byte[] validKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        byte[] validAid = Convert.FromHexString("A0000003080000100001");

        // Act & Assert: Test various validation scenarios

        // Invalid key length
        byte[] invalidKey = new byte[15];
        Result<byte[], SmartCardError> result1 = CryptoOperations.Keys.ComputeDeleteToken(
            invalidKey,
            0x00,
            0x80,
            validAid,
            Maybe<byte[]>.None
        );

        _ = result1
            .IsFailure.Should()
            .BeTrue("Invalid key length should return Result.Failure, not throw exception");
        _ = result1
            .Error.Message.Should()
            .Contain("Delete Token MAC key must be 16, 24, or 32 bytes");

        // Empty AID
        byte[] emptyAid = [];
        Result<byte[], SmartCardError> result2 = CryptoOperations.Keys.ComputeDeleteToken(
            validKey,
            0x00,
            0x80,
            emptyAid,
            Maybe<byte[]>.None
        );

        _ = result2
            .IsFailure.Should()
            .BeTrue("Empty AID should return Result.Failure, not throw exception");
        _ = result2.Error.Message.Should().Contain("AID cannot be empty");

        // AID too short
        byte[] shortAid = new byte[4]; // Must be 5-16 bytes
        Result<byte[], SmartCardError> result3 = CryptoOperations.Keys.ComputeDeleteToken(
            validKey,
            0x00,
            0x80,
            shortAid,
            Maybe<byte[]>.None
        );

        _ = result3
            .IsFailure.Should()
            .BeTrue("Short AID should return Result.Failure, not throw exception");
        _ = result3.Error.Message.Should().Contain("AID length must be 5-16 bytes");

        // Valid case
        Result<byte[], SmartCardError> result4 = CryptoOperations.Keys.ComputeDeleteToken(
            validKey,
            0x00,
            0x80,
            validAid,
            Maybe<byte[]>.None
        );

        _ = result4.IsSuccess.Should().BeTrue("Valid parameters should succeed");
        _ = result4.Value.Length.Should().Be(16, "AES-CMAC should produce 16-byte token");
    }

    [Test]
    public void DeleteCommand_TokenFormat_MatchesTraceStructure()
    {
        // Arrange: AID taken from the real DELETE in
        // TestData/Traces/Raw/install_uninstall.log:
        //   84E40080 13 4F09A00000030800001000 20EEDD243F094FAD
        // That capture carries no Delete Token. Its CLA is '84', so the trailing
        // eight bytes are the SCP02 C-MAC over a data field of 4F || len || AID.
        // The token below is therefore synthetic, exercising the Table 11-23
        // encoding rather than reproducing captured bytes.
        byte[] aid = Convert.FromHexString("A00000030800001000");
        byte[] expectedToken = Convert.FromHexString("7547C55C046E221C");

        // Act: Create DELETE command with same parameters
        Result<DeleteCommand, SmartCardError> deleteCommandResult =
            DeleteCommand.CreateForApplication(
                aid,
                deleteRelated: true,
                deletionToken: expectedToken
            );

        _ = deleteCommandResult.IsSuccess.Should().BeTrue("DELETE command creation should succeed");
        var deleteCommand = deleteCommandResult.Value;

        // Get APDU bytes
        byte[] apduBytes = deleteCommand.ToBytes();

        // Assert: Command should follow GP Table 11-23 format
        _ = apduBytes[0].Should().Be(0x80, "CLA should be 0x80 for plain command");
        _ = apduBytes[1].Should().Be(0xE4, "INS should be DELETE (0xE4)");
        _ = apduBytes[2].Should().Be(0x00, "P1 should be 0x00 (delete object and related)");
        _ = apduBytes[3].Should().Be(0x80, "P2 should be 0x80 (with related objects)");

        // Verify AID TLV structure: 4F <len> <AID>
        _ = apduBytes[5].Should().Be(0x4F, "AID tag should be 0x4F");
        _ = apduBytes[6].Should().Be((byte)aid.Length, "AID length should match");

        // GP 2.3.1 Table 11-23 lists the Delete Token as tag '9E', length 1-n, and
        // 11.2.2.3.1 requires: "The length fields for the Control Reference Template
        // for Digital Signature and the Delete Token are coded according to ASN.1
        // BER-TLV". The token is therefore a tagged data object, not raw bytes.
        int tokenTagOffset = 7 + aid.Length;
        _ = apduBytes[tokenTagOffset].Should().Be(0x9E, "Delete Token tag is '9E'");
        _ = apduBytes[tokenTagOffset + 1]
            .Should()
            .Be((byte)expectedToken.Length, "token length precedes the token value");

        byte[] tokenInApdu = [.. apduBytes.Skip(tokenTagOffset + 2).Take(expectedToken.Length),];
        _ = tokenInApdu
            .Should()
            .BeEquivalentTo(expectedToken, "the token value follows its tag and length");
    }

    [Test]
    public void InitializeUpdateResponse_VariableLengths_AllValidPerGpSpec()
    {
        // Arrange: Test the variable length support (28+ bytes) that was added

        // Factory unlock trace - 29 bytes (reference trace data)
        byte[] factoryResponse = Convert.FromHexString(
            "00002345558083204839FF020003A33DFDBFFADF57EB6A4A52CFB3E9"
        );

        // SCP02 lock trace - 28 bytes (reference trace data)
        byte[] scp02Response = Convert.FromHexString(
            "000023455580832048390102000303D2C0BAFBF0D31B42E57648A0C5"
        );

        // SCP03 trace - 32 bytes (reference trace data)
        byte[] scp03Response = Convert.FromHexString(
            "0370000000000000000001037083FA042C5C10F778148C0CAF84B0E110000002"
        );

        // Act & Assert: All reference traces should parse successfully
        Result<InitializeUpdateResponse, SmartCardError> factoryResult =
            InitializeUpdateResponse.Parse(factoryResponse);
        _ = factoryResult
            .IsSuccess.Should()
            .BeTrue("Factory unlock trace (29 bytes) should parse successfully");

        Result<InitializeUpdateResponse, SmartCardError> scp02Result =
            InitializeUpdateResponse.Parse(scp02Response);
        _ = scp02Result
            .IsSuccess.Should()
            .BeTrue("SCP02 lock trace (28 bytes) should parse successfully");

        Result<InitializeUpdateResponse, SmartCardError> scp03Result =
            InitializeUpdateResponse.Parse(scp03Response);
        _ = scp03Result
            .IsSuccess.Should()
            .BeTrue("SCP03 trace (32 bytes) should parse successfully");
    }

    [Test]
    public void InitializeUpdateResponse_InvalidLengths_ReturnsError()
    {
        byte[] tooShortResponse = new byte[27];
        Result<InitializeUpdateResponse, SmartCardError> shortResult =
            InitializeUpdateResponse.Parse(tooShortResponse);
        _ = shortResult
            .IsFailure.Should()
            .BeTrue("27-byte response should be invalid (below minimum)");
        _ = shortResult
            .Error.Message.Should()
            .Contain("INITIALIZE UPDATE response too short: 27 bytes, expected at least 28");

        byte[] scp02WithTrailingData = new byte[29];
        scp02WithTrailingData[10] = 0x01;
        scp02WithTrailingData[11] = 0x02;
        _ = InitializeUpdateResponse
            .Parse(scp02WithTrailingData)
            .IsFailure.Should()
            .BeTrue("SCP02 Table E-8 defines an exact 28-byte response");

        byte[] scp03RandomWithTrailingData = new byte[30];
        scp03RandomWithTrailingData[10] = 0x01;
        scp03RandomWithTrailingData[11] = 0x03;
        scp03RandomWithTrailingData[12] = 0x60;
        _ = InitializeUpdateResponse
            .Parse(scp03RandomWithTrailingData)
            .IsFailure.Should()
            .BeTrue("SCP03 random-challenge responses are exactly 29 bytes");

        byte[] scp03PseudoRandomWithoutCounter = new byte[29];
        scp03PseudoRandomWithoutCounter[10] = 0x01;
        scp03PseudoRandomWithoutCounter[11] = 0x03;
        scp03PseudoRandomWithoutCounter[12] = 0x70;
        _ = InitializeUpdateResponse
            .Parse(scp03PseudoRandomWithoutCounter)
            .IsFailure.Should()
            .BeTrue("SCP03 pseudo-random challenges require the 3-byte sequence counter");
    }

    /// <summary>GP Card Specification v2.3.1, Table 11-36.</summary>
    [Test]
    public void GetStatusResponse_UsesE3ContainersOnly()
    {
        byte[] aid = Convert.FromHexString("A0000000031010");
        byte[] tlvData = BuildE3ContainerResponse(aid, 0x07, [0x80, 0x00, 0x00]);

        Result<GetStatusResponse, SmartCardError> result = GetStatusResponse.Parse(tlvData);

        _ = result
            .IsSuccess.Should()
            .BeTrue("E3 container format should parse successfully per GP Table 11-36");
        _ = result.Value.Applications.Should().HaveCount(1, "Should parse one application");

        var app = result.Value.Applications[0];
        _ = app.Aid.Should().BeEquivalentTo(aid, "AID should be parsed correctly");
        _ = app.RawLifecycleState.Should().Be(0x07, "state should be preserved exactly");
        _ = app
            .Privileges.Should()
            .BeEquivalentTo(
                new byte[] { 0x80, 0x00, 0x00 },
                "Privileges should be parsed correctly"
            );
    }

    private static byte[] BuildE3ContainerResponse(
        byte[] aid,
        byte lifecycleState,
        byte[] privileges
    )
    {
        List<byte> inner = [0x4F, (byte)aid.Length];
        inner.AddRange(aid);
        inner.Add(0x9F);
        inner.Add(0x70);
        inner.Add(0x01);
        inner.Add(lifecycleState);
        if (privileges is { Length: > 0 })
        {
            inner.Add(0xC5);
            inner.Add((byte)privileges.Length);
            inner.AddRange(privileges);
        }

        List<byte> e3Container = [0xE3, (byte)inner.Count];
        e3Container.AddRange(inner);
        return [.. e3Container];
    }
}
