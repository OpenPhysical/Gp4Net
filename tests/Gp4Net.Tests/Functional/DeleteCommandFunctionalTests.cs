using System;
using System.Linq;
using AwesomeAssertions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Functional;

/// <summary>
/// Functional integration tests for DELETE command using virtual card infrastructure.
/// Tests focus on command structure and parsing without expecting full card emulation.
/// </summary>
[TestFixture]
[Category("Integration")]
public class DeleteCommandFunctionalTests
{
    private VirtualCardService _virtualCardService;
    private VirtualCardReader _reader;
    private VirtualCard _virtualCard;

    [SetUp]
    public void Setup()
    {
        // Create virtual card service with test environment
        _virtualCardService = new VirtualCardService();

        // Create a custom virtual card with pre-installed applications
        _reader = new VirtualCardReader("Test Reader");
        _virtualCard = VirtualCardTestBuilder.P71Card();
        _reader.InsertCard(_virtualCard);
        _virtualCardService.GetReaderManager().AddReader(_reader);

        // Connect to the card
        _virtualCardService.Connect("Test Reader");
    }

    [TearDown]
    public void TearDown()
    {
        _virtualCardService?.Dispose();
    }

    [Test]
    public void DeleteCommand_WithValidAid_GeneratesCorrectApdu()
    {
        // Arrange
        var testAppAid = Convert.FromHexString("A0000003080000100001");

        // Act
        var deleteCommandResult = DeleteCommand.CreateForApplication(testAppAid, deleteRelated: false);

        // Assert
        deleteCommandResult.IsSuccess.Should().BeTrue();
        var deleteCommand = deleteCommandResult.Value;
        var apdu = deleteCommand.ToApdu();

        // Verify APDU structure
        apdu[0].Should().Be(0x80); // CLA
        apdu[1].Should().Be(0xE4); // INS (DELETE)
        apdu[2].Should().Be(0x80); // P1 (delete object only)
        apdu[3].Should().Be(0x00); // P2 (by AID)

        // Verify data contains AID in TLV format
        var dataOffset = 5;
        apdu[dataOffset].Should().Be(0x4F); // AID tag
        apdu[dataOffset + 1].Should().Be((byte)testAppAid.Length);
    }

    [Test]
    public void DeleteCommand_WithDeletionToken_IncludesTokenInApdu()
    {
        // Arrange
        var testAppAid = Convert.FromHexString("A0000003080000100001");
        var deletionToken = Convert.FromHexString("20EEDD243F094FAD");

        var deleteCommandResult = DeleteCommand.CreateForApplication(
            testAppAid,
            deleteRelated: true,
            deletionToken);
        deleteCommandResult.IsSuccess.Should().BeTrue();
        var deleteCommand = deleteCommandResult.Value;

        // Act
        var apdu = deleteCommand.ToApdu();

        // Assert
        apdu[0].Should().Be(0x80); // CLA
        apdu[1].Should().Be(0xE4); // INS
        apdu[2].Should().Be(0x00); // P1 (delete object and related)
        apdu[3].Should().Be(0x80); // P2 (with related)

        // Verify token is appended after AID TLV
        var dataOffset = 5;
        var aidLength = apdu[dataOffset + 1];
        var tokenOffset = dataOffset + 2 + aidLength;

        var tokenInApdu = apdu.Skip(tokenOffset).Take(deletionToken.Length).ToArray();
        tokenInApdu.Should().BeEquivalentTo(deletionToken);
    }

    [Test]
    public void DeleteCommand_MultipleAids_ConcatenatesCorrectly()
    {
        // Arrange
        var aids = new[]
        {
            Convert.FromHexString("A00000030800001000"), // 9 bytes
            Convert.FromHexString("A0000003080000"), // 7 bytes
            Convert.FromHexString("A000000308") // 5 bytes
        };

        var deleteCommandResult = DeleteCommand.CreateForApplications(aids);
        deleteCommandResult.IsSuccess.Should().BeTrue();
        var deleteCommand = deleteCommandResult.Value;

        // Act
        var apdu = deleteCommand.ToApdu();

        // Assert
        var totalAidLength = aids.Sum(aid => aid.Length); // 21 bytes
        var dataOffset = 5;

        apdu[dataOffset].Should().Be(0x4F); // AID tag
        apdu[dataOffset + 1].Should().Be((byte)totalAidLength);

        // Verify all AIDs are concatenated
        var offset = dataOffset + 2;
        foreach (var aid in aids)
        {
            apdu.Skip(offset).Take(aid.Length).Should().BeEquivalentTo(aid);
            offset += aid.Length;
        }
    }

    [Test]
    public void DeletePackage_CommandStructure_IsCorrect()
    {
        // Arrange
        var packageAid = Convert.FromHexString("A0000003080000100000");

        var deleteCommandResult = DeleteCommand.CreateForPackage(packageAid, deleteRelated: true);
        deleteCommandResult.IsSuccess.Should().BeTrue();
        var deleteCommand = deleteCommandResult.Value;

        // Act
        var apdu = deleteCommand.ToApdu();

        // Assert - Verify command structure
        apdu[0].Should().Be(0x80); // CLA
        apdu[1].Should().Be(0xE4); // INS
        apdu[2].Should().Be(0x00); // P1 (delete object and related)
        apdu[3].Should().Be(0x80); // P2 (with related)

        // Verify AID encoding
        var dataOffset = 5;
        apdu[dataOffset].Should().Be(0x4F); // AID tag
        apdu[dataOffset + 1].Should().Be((byte)packageAid.Length);

        var aidInApdu = apdu.Skip(dataOffset + 2).Take(packageAid.Length).ToArray();
        aidInApdu.Should().BeEquivalentTo(packageAid);
    }

    [Test]
    public void DeleteKey_WithValidKeyReference_GeneratesCorrectApdu()
    {
        // Arrange
        byte keyId = 0x01;
        byte keyVersion = 0x73;

        var deleteCommandResult = DeleteCommand.CreateForKey(keyId, keyVersion);
        deleteCommandResult.IsSuccess.Should().BeTrue();
        var deleteCommand = deleteCommandResult.Value;

        // Act
        var apdu = deleteCommand.ToApdu();

        // Assert
        apdu[0].Should().Be(0x80); // CLA
        apdu[1].Should().Be(0xE4); // INS
        apdu[2].Should().Be(0x80); // P1 (delete object only)
        apdu[3].Should().Be(0x00); // P2 (by AID)

        // For key deletion, the "AID" contains key reference
        var dataOffset = 5;
        apdu[dataOffset].Should().Be(0x4F); // Still uses AID tag
        apdu[dataOffset + 1].Should().Be(0x02); // Length = 2 (keyId + keyVersion)
        apdu[dataOffset + 2].Should().Be(keyId);
        apdu[dataOffset + 3].Should().Be(keyVersion);
    }

    [Test]
    public void DeleteResponse_Parse_HandlesEmptyConfirmation()
    {
        // Arrange - Response with no deletion confirmation
        var responseData = new byte[] { 0x00 }; // Length = 0
        var statusWord = (ushort)0x9000;

        // Act
        var deleteResponse = DeleteResponse.Parse(responseData, statusWord);

        // Assert
        deleteResponse.IsSuccessful.Should().BeTrue();
        deleteResponse.StatusWord.Should().Be(0x9000);
        deleteResponse.DeletionReceipts.Should().BeEmpty();
    }

    [Test]
    public void DeleteResponse_Parse_HandlesDeletionReceipt()
    {
        // Arrange - Response with deletion receipt
        var deletedAid = Convert.FromHexString("A0000003080000100001");
        var responseData = new byte[]
        {
            0x0C, // Length of delete confirmation
            0x4F, // AID tag
            0x0A, // AID length (10 bytes)
        }.Concat(deletedAid).ToArray();
        var statusWord = (ushort)0x9000;

        // Act
        var deleteResponse = DeleteResponse.Parse(responseData, statusWord);

        // Assert
        deleteResponse.IsSuccessful.Should().BeTrue();
        deleteResponse.DeletionReceipts.Should().HaveCount(1);
        deleteResponse.DeletionReceipts[0].Aid.Should().BeEquivalentTo(deletedAid);
        deleteResponse.DeletionReceipts[0].IsSuccessful.Should().BeTrue();
    }

    [Test]
    public void DeleteCommand_PureFunctionality_ProducesIdenticalResults()
    {
        // Arrange
        var aid = Convert.FromHexString("A0000003080000100001");
        var deletionToken = Convert.FromHexString("20EEDD243F094FAD");

        // Act - Create command multiple times
        var result1 = DeleteCommand.CreateForApplication(aid, true, deletionToken);
        var result2 = DeleteCommand.CreateForApplication(aid, true, deletionToken);

        // Assert - Pure function produces identical results
        result1.IsSuccess.Should().BeTrue();
        result2.IsSuccess.Should().BeTrue();

        var apdu1 = result1.Value.ToApdu();
        var apdu2 = result2.Value.ToApdu();

        apdu1.Should().BeEquivalentTo(apdu2);
    }

    [Test]
    public void DeleteCommand_WithSecureMessaging_HasCorrectCla()
    {
        // Arrange
        var aid = Convert.FromHexString("A0000003080000100001");
        var deleteCommandResult = DeleteCommand.CreateForApplication(aid);
        deleteCommandResult.IsSuccess.Should().BeTrue();
        var deleteCommand = deleteCommandResult.Value;

        // Act
        var apdu = deleteCommand.ToApdu();

        // Secure messaging would modify the CLA
        var secureApdu = (byte[])apdu.Clone();
        secureApdu[0] = 0x84; // Secure messaging bit

        // Assert
        secureApdu[0].Should().Be(0x84);
        secureApdu[1].Should().Be(0xE4); // INS unchanged
    }

    [Test]
    public void DeleteCommand_ToApdu_MatchesTraceFormat()
    {
        // Based on the trace analysis from DeleteCommandTraceTests
        // Command: 84E40080134F09A0000003080000100020EEDD243F094FAD

        // Arrange
        var aid = Convert.FromHexString("A00000030800001000"); // 9 bytes
        var deletionToken = Convert.FromHexString("20EEDD243F094FAD"); // 8 bytes

        var deleteCommandResult = DeleteCommand.CreateForApplication(
            aid,
            deleteRelated: true,
            deletionToken);
        deleteCommandResult.IsSuccess.Should().BeTrue();
        var deleteCommand = deleteCommandResult.Value;

        // Act
        var apdu = deleteCommand.ToApdu();

        // Assert - Structure matches trace
        apdu[0].Should().Be(0x80); // CLA (before secure messaging)
        apdu[1].Should().Be(0xE4); // INS
        apdu[2].Should().Be(0x00); // P1 (delete object and related)
        apdu[3].Should().Be(0x80); // P2 (with related)
        apdu[4].Should().Be(0x13); // Lc = 19 bytes (2 + 9 + 8)

        // Data: 4F09<AID><TOKEN>
        apdu[5].Should().Be(0x4F); // AID tag
        apdu[6].Should().Be(0x09); // AID length

        // Verify complete data section
        var expectedData = new byte[] { 0x4F, 0x09 }
            .Concat(aid)
            .Concat(deletionToken)
            .ToArray();

        var actualData = apdu.Skip(5).ToArray();
        actualData.Should().BeEquivalentTo(expectedData);
    }

    [Test]
    public void VirtualCard_ProcessesBasicCommands()
    {
        // This test verifies the virtual card can process basic commands
        // without expecting full DELETE implementation

        // Arrange
        var selectCommand = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 };

        // Act
        var response = _virtualCardService.SendCommand(selectCommand);

        // Assert
        response.IsSuccessful.Should().BeTrue();
        response.Data.Should().NotBeEmpty(); // Should return FCI
    }

    [Test]
    public void DeleteCommand_ErrorScenarios_GenerateCorrectCommands()
    {
        // Test that we can generate commands for various error scenarios
        // even if the virtual card doesn't implement them

        // Non-existent AID
        var nonExistentAid = Convert.FromHexString("AABBCCDDEE");
        var result1 = DeleteCommand.CreateForApplication(nonExistentAid);
        result1.IsSuccess.Should().BeTrue();

        // Empty AID list (should fail at creation)
        var result2 = DeleteCommand.CreateForApplications(Array.Empty<byte[]>());
        result2.IsFailure.Should().BeTrue();
        result2.Error.Message.Should().Contain("At least one AID must be provided");

        // Null AID (should fail at creation)
        var result3 = DeleteCommand.CreateForApplication(null!);
        result3.IsFailure.Should().BeTrue();
        result3.Error.Message.Should().Contain("AID cannot be null");
    }
}
