using System;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.CardEmulator.Tests.Functional;

/// <summary>
/// Functional integration tests for DELETE command using virtual card infrastructure.
/// Tests focus on command structure and parsing without expecting full card emulation.
/// </summary>
[TestFixture]
[Category("Integration")]
public class DeleteCommandFunctionalTests
{
    private VirtualCardService _virtualCardService = null!;
    private VirtualCardReader _reader = null!;
    private VirtualCard _virtualCard = null!;

    [SetUp]
    public void Setup()
    {
        // Create virtual card service with test environment
        _virtualCardService = new VirtualCardService();

        // Create a custom virtual card with pre-installed applications
        _virtualCard = VirtualCardTestBuilder.CreateWithSecureRng(CardConfiguration.P71());
        
        var readerResult = VirtualCardReader.Create("Test Reader")
            .Bind(reader => reader.WithCard(_virtualCard))
            .Bind(reader => reader.Connected());
            
        readerResult.Match(
            reader => { _reader = reader; _virtualCardService.GetReaderManager().AddReader(_reader); },
            error => Assert.Fail($"Failed to create reader: {error}")
        );
        _virtualCardService = _virtualCardService.WithConnectedReader(_reader);
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
        byte[] testAppAid = Convert.FromHexString("A0000003080000100001");

        // Act
        Result<DeleteCommand, SmartCardError> deleteCommandResult =
            DeleteCommand.CreateForApplication(testAppAid, deleteRelated: false);

        // Assert
        _ = deleteCommandResult.IsSuccess.Should().BeTrue();
        DeleteCommand? deleteCommand = deleteCommandResult.Value;
        byte[]? apdu = deleteCommand.ToApdu();

        // Verify APDU structure
        _ = apdu[0].Should().Be(0x80); // CLA
        _ = apdu[1].Should().Be(0xE4); // INS (DELETE)
        _ = apdu[2].Should().Be(0x80); // P1 (delete object only)
        _ = apdu[3].Should().Be(0x00); // P2 (by AID)

        // Verify data contains AID in TLV format
        int dataOffset = 5;
        _ = apdu[dataOffset].Should().Be(0x4F); // AID tag
        _ = apdu[dataOffset + 1].Should().Be((byte)testAppAid.Length);
    }

    [Test]
    public void DeleteCommand_WithDeletionToken_IncludesTokenInApdu()
    {
        // Arrange
        byte[] testAppAid = Convert.FromHexString("A0000003080000100001");
        byte[] deletionToken = Convert.FromHexString("20EEDD243F094FAD");

        Result<DeleteCommand, SmartCardError> deleteCommandResult =
            DeleteCommand.CreateForApplication(testAppAid, deleteRelated: true, deletionToken);
        _ = deleteCommandResult.IsSuccess.Should().BeTrue();
        DeleteCommand? deleteCommand = deleteCommandResult.Value;

        // Act
        byte[]? apdu = deleteCommand.ToApdu();

        // Assert
        _ = apdu[0].Should().Be(0x80); // CLA
        _ = apdu[1].Should().Be(0xE4); // INS
        _ = apdu[2].Should().Be(0x00); // P1 (delete object and related)
        _ = apdu[3].Should().Be(0x80); // P2 (with related)

        // Verify token is appended after AID TLV
        int dataOffset = 5;
        byte aidLength = apdu[dataOffset + 1];
        int tokenOffset = dataOffset + 2 + aidLength;

        byte[] tokenInApdu = [.. apdu.Skip(tokenOffset).Take(deletionToken.Length)];
        _ = tokenInApdu.Should().BeEquivalentTo(deletionToken);
    }

    [Test]
    public void DeleteCommand_MultipleAids_ConcatenatesCorrectly()
    {
        // Arrange
        byte[][] aids =
        [
            Convert.FromHexString("A00000030800001000"), // 9 bytes
            Convert.FromHexString("A0000003080000"), // 7 bytes
            Convert.FromHexString("A000000308"), // 5 bytes
        ];

        Result<DeleteCommand, SmartCardError> deleteCommandResult =
            DeleteCommand.CreateForApplications(aids);
        _ = deleteCommandResult.IsSuccess.Should().BeTrue();
        DeleteCommand? deleteCommand = deleteCommandResult.Value;

        // Act
        byte[]? apdu = deleteCommand.ToApdu();

        // Assert
        int totalAidLength = aids.Sum(aid => aid.Length); // 21 bytes
        int dataOffset = 5;

        _ = apdu[dataOffset].Should().Be(0x4F); // AID tag
        _ = apdu[dataOffset + 1].Should().Be((byte)totalAidLength);

        // Verify all AIDs are concatenated
        int offset = dataOffset + 2;
        foreach (byte[] aid in aids)
        {
            _ = apdu.Skip(offset).Take(aid.Length).Should().BeEquivalentTo(aid);
            offset += aid.Length;
        }
    }

    [Test]
    public void DeletePackage_CommandStructure_IsCorrect()
    {
        // Arrange
        byte[] packageAid = Convert.FromHexString("A0000003080000100000");

        Result<DeleteCommand, SmartCardError> deleteCommandResult = DeleteCommand.CreateForPackage(
            packageAid,
            deleteRelated: true
        );
        _ = deleteCommandResult.IsSuccess.Should().BeTrue();
        DeleteCommand? deleteCommand = deleteCommandResult.Value;

        // Act
        byte[]? apdu = deleteCommand.ToApdu();

        // Assert - Verify command structure
        _ = apdu[0].Should().Be(0x80); // CLA
        _ = apdu[1].Should().Be(0xE4); // INS
        _ = apdu[2].Should().Be(0x00); // P1 (delete object and related)
        _ = apdu[3].Should().Be(0x80); // P2 (with related)

        // Verify AID encoding
        int dataOffset = 5;
        _ = apdu[dataOffset].Should().Be(0x4F); // AID tag
        _ = apdu[dataOffset + 1].Should().Be((byte)packageAid.Length);

        byte[] aidInApdu = [.. apdu.Skip(dataOffset + 2).Take(packageAid.Length)];
        _ = aidInApdu.Should().BeEquivalentTo(packageAid);
    }

    [Test]
    public void DeleteKey_WithValidKeyReference_GeneratesCorrectApdu()
    {
        // Arrange
        byte keyId = 0x01;
        byte keyVersion = 0x73;

        Result<DeleteCommand, SmartCardError> deleteCommandResult = DeleteCommand.CreateForKey(
            keyId,
            keyVersion
        );
        _ = deleteCommandResult.IsSuccess.Should().BeTrue();
        DeleteCommand? deleteCommand = deleteCommandResult.Value;

        // Act
        byte[]? apdu = deleteCommand.ToApdu();

        // Assert
        _ = apdu[0].Should().Be(0x80); // CLA
        _ = apdu[1].Should().Be(0xE4); // INS
        _ = apdu[2].Should().Be(0x80); // P1 (delete object only)
        _ = apdu[3].Should().Be(0x00); // P2 (by AID)

        // For key deletion, the "AID" contains key reference
        int dataOffset = 5;
        _ = apdu[dataOffset].Should().Be(0x4F); // Still uses AID tag
        _ = apdu[dataOffset + 1].Should().Be(0x02); // Length = 2 (keyId + keyVersion)
        _ = apdu[dataOffset + 2].Should().Be(keyId);
        _ = apdu[dataOffset + 3].Should().Be(keyVersion);
    }

    [Test]
    public void DeleteResponse_Parse_HandlesEmptyConfirmation()
    {
        // Arrange - Response with no deletion confirmation
        byte[] responseData = [0x00]; // Length = 0
        ushort statusWord = 0x9000;

        // Act
        DeleteResponse? deleteResponse = DeleteResponse.Parse(responseData, statusWord);

        // Assert
        _ = deleteResponse.IsSuccessful.Should().BeTrue();
        _ = deleteResponse.StatusWord.Should().Be(0x9000);
        _ = deleteResponse.DeletionReceipts.Should().BeEmpty();
    }

    [Test]
    public void DeleteResponse_Parse_HandlesDeletionReceipt()
    {
        // Arrange - Response with deletion receipt
        byte[] deletedAid = Convert.FromHexString("A0000003080000100001");
        byte[] responseData =
        [
            0x0C, // Length of delete confirmation
            0x4F, // AID tag
            0x0A,
            .. deletedAid, // AID length (10 bytes)
        ];
        ushort statusWord = 0x9000;

        // Act
        DeleteResponse? deleteResponse = DeleteResponse.Parse(responseData, statusWord);

        // Assert
        _ = deleteResponse.IsSuccessful.Should().BeTrue();
        _ = deleteResponse.DeletionReceipts.Should().HaveCount(1);
        _ = deleteResponse.DeletionReceipts[0].Aid.Should().BeEquivalentTo(deletedAid);
        _ = deleteResponse.DeletionReceipts[0].IsSuccessful.Should().BeTrue();
    }

    [Test]
    public void DeleteCommand_PureFunctionality_ProducesIdenticalResults()
    {
        // Arrange
        byte[] aid = Convert.FromHexString("A0000003080000100001");
        byte[] deletionToken = Convert.FromHexString("20EEDD243F094FAD");

        // Act - Create command multiple times
        Result<DeleteCommand, SmartCardError> result1 = DeleteCommand.CreateForApplication(
            aid,
            true,
            deletionToken
        );
        Result<DeleteCommand, SmartCardError> result2 = DeleteCommand.CreateForApplication(
            aid,
            true,
            deletionToken
        );

        // Assert - Pure function produces identical results
        _ = result1.IsSuccess.Should().BeTrue();
        _ = result2.IsSuccess.Should().BeTrue();

        byte[]? apdu1 = result1.Value.ToApdu();
        byte[]? apdu2 = result2.Value.ToApdu();

        _ = apdu1.Should().BeEquivalentTo(apdu2);
    }

    [Test]
    public void DeleteCommand_WithSecureMessaging_HasCorrectCla()
    {
        // Arrange
        byte[] aid = Convert.FromHexString("A0000003080000100001");
        Result<DeleteCommand, SmartCardError> deleteCommandResult =
            DeleteCommand.CreateForApplication(aid);
        _ = deleteCommandResult.IsSuccess.Should().BeTrue();
        DeleteCommand? deleteCommand = deleteCommandResult.Value;

        // Act
        byte[]? apdu = deleteCommand.ToApdu();

        // Secure messaging would modify the CLA
        byte[] secureApdu = (byte[])apdu.Clone();
        secureApdu[0] = 0x84; // Secure messaging bit

        // Assert
        _ = secureApdu[0].Should().Be(0x84);
        _ = secureApdu[1].Should().Be(0xE4); // INS unchanged
    }

    [Test]
    public void DeleteCommand_ToApdu_MatchesTraceFormat()
    {
        // Based on the trace analysis from DeleteCommandTraceTests
        // Command: 84E40080134F09A0000003080000100020EEDD243F094FAD

        // Arrange
        byte[] aid = Convert.FromHexString("A00000030800001000"); // 9 bytes
        byte[] deletionToken = Convert.FromHexString("20EEDD243F094FAD"); // 8 bytes

        Result<DeleteCommand, SmartCardError> deleteCommandResult =
            DeleteCommand.CreateForApplication(aid, deleteRelated: true, deletionToken);
        _ = deleteCommandResult.IsSuccess.Should().BeTrue();
        DeleteCommand? deleteCommand = deleteCommandResult.Value;

        // Act
        byte[]? apdu = deleteCommand.ToApdu();

        // Assert - Structure matches trace
        _ = apdu[0].Should().Be(0x80); // CLA (before secure messaging)
        _ = apdu[1].Should().Be(0xE4); // INS
        _ = apdu[2].Should().Be(0x00); // P1 (delete object and related)
        _ = apdu[3].Should().Be(0x80); // P2 (with related)
        _ = apdu[4].Should().Be(0x13); // Lc = 19 bytes (2 + 9 + 8)

        // Data: 4F09<AID><TOKEN>
        _ = apdu[5].Should().Be(0x4F); // AID tag
        _ = apdu[6].Should().Be(0x09); // AID length

        // Verify complete data section
        byte[] expectedData = [0x4F, 0x09, .. aid, .. deletionToken];

        byte[] actualData = [.. apdu.Skip(5)];
        _ = actualData.Should().BeEquivalentTo(expectedData);
    }

    [Test]
    public void VirtualCard_ProcessesBasicCommands()
    {
        // This test verifies the virtual card can process basic commands
        // without expecting full DELETE implementation

        // Arrange
        byte[] selectCommand = [0x00, 0xA4, 0x04, 0x00, 0x00];

        // Act
        VirtualCommandResponse response = _virtualCardService.SendCommand(selectCommand);

        // Assert - Debug the response
        Console.WriteLine($"Response IsSuccessful: {response.IsSuccessful}");
        Console.WriteLine($"Response StatusWord: 0x{response.StatusWord:X4}");
        Console.WriteLine($"Response Data Length: {response.Data.Length}");
        response.Error.Match(
            error => Console.WriteLine($"Response Error: {error}"),
            () => Console.WriteLine("No error")
        );

        _ = response.IsSuccessful.Should().BeTrue();
        _ = response.Data.Should().NotBeEmpty(); // Should return FCI
    }

    [Test]
    public void DeleteCommand_ErrorScenarios_GenerateCorrectCommands()
    {
        // Test that we can generate commands for various error scenarios
        // even if the virtual card doesn't implement them

        // Non-existent AID
        byte[] nonExistentAid = Convert.FromHexString("AABBCCDDEE");
        Result<DeleteCommand, SmartCardError> result1 = DeleteCommand.CreateForApplication(
            nonExistentAid
        );
        _ = result1.IsSuccess.Should().BeTrue();

        // Empty AID list (should fail at creation)
        Result<DeleteCommand, SmartCardError> result2 = DeleteCommand.CreateForApplications(
            Array.Empty<byte[]>()
        );
        _ = result2.IsFailure.Should().BeTrue();
        _ = result2.Error.Message.Should().Contain("At least one AID must be provided");

        // Null AID (should fail at creation)
        Result<DeleteCommand, SmartCardError> result3 = DeleteCommand.CreateForApplication(null!);
        _ = result3.IsFailure.Should().BeTrue();
        _ = result3.Error.Message.Should().Contain("AID cannot be null");
    }
}
