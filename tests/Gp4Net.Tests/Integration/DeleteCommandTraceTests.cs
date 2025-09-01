using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Tests DELETE command implementation using real trace data.
/// </summary>
[TestFixture]
[Category("Integration")]
public class DeleteCommandTraceTests : TraceBasedTestBase
{
    public DeleteCommandTraceTests()
        : base("install_uninstall.json", TraceOperations.Uninstall) { }

    [Test]
    public void DeleteCommand_MatchesTraceFormat()
    {
        // Arrange - From the trace analysis:
        // Command: 84E40080134F09A0000003080000100020EEDD243F094FAD
        // Breaking down:
        // 84 - CLA with secure messaging
        // E4 - DELETE instruction
        // 00 - P1 (delete object and related)
        // 80 - P2 (with related objects)
        // 13 - Lc (19 bytes)
        // 4F09A000000308000010000 - TLV: tag 4F, length 09, AID
        // 20EEDD243F094FAD - 8 bytes deletion token

        byte[] aid = Convert.FromHexString("A0000003080000100001");
        Result<DeleteCommand, SmartCardError> deleteCommandResult =
            DeleteCommand.CreateForApplication(aid, deleteRelated: true);
        DeleteCommand? deleteCommand = deleteCommandResult.Value;

        // Act - Convert to APDU
        byte[]? apdu = deleteCommand.ToApdu();
        Assert.Multiple(() =>
        {
            // Assert - Verify structure
            Assert.That(apdu[0], Is.EqualTo(0x80)); // CLA (without secure messaging)
            Assert.That(apdu[1], Is.EqualTo(0xE4)); // INS
            Assert.That(apdu[2], Is.EqualTo(0x00)); // P1
            Assert.That(apdu[3], Is.EqualTo(0x80)); // P2
        });

        // The data should be: 4F <len> <AID>
        int dataStart = 5;
        Assert.Multiple(() =>
        {
            Assert.That(apdu[dataStart], Is.EqualTo(0x4F)); // AID tag
            Assert.That(apdu[dataStart + 1], Is.EqualTo((byte)aid.Length)); // AID length
        });

        // Verify the AID
        byte[] aidInApdu = [.. apdu.Skip(dataStart + 2).Take(aid.Length)];
        Assert.That(aidInApdu, Is.EqualTo(aid));
    }

    [Test]
    public void DeleteCommand_WithDeletionToken_MatchesTrace()
    {
        // Arrange - Exact values from trace
        byte[] aid = Convert.FromHexString("A0000003080000100001");
        byte[] deletionToken = Convert.FromHexString("20EEDD243F094FAD");

        Result<DeleteCommand, SmartCardError> deleteCommandResult =
            DeleteCommand.CreateForApplication(
                aid,
                deleteRelated: true,
                deletionToken: deletionToken
            );
        DeleteCommand? deleteCommand = deleteCommandResult.Value;

        // Act
        byte[]? apdu = deleteCommand.ToApdu();
        Assert.Multiple(() =>
        {
            // Assert - The complete APDU structure
            Assert.That(apdu[0], Is.EqualTo(0x80)); // CLA
            Assert.That(apdu[1], Is.EqualTo(0xE4)); // INS
            Assert.That(apdu[2], Is.EqualTo(0x00)); // P1
            Assert.That(apdu[3], Is.EqualTo(0x80)); // P2
        });

        // Calculate expected Lc - deletion token is appended directly without length prefix
        int expectedLc = 2 + aid.Length + deletionToken.Length; // 4F<len><AID><token>
        Assert.That(apdu[4], Is.EqualTo((byte)expectedLc)); // Lc

        // Verify data structure
        int dataStart = 5;
        Assert.Multiple(() =>
        {
            Assert.That(apdu[dataStart], Is.EqualTo(0x4F)); // AID tag
            Assert.That(apdu[dataStart + 1], Is.EqualTo((byte)aid.Length)); // AID length
        });

        // Verify AID
        int aidOffset = dataStart + 2;
        byte[] aidInApdu = [.. apdu.Skip(aidOffset).Take(aid.Length)];
        Assert.That(aidInApdu, Is.EqualTo(aid));

        // Verify deletion token - appended directly without length prefix
        int tokenOffset = aidOffset + aid.Length;
        byte[] tokenInApdu = [.. apdu.Skip(tokenOffset).Take(deletionToken.Length)];
        Assert.That(tokenInApdu, Is.EqualTo(deletionToken));
    }

    [Test]
    public void DeleteCommand_TraceReplay_Succeeds()
    {
        // Arrange - Connect to trace
        ConnectToTrace(TraceOperations.Uninstall);
        Assert.That(CardService, Is.Not.Null);

        // From trace: 84E40080134F09A000000308000010007547C55C046E221C
        byte[] expectedCommand = Convert.FromHexString(
            "84E40080134F09A000000308000010007547C55C046E221C"
        );

        // Act - Send the exact command from trace
        var response = CardService.SendCommand(expectedCommand);

        // Assert - From trace: Response is 6A88 (Referenced data not found)
        Assert.That(response.StatusWord, Is.EqualTo(0x6A88));
        Assert.That(response.Data, Is.Not.Null);
        Assert.That(response.Data.Length, Is.EqualTo(0)); // Error response has no data
    }

    [Test]
    public void DeleteCommand_WithSecureChannel_HandlesNonExistentApp()
    {
        // This test verifies that DELETE commands through secure channel properly handle non-existent applications
        // The trace shows a DELETE attempt that returns 6A88 (Referenced data not found)

        // Arrange - Connect with secure channel from trace
        ConnectToTrace(TraceOperations.Uninstall);
        Assert.That(CardService, Is.Not.Null);
        Assert.That(CardService.IsSecureChannelEstablished, Is.True);

        // From trace command: 84E40080134F09A000000308000010007547C55C046E221C
        // Breaking down the wrapped command data:
        // 84 - CLA with secure messaging
        // E4 - DELETE instruction
        // 00 80 - P1 P2 (delete with related objects)
        // 13 - Lc (19 bytes)
        // 4F09A00000030800001000 - TLV: tag 4F, length 09, AID A00000030800001000
        // 7547C55C046E221C - 8-byte deletion token
        byte[] aid = Convert.FromHexString("A00000030800001000");
        byte[] deletionToken = Convert.FromHexString("7547C55C046E221C");
        Result<DeleteCommand, SmartCardError> deleteCommandResult =
            DeleteCommand.CreateForApplication(aid, deleteRelated: true, deletionToken);
        DeleteCommand? deleteCommand = deleteCommandResult.Value;

        // Act - Send the DELETE command (secure channel wrapping is handled by the trace)
        byte[]? commandApdu = deleteCommand.ToApdu();
        commandApdu[0] = 0x84; // Set secure messaging bit to match trace
        var response = CardService.SendCommand(commandApdu);

        // Assert - From trace: Response is 6A88 (Referenced data not found)
        Assert.Multiple(() =>
        {
            Assert.That(
                response.StatusWord,
                Is.EqualTo(0x6A88),
                "Should return 'Referenced data not found'"
            );
            Assert.That(response.Data, Is.Not.Null);
            Assert.That(response.Data.Length, Is.EqualTo(0), "Error response should have no data");
        });
    }

    [Test]
    public void DeleteCommand_GeneratesCorrectPlainApdu()
    {
        // This test verifies our plain DELETE command structure before wrapping

        // Arrange
        byte[] aid = Convert.FromHexString("A0000003080000100001"); // 10-byte AID from trace
        Result<DeleteCommand, SmartCardError> deleteCommandResult =
            DeleteCommand.CreateForApplication(aid, deleteRelated: true);
        DeleteCommand? deleteCommand = deleteCommandResult.Value;

        // Act
        byte[]? apdu = deleteCommand.ToApdu();
        Assert.Multiple(() =>
        {
            // Assert - Plain command structure
            Assert.That(apdu[0], Is.EqualTo(0x80)); // CLA (no secure messaging)
            Assert.That(apdu[1], Is.EqualTo(0xE4)); // INS (DELETE)
            Assert.That(apdu[2], Is.EqualTo(0x00)); // P1 (delete object and related)
            Assert.That(apdu[3], Is.EqualTo(0x80)); // P2 (with related objects)
            Assert.That(apdu[4], Is.EqualTo(0x0C)); // Lc = 12 bytes (2 + 10 for TLV with AID)

            // Verify data: 4F 0A <10-byte AID>
            Assert.That(apdu[5], Is.EqualTo(0x4F)); // AID tag
            Assert.That(apdu[6], Is.EqualTo(0x0A)); // AID length = 10
        });

        // Verify AID bytes
        byte[] aidInApdu = [.. apdu.Skip(7).Take(10)];
        Assert.Multiple(() =>
        {
            Assert.That(aidInApdu, Is.EqualTo(aid));

            // Total command length should be 5 (header) + 12 (data) = 17 bytes
            Assert.That(apdu.Length, Is.EqualTo(17));
        });
    }

    [Test]
    public void DeleteCommand_MultipleAids_CalculatesLengthCorrectly()
    {
        // This test specifically checks the bug on line 121 of DeleteCommand.cs
        // which assumed all AIDs have the same length as the first one

        // Arrange - Different length AIDs
        byte[][] aids =
        [
            Convert.FromHexString("A0000003080000100000"), // 10 bytes
            Convert.FromHexString("A0000003080000100001"), // 10 bytes
            Convert.FromHexString("A00000030800"), // 6 bytes
        ];

        Result<DeleteCommand, SmartCardError> deleteCommandResult =
            DeleteCommand.CreateForApplications(aids);
        DeleteCommand? deleteCommand = deleteCommandResult.Value;

        // Act
        byte[]? apdu = deleteCommand.ToApdu();

        // Assert - With the fix, should have single 4F tag with total length
        int totalAidLength = aids.Sum(aid => aid.Length); // 10 + 10 + 6 = 26
        int expectedDataLength = 2 + totalAidLength; // 4F <len> <all AIDs concatenated>

        Assert.That(apdu[4], Is.EqualTo((byte)expectedDataLength)); // Lc

        // Verify the encoding: 4F <total_len> <AID1><AID2><AID3>
        int offset = 5; // Skip header
        Assert.Multiple(() =>
        {
            Assert.That(apdu[offset], Is.EqualTo(0x4F)); // Tag
            Assert.That(apdu[offset + 1], Is.EqualTo((byte)totalAidLength)); // Total length
        });

        // Verify all AIDs are concatenated
        offset += 2;
        foreach (byte[] aid in aids)
        {
            byte[] aidInApdu = [.. apdu.Skip(offset).Take(aid.Length)];
            Assert.That(aidInApdu, Is.EqualTo(aid));
            offset += aid.Length;
        }
    }

    [Test]
    public void DeleteResponse_Parse_HandlesSpecificationFormat()
    {
        // Test parsing of DELETE response per GP spec Table 11-25

        // Test 1: Response with no confirmation data (like our trace)
        byte[] response1 = [0x00]; // Length of delete confirmation = 0
        DeleteResponse? parsed1 = DeleteResponse.Parse(response1, 0x9000);
        Assert.Multiple(() =>
        {
            Assert.That(parsed1.IsSuccessful, Is.True);
            Assert.That(parsed1.DeletionReceipts, Is.Empty);
        });

        // Test 2: Response with delete confirmation containing an AID
        byte[] testAid = Convert.FromHexString("A0000003080000100001");
        List<byte> response2 =
        [
            0x0C, // Length of delete confirmation
            0x4F, // AID tag
            (byte)testAid.Length,
        ];
        response2.AddRange(testAid);

        DeleteResponse? parsed2 = DeleteResponse.Parse([.. response2], 0x9000);
        Assert.Multiple(() =>
        {
            Assert.That(parsed2.IsSuccessful, Is.True);
            Assert.That(parsed2.DeletionReceipts, Has.Count.EqualTo(1));
        });
        Assert.That(parsed2.DeletionReceipts[0].Aid, Is.EqualTo(testAid));

        // Test 3: Extended length encoding
        byte[] response3 = [0x81, 0x80]; // Extended length: 128 bytes follow
        DeleteResponse? parsed3 = DeleteResponse.Parse(response3, 0x9000);
        Assert.Multiple(() =>
        {
            Assert.That(parsed3.IsSuccessful, Is.True);
            Assert.That(parsed3.DeletionReceipts, Is.Empty); // No actual data follows in this test
        });
    }
}
