using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.Domain.Commands;
using Xunit;

namespace Gp4Net.Tests.Integration
{
    /// <summary>
    /// Tests DELETE command implementation using real trace data.
    /// </summary>
    public class DeleteCommandTraceTests : TraceBasedTestBase
    {
        public DeleteCommandTraceTests() : base("install_uninstall.json", TraceOperations.Uninstall)
        {
        }

        [Fact]
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
            
            var aid = Convert.FromHexString("A0000003080000100001");
            var deleteCommand = DeleteCommand.CreateForApplication(aid, deleteRelated: true);
            
            // Act - Convert to APDU
            var apdu = deleteCommand.ToApdu();
            
            // Assert - Verify structure
            Assert.Equal(0x80, apdu[0]); // CLA (without secure messaging)
            Assert.Equal(0xE4, apdu[1]); // INS
            Assert.Equal(0x00, apdu[2]); // P1
            Assert.Equal(0x80, apdu[3]); // P2
            
            // The data should be: 4F <len> <AID>
            var dataStart = 5;
            Assert.Equal(0x4F, apdu[dataStart]); // AID tag
            Assert.Equal((byte)aid.Length, apdu[dataStart + 1]); // AID length
            
            // Verify the AID
            var aidInApdu = apdu.Skip(dataStart + 2).Take(aid.Length).ToArray();
            Assert.Equal(aid, aidInApdu);
        }

        [Fact]
        public void DeleteCommand_WithDeletionToken_MatchesTrace()
        {
            // Arrange - Exact values from trace
            var aid = Convert.FromHexString("A0000003080000100001");
            var deletionToken = Convert.FromHexString("20EEDD243F094FAD");
            
            var deleteCommand = DeleteCommand.CreateForApplication(
                aid, 
                deleteRelated: true,
                deletionToken: deletionToken
            );
            
            // Act
            var apdu = deleteCommand.ToApdu();
            
            // Assert - The complete APDU structure
            Assert.Equal(0x80, apdu[0]); // CLA
            Assert.Equal(0xE4, apdu[1]); // INS
            Assert.Equal(0x00, apdu[2]); // P1
            Assert.Equal(0x80, apdu[3]); // P2
            
            // Calculate expected Lc
            var expectedLc = 2 + aid.Length + 1 + deletionToken.Length; // 4F<len><AID><token_len><token>
            Assert.Equal((byte)expectedLc, apdu[4]); // Lc
            
            // Verify data structure
            var dataStart = 5;
            Assert.Equal(0x4F, apdu[dataStart]); // AID tag
            Assert.Equal((byte)aid.Length, apdu[dataStart + 1]); // AID length
            
            // Verify AID
            var aidOffset = dataStart + 2;
            var aidInApdu = apdu.Skip(aidOffset).Take(aid.Length).ToArray();
            Assert.Equal(aid, aidInApdu);
            
            // Verify deletion token
            var tokenOffset = aidOffset + aid.Length;
            Assert.Equal((byte)deletionToken.Length, apdu[tokenOffset]); // Token length
            var tokenInApdu = apdu.Skip(tokenOffset + 1).Take(deletionToken.Length).ToArray();
            Assert.Equal(deletionToken, tokenInApdu);
        }

        [Fact]
        public void DeleteCommand_TraceReplay_Succeeds()
        {
            // Arrange - Connect to trace
            ConnectToTrace(TraceOperations.Uninstall);
            Assert.NotNull(CardService);
            
            // From trace: 84E40080134F09A0000003080000100020EEDD243F094FAD
            var expectedCommand = Convert.FromHexString("84E40080134F09A0000003080000100020EEDD243F094FAD");
            
            // Act - Send the exact command from trace
            var response = CardService.SendCommand(expectedCommand);
            
            // Assert
            Assert.Equal(0x9000, response.StatusWord);
            Assert.NotNull(response.Data);
            // From trace: Response <-- 009000
            // The "00" is the mandatory length field per GP spec Table 11-25
            // indicating 0 bytes of delete confirmation data
            Assert.Equal(1, response.Data.Length);
            Assert.Equal(0x00, response.Data[0]); // Length of delete confirmation = 0
        }

        [Fact]
        public void DeleteCommand_WithSecureChannel_WorksCorrectly()
        {
            // This test verifies that our DELETE command works correctly through secure channel
            
            // Arrange - Connect with secure channel from trace
            ConnectToTrace(TraceOperations.Uninstall);
            Assert.NotNull(CardService);
            Assert.True(CardService.IsSecureChannelEstablished);
            
            // From trace analysis:
            // - AID being deleted: A000000308000010000 (9 bytes)
            var aid = Convert.FromHexString("A000000308000010000");
            var deleteCommand = DeleteCommand.CreateForApplication(aid, deleteRelated: true);
            
            // Act - Send the DELETE command (secure channel wrapping happens internally)
            var response = CardService.SendCommand(deleteCommand);
            
            // Assert - Command should succeed
            Assert.Equal(0x9000, response.StatusWord);
            Assert.NotNull(response.Data);
            Assert.Equal(1, response.Data.Length);
            Assert.Equal(0x00, response.Data[0]); // Length of delete confirmation = 0
        }

        [Fact]
        public void DeleteCommand_GeneratesCorrectPlainApdu()
        {
            // This test verifies our plain DELETE command structure before wrapping
            
            // Arrange
            var aid = Convert.FromHexString("A000000308000010000"); // 9-byte AID from trace
            var deleteCommand = DeleteCommand.CreateForApplication(aid, deleteRelated: true);
            
            // Act
            var apdu = deleteCommand.ToApdu();
            
            // Assert - Plain command structure
            Assert.Equal(0x80, apdu[0]); // CLA (no secure messaging)
            Assert.Equal(0xE4, apdu[1]); // INS (DELETE)
            Assert.Equal(0x00, apdu[2]); // P1 (delete object and related)
            Assert.Equal(0x80, apdu[3]); // P2 (with related objects)
            Assert.Equal(0x0B, apdu[4]); // Lc = 11 bytes (2 + 9 for TLV with AID)
            
            // Verify data: 4F 09 <9-byte AID>
            Assert.Equal(0x4F, apdu[5]); // AID tag
            Assert.Equal(0x09, apdu[6]); // AID length = 9
            
            // Verify AID bytes
            var aidInApdu = apdu.Skip(7).Take(9).ToArray();
            Assert.Equal(aid, aidInApdu);
            
            // Total command length should be 5 (header) + 11 (data) = 16 bytes
            Assert.Equal(16, apdu.Length);
        }

        [Fact]
        public void DeleteCommand_MultipleAids_CalculatesLengthCorrectly()
        {
            // This test specifically checks the bug on line 121 of DeleteCommand.cs
            // which assumed all AIDs have the same length as the first one
            
            // Arrange - Different length AIDs
            var aids = new[]
            {
                Convert.FromHexString("A00000030800001000"), // 9 bytes
                Convert.FromHexString("A0000003080000100001"), // 10 bytes
                Convert.FromHexString("A000000308"), // 5 bytes
            };
            
            var deleteCommand = DeleteCommand.CreateForApplications(aids);
            
            // Act
            var apdu = deleteCommand.ToApdu();
            
            // Assert - With the fix, should have single 4F tag with total length
            var totalAidLength = aids.Sum(aid => aid.Length); // 9 + 10 + 5 = 24
            var expectedDataLength = 2 + totalAidLength; // 4F <len> <all AIDs concatenated>
            
            Assert.Equal((byte)expectedDataLength, apdu[4]); // Lc
            
            // Verify the encoding: 4F <total_len> <AID1><AID2><AID3>
            var offset = 5; // Skip header
            Assert.Equal(0x4F, apdu[offset]); // Tag
            Assert.Equal((byte)totalAidLength, apdu[offset + 1]); // Total length
            
            // Verify all AIDs are concatenated
            offset += 2;
            foreach (var aid in aids)
            {
                var aidInApdu = apdu.Skip(offset).Take(aid.Length).ToArray();
                Assert.Equal(aid, aidInApdu);
                offset += aid.Length;
            }
        }

        [Fact]
        public void DeleteResponse_Parse_HandlesSpecificationFormat()
        {
            // Test parsing of DELETE response per GP spec Table 11-25
            
            // Test 1: Response with no confirmation data (like our trace)
            var response1 = new byte[] { 0x00 }; // Length of delete confirmation = 0
            var parsed1 = DeleteResponse.Parse(response1, 0x9000);
            Assert.True(parsed1.IsSuccessful);
            Assert.Empty(parsed1.DeletionReceipts);
            
            // Test 2: Response with delete confirmation containing an AID
            var testAid = Convert.FromHexString("A0000003080000100001");
            var response2 = new List<byte>();
            response2.Add(0x0C); // Length of delete confirmation
            response2.Add(0x4F); // AID tag
            response2.Add((byte)testAid.Length);
            response2.AddRange(testAid);
            
            var parsed2 = DeleteResponse.Parse(response2.ToArray(), 0x9000);
            Assert.True(parsed2.IsSuccessful);
            Assert.Single(parsed2.DeletionReceipts);
            Assert.Equal(testAid, parsed2.DeletionReceipts[0].Aid);
            
            // Test 3: Extended length encoding
            var response3 = new byte[] { 0x81, 0x80 }; // Extended length: 128 bytes follow
            var parsed3 = DeleteResponse.Parse(response3, 0x9000);
            Assert.True(parsed3.IsSuccessful);
            Assert.Empty(parsed3.DeletionReceipts); // No actual data follows in this test
        }
    }
}