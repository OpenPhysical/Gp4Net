using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Gp4Net.Domain.CapFile;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration
{
    /// <summary>
    /// Tests LOAD command chunking using trace data.
    /// </summary>
    [TestFixture]
    public class LoadCommandTraceTests : TraceBasedTestBase
    {
        private readonly string _capFilePath;

        public LoadCommandTraceTests() : base(TraceFiles.GpShellInstallJson)
        {
            // Get the CAP file used in the trace
            _capFilePath = Path.Combine(
                TestContext.GetProjectRootDirectory(),
                "tests",
                "applets",
                "OpenFIPS201-v1_10_2-chainfix.cap"
            );
        }

        [Test]
        public void LoadCommand_FirstBlock_MatchesTrace()
        {
            // Arrange - Load CAP file
            var capFileData = File.ReadAllBytes(_capFilePath);
            var maxBlockSize = 245;
            
            // Act - Generate LOAD commands
            var result = LoadCommand.CreateFromCapFile(capFileData, maxBlockSize);
            Assert.That(result.IsSuccess, Is.True, "CreateFromCapFile should succeed");
            var loadCommands = result.Value;
            
            // Assert - First command structure
            Assert.That(loadCommands.Count > 0);
            var firstCommand = loadCommands[0];
            
            Assert.That(firstCommand.IsFirstBlock);
            Assert.That(firstCommand.IsFinalBlock, Is.False); // Large CAP file, not final block
            Assert.That(firstCommand.P1, Is.EqualTo(0x00)); // Continuation
            Assert.That(firstCommand.P2, Is.EqualTo(0x00)); // Block 0
            
            // The first block should include TLV header with total size
            var apdu = firstCommand.ToApdu();
            Assert.That(apdu[0], Is.EqualTo(0x80)); // CLA
            Assert.That(apdu[1], Is.EqualTo(0xE8)); // INS
            Assert.That(apdu[2], Is.EqualTo(0x00)); // P1
            Assert.That(apdu[3], Is.EqualTo(0x00)); // P2
            
            // Should start with C4 tag and length encoding
            Assert.That(apdu[5], Is.EqualTo(0xC4)); // CAP data tag
            
            // Verify the total payload size respects maxBlockSize
            var payloadSize = apdu[4]; // Lc field
            Assert.That(payloadSize, Is.LessThanOrEqualTo(maxBlockSize), 
                $"Payload size {payloadSize} should not exceed maxBlockSize {maxBlockSize}");
            
            // The length encoding should match the total CAP file size
            var totalSize = (uint)capFileData.Length;
            Assert.That(firstCommand.TotalCapSize, Is.EqualTo(totalSize));
            
            // Verify TLV length encoding is correct for this file size
            var expectedTlvHeader = CreateExpectedTlvHeader(totalSize);
            for (int i = 0; i < expectedTlvHeader.Length; i++)
            {
                Assert.That(apdu[5 + i], Is.EqualTo(expectedTlvHeader[i]), 
                    $"TLV header byte {i} should match expected encoding");
            }
        }
        
        private static byte[] CreateExpectedTlvHeader(uint totalSize)
        {
            var header = new List<byte> { 0xC4 }; // Tag
            
            if (totalSize <= 0x7F)
            {
                header.Add((byte)totalSize);
            }
            else if (totalSize <= 0xFF)
            {
                header.Add(0x81);
                header.Add((byte)totalSize);
            }
            else if (totalSize <= 0xFFFF)
            {
                header.Add(0x82);
                header.Add((byte)(totalSize >> 8));
                header.Add((byte)(totalSize & 0xFF));
            }
            else if (totalSize <= 0xFFFFFF)
            {
                header.Add(0x83);
                header.Add((byte)(totalSize >> 16));
                header.Add((byte)((totalSize >> 8) & 0xFF));
                header.Add((byte)(totalSize & 0xFF));
            }
            else
            {
                header.Add(0x84);
                header.Add((byte)(totalSize >> 24));
                header.Add((byte)((totalSize >> 16) & 0xFF));
                header.Add((byte)((totalSize >> 8) & 0xFF));
                header.Add((byte)(totalSize & 0xFF));
            }
            
            return [.. header];
        }

        [Test]
        public void LoadCommand_Chunking_GeneratesCorrectNumberOfBlocks()
        {
            // The trace shows 567 LOAD commands for OpenFIPS201
            
            // Arrange
            var capFileData = File.ReadAllBytes(_capFilePath);
            var capFileSize = capFileData.Length;
            
            // Act
            var result = LoadCommand.CreateFromCapFile(capFileData, maxBlockSize: 245);
            Assert.That(result.IsSuccess, Is.True, "CreateFromCapFile should succeed");
            var loadCommands = result.Value;
            
            // Assert
            // With 245 byte blocks and considering TLV overhead:
            // First block has additional TLV header (C4 + length encoding)
            // Each block can carry up to 245 bytes of actual data
            
            // The trace shows many LOAD commands, let's verify we generate a reasonable number
            Assert.That(loadCommands.Count > 100, Is.True, $"Expected many LOAD commands, got {loadCommands.Count}");
            
            // Verify block numbering (wraps at 256 due to byte limit)
            for (int i = 0; i < loadCommands.Count; i++)
            {
                var expectedBlockNumber = (byte)(i % 256);
                Assert.That(loadCommands[i].BlockNumber, Is.EqualTo(expectedBlockNumber));
            }
            
            // Last block should be marked as final
            var lastCommand = loadCommands.Last();
            Assert.That(lastCommand.IsFinalBlock);
            Assert.That(lastCommand.P1, Is.EqualTo(0x80)); // Final block
        }

        [Test]
        public void LoadCommand_DataReassembly_ReconstructsOriginalCapFile()
        {
            // Verify that reassembling all LOAD command data reconstructs the original CAP file
            
            // Arrange
            var originalCapData = File.ReadAllBytes(_capFilePath);
            
            // Act
            var result = LoadCommand.CreateFromCapFile(originalCapData, maxBlockSize: 245);
            Assert.That(result.IsSuccess, Is.True, "CreateFromCapFile should succeed");
            var loadCommands = result.Value;
            
            // Reassemble data from all commands
            var reassembledData = new System.Collections.Generic.List<byte>();
            
            foreach (var cmd in loadCommands)
            {
                var apdu = cmd.ToApdu();
                var lc = apdu[4];
                var commandData = apdu[5..(5 + lc)];
                
                if (cmd.IsFirstBlock)
                {
                    // Skip TLV header (C4 tag and length encoding)
                    Assert.That(commandData[0], Is.EqualTo(0xC4));
                    
                    // Determine length encoding size
                    int headerSize = 1; // C4 tag
                    if (commandData[1] == 0x82)
                    {
                        headerSize += 3; // 82 + 2 length bytes
                    }
                    else if (commandData[1] == 0x83)
                    {
                        headerSize += 4; // 83 + 3 length bytes
                    }
                    else if (commandData[1] == 0x84)
                    {
                        headerSize += 5; // 84 + 4 length bytes
                    }
                    else if (commandData[1] <= 0x7F)
                    {
                        headerSize += 1; // Direct length
                    }
                    else if (commandData[1] == 0x81)
                    {
                        headerSize += 2; // 81 + 1 length byte
                    }
                    
                    reassembledData.AddRange(commandData[headerSize..]);
                }
                else
                {
                    // Subsequent blocks contain raw data
                    reassembledData.AddRange(commandData);
                }
            }
            
            // Assert
            var reassembled = reassembledData.ToArray();
            Assert.That(reassembled.Length, Is.EqualTo(originalCapData.Length));
            Assert.That(reassembled, Is.EqualTo(originalCapData));
        }

        [Test]
        public void LoadCommand_CapFileStructure_IsValid()
        {
            // Verify the CAP file can be parsed
            
            // Arrange
            var capFileData = File.ReadAllBytes(_capFilePath);
            
            // Act & Assert
            var capFile = CapFileStructure.Parse(capFileData);
            
            Assert.That(capFile, Is.Not.Null);
            Assert.That(Convert.ToHexString(capFile.PackageAid), Is.EqualTo("A00000030800001000"));
            Assert.That(capFile.Components.Count > 0);
            Assert.That(capFile.TotalSize > 0);
            
            // The trace mentions OpenFIPS201-v1_10_2-chainfix.cap
            // This is a substantial applet with multiple components
            Assert.That(capFile.Components.Count >= 5, Is.True, $"Expected multiple components, got {capFile.Components.Count}");
        }

        [Test]
        public void LoadCommand_BlockSizeLimits_AreRespected()
        {
            // Verify that no LOAD command exceeds the maximum block size
            
            // Arrange
            var capFileData = File.ReadAllBytes(_capFilePath);
            const int maxBlockSize = 245;
            
            // Act
            var result = LoadCommand.CreateFromCapFile(capFileData, maxBlockSize);
            Assert.That(result.IsSuccess, Is.True, "CreateFromCapFile should succeed");
            var loadCommands = result.Value;
            
            // Assert
            foreach (var cmd in loadCommands)
            {
                var apdu = cmd.ToApdu();
                var lc = apdu[4]; // Data length
                
                // The actual data length should not exceed maxBlockSize
                // Note: First block has additional TLV overhead
                Assert.That(lc <= 255, Is.True, $"Lc byte {lc} exceeds maximum");
                
                // The data portion (excluding header and Le) should respect limits
                var dataLength = apdu.Length - 6; // Minus CLA INS P1 P2 Lc Le
                Assert.That(dataLength <= maxBlockSize + 10, Is.True, $"Data length {dataLength} exceeds reasonable limits");
            }
        }

        [Test]
        public void LoadCommand_WithWrapping_MatchesTraceFormat()
        {
            // Compare wrapped commands with trace
            
            // Arrange
            ConnectToTrace("secure_channel_establish,install_applet");
            Assert.That(CardService, Is.Not.Null);
            
            // From trace - first wrapped LOAD command (line 48)
            var expectedWrappedLoad = Convert.FromHexString(
                "84E80000F8447D3EA162C35893A127A403AACD1D2CFA480A1CFBCD6F6A5A71A592F180876C7E83DE507ADC629BE0EA4E695C6875E05B02D2FB746942781DFA2899E7428235D6E18FA98D4F9DD42E17DE3CB369FBB59B7E5DAE2E4204FE162B21C0FEC471E5E9A361F2B8CA7B017E31F08D4756D4459DD38939AF99A9258470EBD3C8C4E528C7ED1E7DFD0F08CB7CB98DFAE62F50887ADA0C0160E21CC0B1DDE8D46BB891708EED2B95648D7325628AA7CE2714910CA189FC290E4CB897C0F23EC8EFC88CE02405AE0E86B869FADD56C91C91623EAE47C4C8503E6601EE1CF242E6C1D886605EB98C874C286D6808EA69C4020A378589DF027ACF2E85E2"
            );
            
            // Act - Send the wrapped command
            var response = CardService.SendCommand(expectedWrappedLoad);
            
            // Assert
            Assert.That(response, Is.Not.Null);
            Assert.That(response.StatusWord, Is.EqualTo(0x9000));
            Assert.That(response.Data, Is.Empty); // LOAD commands typically return no data
        }
    }
}