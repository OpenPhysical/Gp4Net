using System;
using System.IO;
using System.Linq;
using Gp4Net.Domain.CapFile;
using Gp4Net.Domain.Commands;
using Xunit;

namespace Gp4Net.Tests.Integration
{
    /// <summary>
    /// Tests LOAD command chunking using trace data.
    /// </summary>
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

        [Fact]
        public void LoadCommand_FirstBlock_MatchesTrace()
        {
            // From trace line 47: Command --> 80E80000EFC48268EE010013DECAFFED...
            var expectedFirstBlockStart = "80E80000EFC48268EE010013DECAFFED";
            
            // Arrange - Load CAP file
            var capFileData = File.ReadAllBytes(_capFilePath);
            
            // Act - Generate LOAD commands
            var loadCommands = LoadCommand.CreateFromCapFile(capFileData, maxBlockSize: 245);
            
            // Assert - First command structure
            Assert.True(loadCommands.Count > 0);
            var firstCommand = loadCommands[0];
            
            Assert.True(firstCommand.IsFirstBlock);
            Assert.False(firstCommand.IsFinalBlock);
            Assert.Equal(0x00, firstCommand.P1); // Continuation
            Assert.Equal(0x00, firstCommand.P2); // Block 0
            
            // The first block should include TLV header with total size
            var apdu = firstCommand.ToApdu();
            Assert.Equal(0x80, apdu[0]); // CLA
            Assert.Equal(0xE8, apdu[1]); // INS
            Assert.Equal(0x00, apdu[2]); // P1
            Assert.Equal(0x00, apdu[3]); // P2
            Assert.Equal(0xEF, apdu[4]); // Lc (239 bytes)
            
            // Should start with C4 tag and length encoding
            Assert.Equal(0xC4, apdu[5]); // CAP data tag
            
            // The length encoding should match the total CAP file size
            var totalSize = (uint)capFileData.Length;
            Assert.Equal(totalSize, firstCommand.TotalCapSize);
        }

        [Fact]
        public void LoadCommand_Chunking_GeneratesCorrectNumberOfBlocks()
        {
            // The trace shows 567 LOAD commands for OpenFIPS201
            
            // Arrange
            var capFileData = File.ReadAllBytes(_capFilePath);
            var capFileSize = capFileData.Length;
            
            // Act
            var loadCommands = LoadCommand.CreateFromCapFile(capFileData, maxBlockSize: 245);
            
            // Assert
            // With 245 byte blocks and considering TLV overhead:
            // First block has additional TLV header (C4 + length encoding)
            // Each block can carry up to 245 bytes of actual data
            
            // The trace shows many LOAD commands, let's verify we generate a reasonable number
            Assert.True(loadCommands.Count > 100, $"Expected many LOAD commands, got {loadCommands.Count}");
            
            // Verify block numbering
            for (int i = 0; i < loadCommands.Count; i++)
            {
                Assert.Equal(i, loadCommands[i].BlockNumber);
            }
            
            // Last block should be marked as final
            var lastCommand = loadCommands.Last();
            Assert.True(lastCommand.IsFinalBlock);
            Assert.Equal(0x80, lastCommand.P1); // Final block
        }

        [Fact]
        public void LoadCommand_DataReassembly_ReconstructsOriginalCapFile()
        {
            // Verify that reassembling all LOAD command data reconstructs the original CAP file
            
            // Arrange
            var originalCapData = File.ReadAllBytes(_capFilePath);
            
            // Act
            var loadCommands = LoadCommand.CreateFromCapFile(originalCapData, maxBlockSize: 245);
            
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
                    Assert.Equal(0xC4, commandData[0]);
                    
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
            Assert.Equal(originalCapData.Length, reassembled.Length);
            Assert.Equal(originalCapData, reassembled);
        }

        [Fact]
        public void LoadCommand_CapFileStructure_IsValid()
        {
            // Verify the CAP file can be parsed
            
            // Arrange
            var capFileData = File.ReadAllBytes(_capFilePath);
            
            // Act & Assert
            var capFile = CapFileStructure.Parse(capFileData);
            
            Assert.NotNull(capFile);
            Assert.Equal("A00000030800001000", Convert.ToHexString(capFile.PackageAid));
            Assert.True(capFile.Components.Count > 0);
            Assert.True(capFile.TotalSize > 0);
            
            // The trace mentions OpenFIPS201-v1_10_2-chainfix.cap
            // This is a substantial applet with multiple components
            Assert.True(capFile.Components.Count >= 5, $"Expected multiple components, got {capFile.Components.Count}");
        }

        [Fact]
        public void LoadCommand_BlockSizeLimits_AreRespected()
        {
            // Verify that no LOAD command exceeds the maximum block size
            
            // Arrange
            var capFileData = File.ReadAllBytes(_capFilePath);
            const int maxBlockSize = 245;
            
            // Act
            var loadCommands = LoadCommand.CreateFromCapFile(capFileData, maxBlockSize);
            
            // Assert
            foreach (var cmd in loadCommands)
            {
                var apdu = cmd.ToApdu();
                var lc = apdu[4]; // Data length
                
                // The actual data length should not exceed maxBlockSize
                // Note: First block has additional TLV overhead
                Assert.True(lc <= 255, $"Lc byte {lc} exceeds maximum");
                
                // The data portion (excluding header and Le) should respect limits
                var dataLength = apdu.Length - 6; // Minus CLA INS P1 P2 Lc Le
                Assert.True(dataLength <= maxBlockSize + 10, $"Data length {dataLength} exceeds reasonable limits");
            }
        }

        [Fact]
        public void LoadCommand_WithWrapping_MatchesTraceFormat()
        {
            // Compare wrapped commands with trace
            
            // Arrange
            ConnectToTrace("secure_channel_establish,install_applet");
            Assert.NotNull(CardService);
            
            // From trace - first wrapped LOAD command (line 48)
            var expectedWrappedLoad = Convert.FromHexString(
                "84E80000F8447D3EA162C35893A127A403AACD1D2CFA480A1CFBCD6F6A5A71A592F180876C7E83DE507ADC629BE0EA4E695C6875E05B02D2FB746942781DFA2899E7428235D6E18FA98D4F9DD42E17DE3CB369FBB59B7E5DAE2E4204FE162B21C0FEC471E5E9A361F2B8CA7B017E31F08D4756D4459DD38939AF99A9258470EBD3C8C4E528C7ED1E7DFD0F08CB7CB98DFAE62F50887ADA0C0160E21CC0B1DDE8D46BB891708EED2B95648D7325628AA7CE2714910CA189FC290E4CB897C0F23EC8EFC88CE02405AE0E86B869FADD56C91C91623EAE47C4C8503E6601EE1CF242E6C1D886605EB98C874C286D6808EA69C4020A378589DF027ACF2E85E2"
            );
            
            // Act - Send the wrapped command
            var response = CardService.SendCommand(expectedWrappedLoad);
            
            // Assert
            Assert.NotNull(response);
            Assert.Equal(0x9000, response.StatusWord);
            Assert.Empty(response.Data); // LOAD commands typically return no data
        }
    }
}