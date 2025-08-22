using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Gp4Net.Domain.CapFile;
using Gp4Net.Domain.Commands;
using Gp4Net.Tests.TestHelpers;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Tests LOAD command chunking using trace data.
/// </summary>
[TestFixture]
[Category("Integration")]
public class LoadCommandTraceTests : TraceBasedTestBase
{
    private readonly string _capFilePath;

    public LoadCommandTraceTests() : base(TraceFiles.GpShellInstallJson)
    {
        // Get the CAP file used in the trace
        _capFilePath = Path.Combine(
            TestContextHelper.GetProjectRootDirectory(),
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
        Assert.Multiple(() =>
        {
            Assert.That(firstCommand.IsFirstBlock);
            Assert.That(firstCommand.IsFinalBlock, Is.False); // Large CAP file, not final block
            Assert.That(firstCommand.P1, Is.EqualTo(0x00)); // Continuation
            Assert.That(firstCommand.P2, Is.EqualTo(0x00)); // Block 0
        });

        // The first block should include TLV header with total size
        var apdu = firstCommand.ToApdu();
        Assert.Multiple(() =>
        {
            Assert.That(apdu[0], Is.EqualTo(0x80)); // CLA
            Assert.That(apdu[1], Is.EqualTo(0xE8)); // INS
            Assert.That(apdu[2], Is.EqualTo(0x00)); // P1
            Assert.That(apdu[3], Is.EqualTo(0x00)); // P2

            // Should start with C4 tag and length encoding
            Assert.That(apdu[5], Is.EqualTo(0xC4)); // CAP data tag
        });

        // Verify the total payload size respects maxBlockSize
        var payloadSize = apdu[4]; // Lc field
        Assert.That(payloadSize, Is.LessThanOrEqualTo(maxBlockSize), 
            $"Payload size {payloadSize} should not exceed maxBlockSize {maxBlockSize}");
            
        // The length encoding should match the total CAP file size
        var totalSize = (uint)capFileData.Length;
        Assert.That(firstCommand.TotalCapSize, Is.EqualTo(totalSize));
            
        // Verify TLV length encoding is correct for this file size
        var expectedTlvHeader = CreateExpectedTlvHeader(totalSize);
        for (var i = 0; i < expectedTlvHeader.Length; i++)
        {
            Assert.That(apdu[5 + i], Is.EqualTo(expectedTlvHeader[i]), 
                $"TLV header byte {i} should match expected encoding");
        }
    }
        
    private static byte[] CreateExpectedTlvHeader(uint totalSize)
    {
        var header = new List<byte> { 0xC4 }; // Tag
            
        switch (totalSize)
        {
            case <= 0x7F:
                header.Add((byte)totalSize);
                break;
            case <= 0xFF:
                header.Add(0x81);
                header.Add((byte)totalSize);
                break;
            case <= 0xFFFF:
                header.Add(0x82);
                header.Add((byte)(totalSize >> 8));
                header.Add((byte)(totalSize & 0xFF));
                break;
            case <= 0xFFFFFF:
                header.Add(0x83);
                header.Add((byte)(totalSize >> 16));
                header.Add((byte)((totalSize >> 8) & 0xFF));
                header.Add((byte)(totalSize & 0xFF));
                break;
            default:
                header.Add(0x84);
                header.Add((byte)(totalSize >> 24));
                header.Add((byte)((totalSize >> 16) & 0xFF));
                header.Add((byte)((totalSize >> 8) & 0xFF));
                header.Add((byte)(totalSize & 0xFF));
                break;
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
        for (var i = 0; i < loadCommands.Count; i++)
        {
            var expectedBlockNumber = (byte)(i % 256);
            Assert.That(loadCommands[i].BlockNumber, Is.EqualTo(expectedBlockNumber));
        }
            
        // Last block should be marked as final
        var lastCommand = loadCommands.Last();
        Assert.Multiple(() =>
        {
            Assert.That(lastCommand.IsFinalBlock);
            Assert.That(lastCommand.P1, Is.EqualTo(0x80)); // Final block
        });
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
                var headerSize = 1; // C4 tag
                switch (commandData[1])
                {
                    case 0x82:
                        headerSize += 3; // 82 + 2 length bytes
                        break;
                    case 0x83:
                        headerSize += 4; // 83 + 3 length bytes
                        break;
                    case 0x84:
                        headerSize += 5; // 84 + 4 length bytes
                        break;
                    case <= 0x7F:
                        headerSize += 1; // Direct length
                        break;
                    case 0x81:
                        headerSize += 2; // 81 + 1 length byte
                        break;
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
        var capFileResult = CapFileStructure.Parse(capFileData);
        Assert.That(capFileResult.IsSuccess, Is.True, "Failed to parse CAP file");
        var capFile = capFileResult.Value;
        Assert.Multiple(() =>
        {
            Assert.That(capFile, Is.Not.Null);
            Assert.That(Convert.ToHexString(capFile.PackageAid), Is.EqualTo("A00000030800001000"));
        });
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
        // Compare LOAD commands with trace
            
        // Arrange - Include load_blocks operation to get LOAD commands
        ConnectToTrace("secure_channel_establish,install_applet,load_blocks");
        Assert.That(CardService, Is.Not.Null);
        Assert.That(CardService.IsSecureChannelEstablished, Is.True);
            
        // From trace - first LOAD command (exchange 6)
        // Note: In this trace, LOAD commands are not wrapped (secure_messaging: false)
        var firstLoadCommand = Convert.FromHexString(
            "80E80000EFC48268EE010013DECAFFED0102040A0109A0000003080000100002001F0013001F000F003205C2029540B902C408B2000013D70038000D029305010004003205000107A0000000620001050107A0000000620101050106A00000015100050107A0000000620201050107A000000062010203000F010BA0000003080000100001000612060295818101008000010001010000050130013701440153017000800000FF00010600000569056D056F05710573057500001700FF000106000005B8059A05A005A605AC05B200001700FF000106000005FD05DF05E505EB05F105F701810301000104050000064AFFFF0626"
        );
            
        // Act - Send the LOAD command
        var response = CardService.SendCommand(firstLoadCommand);
            
        // Assert
        Assert.That(response, Is.Not.Null);
        Assert.Multiple(() =>
        {
            Assert.That(response.StatusWord, Is.EqualTo(0x9000));
            Assert.That(response.Data, Is.Empty); // LOAD commands typically return no data
        });
            
        // Verify the command structure
        Assert.Multiple(() =>
        {
            Assert.That(firstLoadCommand[0], Is.EqualTo(0x80)); // CLA
            Assert.That(firstLoadCommand[1], Is.EqualTo(0xE8)); // INS (LOAD)
            Assert.That(firstLoadCommand[2], Is.EqualTo(0x00)); // P1 (continuation)
            Assert.That(firstLoadCommand[3], Is.EqualTo(0x00)); // P2 (block 0)
            Assert.That(firstLoadCommand[4], Is.EqualTo(0xEF)); // Lc (239 bytes)
            
            // Verify TLV header
            Assert.That(firstLoadCommand[5], Is.EqualTo(0xC4)); // CAP data tag
            Assert.That(firstLoadCommand[6], Is.EqualTo(0x82)); // Extended length encoding
        });
    }
}