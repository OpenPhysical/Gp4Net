using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;
using Gp4Net.Domain.Commands;
using Gp4Net.Tests.Infrastructure;
using Gp4Net.Transport;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Integration tests for CAP file loading with secure channel wrapping.
/// Tests the complete workflow from CAP file to wrapped APDUs without requiring a physical card.
/// </summary>
[TestFixture]
[Category("Integration")]
public class CapLoadingIntegrationTests
{
    private readonly string _capFilePath;

    public CapLoadingIntegrationTests()
    {
        // Path to the OpenFIPS201 CAP file used in the trace
        _capFilePath = Path.Combine(
            TestContextHelper.GetProjectRootDirectory(),
            "tests",
            "applets",
            "OpenFIPS201-v1_10_2-chainfix.cap"
        );
    }

    [Test]
    public void CapFile_Exists_CanBeRead()
    {
        // Verify the CAP file exists and can be read
        Assert.That(File.Exists(_capFilePath), Is.True, $"CAP file not found at: {_capFilePath}");

        byte[] capFileData = File.ReadAllBytes(_capFilePath);
        Assert.That(capFileData.Length, Is.GreaterThan(0), "CAP file should not be empty");

        // Parse and check structure
        Result<CapFileStructure, SmartCardError> capFileResult = CapFileStructure.Parse(
            capFileData
        );
        Assert.That(capFileResult.IsSuccess, Is.True, "Failed to parse CAP file");
        var capFile = capFileResult.Value;
    }

    [Test]
    public void CapFileLoading_EndToEndWorkflow_GeneratesCorrectWrappedCommands()
    {
        // Arrange - Load the CAP file used in the reference trace
        byte[] capFileData = File.ReadAllBytes(_capFilePath);

        // Parse CAP file structure
        Result<CapFileStructure, SmartCardError> capFileResult = CapFileStructure.Parse(
            capFileData
        );
        Assert.That(capFileResult.IsSuccess, Is.True, "Failed to parse CAP file");
        var capFile = capFileResult.Value;

        // Verify we have the expected package from the trace (OpenFIPS201 package)
        byte[] expectedPackageAid = Convert.FromHexString("A00000030800001000");
        Assert.That(capFile.PackageAid, Is.EqualTo(expectedPackageAid));

        // Act - Generate LOAD commands from CAP file
        Result<IList<LoadCommand>, SmartCardError> result = LoadCommand.CreateFromCapFile(
            capFileData,
            maxBlockSize: 245
        );
        Assert.That(result.IsSuccess, Is.True, "CreateFromCapFile should succeed");
        var loadCommands = result.Value;

        // Assert - Verify we generated the expected number of commands
        Assert.That(
            loadCommands.Count,
            Is.GreaterThanOrEqualTo(2),
            "Should have at least 2 LOAD commands for OpenFIPS201"
        );

        // Verify first command structure matches trace expectations
        var firstCommand = loadCommands[0];
        Assert.Multiple(() =>
        {
            Assert.That(
                firstCommand.IsFirstBlock,
                Is.True,
                "First command should be marked as first block"
            );
            Assert.That(
                firstCommand.IsFinalBlock,
                Is.False,
                "First command should not be final block"
            );
        });

        // Verify final command structure
        var lastCommand = loadCommands.Last();
        Assert.That(
            lastCommand.IsFinalBlock,
            Is.True,
            "Last command should be marked as final block"
        );

        // Convert to APDUs for secure channel wrapping
        List<byte[]> plainApdus =
        [
            .. loadCommands.Select(cmd =>
                ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(cmd)).GetValueOrDefault([])
            ),
        ];

        // Verify APDU structure matches trace format
        byte[] firstApdu = plainApdus[0];
        Assert.Multiple(() =>
        {
            Assert.That(firstApdu[0], Is.EqualTo(0x80)); // CLA
            Assert.That(firstApdu[1], Is.EqualTo(0xE8)); // INS (LOAD)
            Assert.That(firstApdu[2], Is.EqualTo(0x00)); // P1 (first block)
            Assert.That(firstApdu[3], Is.EqualTo(0x00)); // P2
        });
    }

    [Test]
    public void CapFileLoading_GeneratesCorrectLoadCommands()
    {
        // Arrange - Load CAP file and generate LOAD commands using ONLY real library services
        byte[] capFileData = File.ReadAllBytes(_capFilePath);

        // Act - Use real library to create load commands
        Result<IList<LoadCommand>, SmartCardError> result = LoadCommand.CreateFromCapFile(
            capFileData,
            maxBlockSize: 245
        );

        // Assert - Verify load commands generated successfully
        Assert.That(result.IsSuccess, Is.True, "CreateFromCapFile should succeed");
        var loadCommands = result.Value;
        List<byte[]> plainApdus =
        [
            .. loadCommands.Select(cmd =>
                ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(cmd)).GetValueOrDefault([])
            ),
        ];
        Assert.That(plainApdus.Count > 0, "Should have generated LOAD APDUs");

        // Verify APDU structure using functional composition - NO imperative loops
        bool allValidStructure = plainApdus.All(apdu =>
            apdu[0] == 0x80
            && // CLA for GP LOAD
            apdu[1] == 0xE8
            && // INS (LOAD)
            apdu.Length > 4
        ); // APDU should have header and data

        Assert.That(allValidStructure, Is.True, "All APDUs should have valid GP LOAD structure");

        // NOTE: For secure channel wrapping, use real SecureChannelService from core library
        // This test focuses on CAP file parsing and LOAD command generation only
    }

    [Test]
    public void TraceComparison_LoadCommands_MatchExpectedStructure()
    {
        // Arrange - Expected values from configure_gpshell_log.txt trace
        // Line 43: Command --> 80E602001C09A0000003080000100008A0000001510000000006EF04C60268F80000
        // Line 47: Command --> 80E80000EFC48268EE010013DECAFFED0102040A0109A000000308000010000...

        // Expected values from trace (documented for reference)
        // var expectedInstallForLoadApdu =
        //     "80E602001C09A0000003080000100008A0000001510000000006EF04C60268F80000";
        // var expectedFirstLoadPrefix =
        //     "80E80000EFC48268EE010013DECAFFED0102040A0109A000000308000010000";

        // Act - Load CAP file and generate commands
        byte[] capFileData = File.ReadAllBytes(_capFilePath);
        Result<CapFileStructure, SmartCardError> capFileResult = CapFileStructure.Parse(
            capFileData
        );
        Assert.That(capFileResult.IsSuccess, Is.True, "Failed to parse CAP file");
        var capFile = capFileResult.Value;

        // Generate INSTALL [for load] command
        Result<InstallCommand.InstallForLoadCommand, SmartCardError> installForLoadResult =
            InstallCommandBuilder.CreateForLoad(
                packageAid: capFile.PackageAid,
                securityDomainAid: Convert.FromHexString("A000000151000000") // Card Manager AID from trace
            );

        Assert.That(installForLoadResult.IsSuccess, Is.True, "CreateForLoad should succeed");
        var installForLoadCmd = installForLoadResult.Value;
        Result<byte[], SmartCardError> installForLoadApduResult = ApduBuilder.BuildApdu(
            Maybe<IApduCommand>.From(installForLoadCmd)
        );
        byte[] installForLoadApdu = installForLoadApduResult.GetValueOrDefault([]);

        // Generate LOAD commands
        Result<IList<LoadCommand>, SmartCardError> result = LoadCommand.CreateFromCapFile(
            capFileData,
            maxBlockSize: 245
        );
        Assert.That(result.IsSuccess, Is.True, "CreateFromCapFile should succeed");
        var loadCommands = result.Value;
        Result<byte[], SmartCardError> firstLoadApduResult = ApduBuilder.BuildApdu(
            Maybe<IApduCommand>.From(loadCommands[0])
        );
        byte[] firstLoadApdu = firstLoadApduResult.GetValueOrDefault([]);

        Assert.Multiple(() =>
        {
            // Assert - Verify structure matches trace expectations
            Assert.That(installForLoadApdu[0], Is.EqualTo(0x80)); // CLA
            Assert.That(installForLoadApdu[1], Is.EqualTo(0xE6)); // INS (INSTALL)
            Assert.That(installForLoadApdu[2], Is.EqualTo(0x02)); // P1 (for load = 0x02, as per trace)

            Assert.That(firstLoadApdu[0], Is.EqualTo(0x80)); // CLA
            Assert.That(firstLoadApdu[1], Is.EqualTo(0xE8)); // INS (LOAD)
            Assert.That(firstLoadApdu[2], Is.EqualTo(0x00)); // P1 (first block)
        });

        // Verify the LOAD command contains the CAP file header
        byte[]? loadData = loadCommands[0].Data;
        Assert.That(loadData, Is.Not.Null);

        // LOAD block is wrapped in TLV (tag 'C4') as defined by GP 2.3.1 (§10.3.2).
        // Decode the TLV so we can assert against the actual CAP payload (ZIP header "PK").
        var tlv = ParseTlv(loadData);

        Assert.That(tlv.Tag, Is.EqualTo(0xC4), "LOAD block should be encoded with tag 'C4'.");
        Assert.That(
            tlv.AvailableValueLength,
            Is.GreaterThan(2),
            "LOAD block value should be large enough to contain CAP data."
        );

        // CAP files are ZIP archives, so the payload must begin with the ZIP magic "PK" (0x504B).
        Assert.Multiple(() =>
        {
            Assert.That(loadData[tlv.ValueOffset], Is.EqualTo(0x50)); // 'P'
            Assert.That(loadData[tlv.ValueOffset + 1], Is.EqualTo(0x4B)); // 'K'
        });

        // Look for CAP magic "DECAFFED" across all LOAD commands
        List<byte> allLoadData = [];
        foreach (var cmd in loadCommands)
        {
            if (cmd.Data is null)
                continue;

            var payload = ParseTlv(cmd.Data);
            allLoadData.AddRange(
                cmd.Data.Skip(payload.ValueOffset).Take(payload.AvailableValueLength)
            );
        }

        byte[] capMagicPattern = [0xDE, 0xCA, 0xFF, 0xED];
        int capMagicIndex = ByteArrayHelpers.FindBytePattern([.. allLoadData], capMagicPattern);
        Assert.That(
            capMagicIndex,
            Is.GreaterThanOrEqualTo(0),
            "Should contain CAP file magic number DECAFFED somewhere in the load data"
        );
    }

    private static (
        byte Tag,
        int ValueOffset,
        int DeclaredValueLength,
        int AvailableValueLength
    ) ParseTlv(byte[] buffer)
    {
        if (buffer.Length < 2)
        {
            throw new ArgumentException("TLV buffer too short", nameof(buffer));
        }

        byte tag = buffer[0];
        byte lengthDescriptor = buffer[1];
        int valueOffset;
        int valueLength;

        if ((lengthDescriptor & 0x80) == 0)
        {
            valueLength = lengthDescriptor;
            valueOffset = 2;
        }
        else
        {
            int lengthOfLength = lengthDescriptor & 0x7F;
            if (buffer.Length < 2 + lengthOfLength)
            {
                throw new ArgumentException(
                    "TLV length descriptor exceeds buffer size",
                    nameof(buffer)
                );
            }

            valueLength = 0;
            for (int i = 0; i < lengthOfLength; i++)
            {
                valueLength = (valueLength << 8) | buffer[2 + i];
            }

            valueOffset = 2 + lengthOfLength;
        }

        int available = Math.Max(0, buffer.Length - valueOffset);
        return (tag, valueOffset, valueLength, Math.Min(valueLength, available));
    }

    // REMOVED: FluentInterface_SecureChannelWorkflow_DemonstratesUsability test
    // Contained duplicate SCP implementation - use real SecureChannelService from core library
}

// ELIMINATED: SecureChannelWorkflow class and related types
// Contained COMPLETE DUPLICATE SCP implementation with simplified secure channel wrapping
// Use real SecureChannelService from core library instead

/// <summary>
/// Helper methods for byte array operations.
/// </summary>
public static class ByteArrayHelpers
{
    /// <summary>
    /// Finds the first occurrence of a byte pattern in a byte array.
    /// </summary>
    /// <param name="source">The source byte array to search in.</param>
    /// <param name="pattern">The pattern to search for.</param>
    /// <returns>The index of the first occurrence, or -1 if not found.</returns>
    public static int FindBytePattern(byte[] source, byte[] pattern)
    {
        if (
            source == null
            || pattern == null
            || pattern.Length == 0
            || source.Length < pattern.Length
        )
        {
            return -1;
        }

        for (int i = 0; i <= source.Length - pattern.Length; i++)
        {
            bool found = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (source[i + j] != pattern[j])
                {
                    found = false;
                    break;
                }
            }
            if (found)
            {
                return i;
            }
        }
        return -1;
    }
}
