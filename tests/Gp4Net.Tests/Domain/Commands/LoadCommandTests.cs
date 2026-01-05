using System;
using System.Collections.Generic;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

/// <summary>
/// Tests for the LoadCommand class per GlobalPlatform Card Specification v2.3.1.
/// Verifies LOAD command (INS=0xE8) behavior including C4 TLV structure.
/// </summary>
[TestFixture]
[Category("Unit")]
public class LoadCommandTests
{
    // Common test data - 4 bytes of sample data
    private static readonly byte[] TestData = Convert.FromHexString("DEADBEEF");
    private const int TestDataLength = 4;

    [Test]
    public void Create_ValidParameters_CreatesInstance()
    {
        byte[] data = TestData;

        Result<LoadCommand, SmartCardError> result = LoadCommand.Create(0, data);

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.BlockNumber.Should().Be(0);
        // First block includes TLV header per GP spec
        _ = command.Data[0].Should().Be(0xC4); // Tag
        _ = command.Data[1].Should().Be(TestDataLength); // Length
        _ = command.Data.Skip(2).Should().BeEquivalentTo(data);
        _ = command.Type.Should().Be(LoadCommand.LoadType.Continuation);
        _ = command.TotalCapSize.HasValue.Should().BeTrue();
        _ = command.TotalCapSize.Value.Should().Be((uint)TestDataLength); // Length of data
        _ = command.IsFirstBlock.Should().BeTrue();
        _ = command.IsFinalBlock.Should().BeFalse();
    }

    [Test]
    public void Create_FinalBlock_SetsFinalType()
    {
        byte[] data = TestData;

        Result<LoadCommand, SmartCardError> result = LoadCommand.Create(1, data, true);

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.Type.Should().Be(LoadCommand.LoadType.Final);
        _ = command.IsFinalBlock.Should().BeTrue();
    }

    [Test]
    public void Create_NullData_ReturnsFailure()
    {
        Result<LoadCommand, SmartCardError> result = LoadCommand.Create(0, data: null!);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("null");
        // This should ideally be NullParameterError for null parameter validation
    }

    [Test]
    public void Create_EmptyData_ReturnsFailure()
    {
        Result<LoadCommand, SmartCardError> result = LoadCommand.Create(0, []);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("empty");
        // This should ideally be EmptyDataError for empty data validation
    }

    [Test]
    public void Create_FirstBlock_IncludesTotalCapSize()
    {
        byte[] data = TestData;

        Result<LoadCommand, SmartCardError> result = LoadCommand.Create(0, data);

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.TotalCapSize.HasValue.Should().BeTrue();
        _ = command.TotalCapSize.Value.Should().Be((uint)TestDataLength);
    }

    [Test]
    public void Create_NonFirstBlock_NoTotalCapSize()
    {
        byte[] data = TestData;

        Result<LoadCommand, SmartCardError> result = LoadCommand.Create(1, data);

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.TotalCapSize.HasValue.Should().BeFalse();
    }

    [Test]
    public void CreateFromCapFile_SmallCapFile_CreatesSingleCommand()
    {
        byte[] capData = Convert.FromHexString("DEADBEEFCAFEBABE");

        Result<IList<LoadCommand>, SmartCardError> result = LoadCommand.CreateFromCapFile(
            capData,
            255
        );

        _ = result.IsSuccess.Should().BeTrue();
        var commands = result.Value;
        _ = commands.Should().HaveCount(1);
        _ = commands[0].BlockNumber.Should().Be(0);
        _ = commands[0].IsFirstBlock.Should().BeTrue();
        _ = commands[0].IsFinalBlock.Should().BeTrue();
        _ = commands[0].TotalCapSize.HasValue.Should().BeTrue();
        _ = commands[0].TotalCapSize.Value.Should().Be(8u);
        // First block includes TLV header per GP spec
        _ = commands[0].Data[0].Should().Be(0xC4); // Tag
        _ = commands[0].Data[1].Should().Be(8); // Length
        _ = commands[0].Data.Skip(2).Should().BeEquivalentTo(capData);
    }

    [Test]
    public void CreateFromCapFile_LargeCapFile_CreatesMultipleCommands()
    {
        byte[] capData = new byte[500]; // Large enough to require multiple blocks
        for (int i = 0; i < capData.Length; i++)
        {
            capData[i] = (byte)(i % 256);
        }

        Result<IList<LoadCommand>, SmartCardError> result = LoadCommand.CreateFromCapFile(
            capData,
            200
        );

        _ = result.IsSuccess.Should().BeTrue();
        var commands = result.Value;
        _ = commands.Count.Should().BeGreaterThan(1);

        // Check first block
        _ = commands[0].BlockNumber.Should().Be(0);
        _ = commands[0].IsFirstBlock.Should().BeTrue();
        _ = commands[0].IsFinalBlock.Should().BeFalse();
        _ = commands[0].TotalCapSize.HasValue.Should().BeTrue();
        _ = commands[0].TotalCapSize.Value.Should().Be(500u);

        // Check last block
        var lastCommand = commands[^1];
        _ = lastCommand.BlockNumber.Should().Be((byte)(commands.Count - 1));
        _ = lastCommand.IsFirstBlock.Should().BeFalse();
        _ = lastCommand.IsFinalBlock.Should().BeTrue();
        _ = lastCommand.TotalCapSize.HasValue.Should().BeFalse();

        // Check intermediate blocks
        for (int i = 1; i < commands.Count - 1; i++)
        {
            _ = commands[i].BlockNumber.Should().Be((byte)i);
            _ = commands[i].IsFirstBlock.Should().BeFalse();
            _ = commands[i].IsFinalBlock.Should().BeFalse();
            _ = commands[i].TotalCapSize.HasValue.Should().BeFalse();
        }
    }

    [Test]
    public void CreateFromCapFile_RespectsMaxBlockSize()
    {
        byte[] capData = new byte[100];
        int maxBlockSize = 30;

        Result<IList<LoadCommand>, SmartCardError> result = LoadCommand.CreateFromCapFile(
            capData,
            maxBlockSize
        );

        _ = result.IsSuccess.Should().BeTrue();
        var commands = result.Value;
        foreach (var command in commands)
        {
            _ = command.Data.Length.Should().BeLessThanOrEqualTo(maxBlockSize);
        }
    }

    [Test]
    public void CreateFromCapFile_ReconstructedDataMatchesOriginal()
    {
        byte[] capData = new byte[123]; // Odd size to test edge cases
        for (int i = 0; i < capData.Length; i++)
        {
            capData[i] = (byte)(i % 256);
        }

        Result<IList<LoadCommand>, SmartCardError> result = LoadCommand.CreateFromCapFile(
            capData,
            50
        );

        _ = result.IsSuccess.Should().BeTrue();
        var commands = result.Value;
        // Reconstruct data, skipping TLV header from first block
        byte[] reconstructed =
        [
            .. commands.SelectMany(
                (c, index) =>
                    index == 0 && c.IsFirstBlock
                        ? c.Data.Skip(2) // Skip C4 tag and length bytes
                        : c.Data
            )
        ];
        _ = reconstructed.Should().BeEquivalentTo(capData);
    }

    [Test]
    public void CreateFromCapFile_NullData_ReturnsFailure()
    {
        byte[]? capData = null;
        Result<IList<LoadCommand>, SmartCardError> result = LoadCommand.CreateFromCapFile(capData!);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("null");
        // This should ideally be NullParameterError for null parameter validation
    }

    [Test]
    public void CreateFromCapFile_EmptyData_ReturnsFailure()
    {
        Result<IList<LoadCommand>, SmartCardError> result = LoadCommand.CreateFromCapFile([]);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("empty");
        // This should ideally be EmptyDataError for empty data validation
    }

    [Test]
    public void CreateFromCapFile_InvalidBlockSize_ReturnsFailure()
    {
        byte[] capData = TestData;

        Result<IList<LoadCommand>, SmartCardError> result1 = LoadCommand.CreateFromCapFile(
            capData,
            0
        );
        Result<IList<LoadCommand>, SmartCardError> result2 = LoadCommand.CreateFromCapFile(
            capData,
            256
        );

        _ = result1.IsFailure.Should().BeTrue();
        _ = result1.Error.Should().BeOfType<SmartCardError>();
        _ = result2.IsFailure.Should().BeTrue();
        _ = result2.Error.Should().BeOfType<SmartCardError>();
    }

    [Test]
    public void ToApdu_FirstBlock_IncludesTlvHeader()
    {
        byte[] data = TestData;
        Result<LoadCommand, SmartCardError> result = LoadCommand.Create(0, data);
        var command = result.Value;

        var apdu = command.ToApdu().BinaryCommand;

        _ = apdu[0].Should().Be(0x80); // CLA
        _ = apdu[1].Should().Be(0xE8); // INS
        _ = apdu[2].Should().Be(0x00); // P1 (continuation)
        _ = apdu[3].Should().Be(0x00); // P2 (block number)

        // Data should include C4 tag and length
        byte[] dataField = [.. apdu.Skip(5).Take(apdu[4])];
        _ = dataField[0].Should().Be(0xC4); // TLV tag
        _ = dataField[1].Should().Be(TestDataLength); // Total length (actual data length)
        _ = dataField.Skip(2).ToArray().Should().BeEquivalentTo(data); // Actual data
    }

    [Test]
    public void ToApdu_ContinuationBlock_DoesNotIncludeTlvHeader()
    {
        byte[] data = TestData;
        Result<LoadCommand, SmartCardError> result = LoadCommand.Create(1, data);
        var command = result.Value;

        var apdu = command.ToApdu().BinaryCommand;

        _ = apdu[2].Should().Be(0x00); // P1 (continuation)
        _ = apdu[3].Should().Be(0x01); // P2 (block number)

        // Data should be raw data without TLV header
        byte[] dataField = [.. apdu.Skip(5).Take(apdu[4])];
        _ = dataField.Should().BeEquivalentTo(data);
    }

    [Test]
    public void ToApdu_FinalBlock_SetsFinalP1()
    {
        byte[] data = TestData;
        Result<LoadCommand, SmartCardError> result = LoadCommand.Create(2, data, true);
        var command = result.Value;

        var apdu = command.ToApdu().BinaryCommand;

        _ = apdu[2].Should().Be(0x80); // P1 (final)
        _ = apdu[3].Should().Be(0x02); // P2 (block number)
    }

    [Test]
    public void ToApdu_LargeTotalSize_UsesMultiByteLengthEncoding()
    {
        // Create a large data set to trigger multi-byte length encoding
        byte[] largeCapData = new byte[0x1234];
        for (int i = 0; i < largeCapData.Length; i++)
        {
            largeCapData[i] = (byte)(i % 256);
        }
        Result<IList<LoadCommand>, SmartCardError> result = LoadCommand.CreateFromCapFile(
            largeCapData,
            50
        );
        var commands = result.Value;
        var firstCommand = commands[0]; // First block will have the TLV header

        byte[]? apdu = firstCommand.ToApdu().ToApdu().Value;

        byte[] dataField = [.. apdu.Skip(5).Take(apdu[4])];
        _ = dataField[0].Should().Be(0xC4); // TLV tag
        _ = dataField[1].Should().Be(0x82); // Length form (2 bytes follow)
        _ = dataField[2].Should().Be(0x12); // Length high byte
        _ = dataField[3].Should().Be(0x34); // Length low byte
    }

    [Test]
    public void ToApdu_IncludesLeField()
    {
        byte[] data = TestData;
        Result<LoadCommand, SmartCardError> result = LoadCommand.Create(0, data);
        var command = result.Value;

        var apdu = command.ToApdu().BinaryCommand;

        _ = apdu[^1].Should().Be(0x00); // Le field
    }

    [Test]
    public void LoadResponse_ErrorStatusWord_IsNotSuccessful()
    {
        // Arrange
        byte[] data = [];
        const ushort statusWord = 0x6A80;

        // Act
        var response = new LoadResponse(data, statusWord);

        // Assert
        _ = response.IsSuccessful.Should().BeFalse();
        _ = response.StatusWord.Should().Be(statusWord);
    }

    [Test]
    public void LoadResponse_Parse_ReturnsCorrectResponse()
    {
        // Arrange
        byte[] data = TestData;
        const ushort statusWord = 0x9000;

        // Act
        var response = LoadResponse.Parse(data, statusWord);

        // Assert
        _ = response.Data.Should().BeEquivalentTo(data);
        _ = response.StatusWord.Should().Be(statusWord);
        _ = response.IsSuccessful.Should().BeTrue();
    }

    [Test]
    public void LoadResponse_ParseNullData_HandlesGracefully()
    {
        // Act
        var response = LoadResponse.Parse(null!, 0x9000);

        // Assert
        _ = response.Data.Should().NotBeNull();
        _ = response.Data.Length.Should().Be(0);
    }

    [Test]
    public void ValidateCapFile_NullData_ReturnsFalse()
    {
        // Act
        bool isValid = CapFileLoader.ValidateCapFile(null!);

        // Assert
        _ = isValid.Should().BeFalse();
    }

    [Test]
    public void ValidateCapFile_EmptyData_ReturnsFalse()
    {
        // Act
        bool isValid = CapFileLoader.ValidateCapFile([]);

        // Assert
        _ = isValid.Should().BeFalse();
    }

    [Test]
    public void ValidateCapFile_TooShortData_ReturnsFalse()
    {
        // Arrange
        byte[] shortData = new byte[5];

        // Act
        bool isValid = CapFileLoader.ValidateCapFile(shortData);

        // Assert
        _ = isValid.Should().BeFalse();
    }
}
