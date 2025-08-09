using System;
using System.Linq;
using AwesomeAssertions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

/// <summary>
/// Tests for the LoadCommand class.
/// </summary>
[TestFixture]
[Category("Unit")]
public class LoadCommandTests
{

    [Test]
    public void Create_ValidParameters_CreatesInstance()
    {
        var data = Convert.FromHexString("DEADBEEF");

        var result = LoadCommand.Create((byte)0, data, false);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.BlockNumber.Should().Be(0);
        command.Data.Should().BeEquivalentTo(data);
        command.Type.Should().Be(LoadCommand.LoadType.Continuation);
        command.TotalCapSize.Should().Be(4); // Length of data
        command.IsFirstBlock.Should().BeTrue();
        command.IsFinalBlock.Should().BeFalse();
    }

    [Test]
    public void Create_FinalBlock_SetsFinalType()
    {
        var data = Convert.FromHexString("DEADBEEF");

        var result = LoadCommand.Create((byte)1, data, true);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.Type.Should().Be(LoadCommand.LoadType.Final);
        command.IsFinalBlock.Should().BeTrue();
    }

    [Test]
    public void Create_NullData_ReturnsFailure()
    {
        var result = LoadCommand.Create((byte)0, data: null!, false);

        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<SmartCardError>();
        result.Error.Message.Should().Contain("null");
        // This should ideally be NullParameterError for null parameter validation
    }

    [Test]
    public void Create_EmptyData_ReturnsFailure()
    {
        var result = LoadCommand.Create((byte)0, [], false);

        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<SmartCardError>();
        result.Error.Message.Should().Contain("empty");
        // This should ideally be EmptyDataError for empty data validation
    }

    [Test]
    public void Create_FirstBlock_IncludesTotalCapSize()
    {
        var data = Convert.FromHexString("DEADBEEF");

        var result = LoadCommand.Create((byte)0, data, false);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.TotalCapSize.Should().Be(4);
    }

    [Test]
    public void Create_NonFirstBlock_NoTotalCapSize()
    {
        var data = Convert.FromHexString("DEADBEEF");

        var result = LoadCommand.Create((byte)1, data, false);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.TotalCapSize.Should().BeNull();
    }

    [Test]
    public void CreateFromCapFile_SmallCapFile_CreatesSingleCommand()
    {
        var capData = Convert.FromHexString("DEADBEEFCAFEBABE");

        var result = LoadCommand.CreateFromCapFile(capData, 255);

        result.IsSuccess.Should().BeTrue();
        var commands = result.Value;
        commands.Should().HaveCount(1);
        commands[0].BlockNumber.Should().Be(0);
        commands[0].IsFirstBlock.Should().BeTrue();
        commands[0].IsFinalBlock.Should().BeTrue();
        commands[0].TotalCapSize.Should().Be(8);
        commands[0].Data.Should().BeEquivalentTo(capData);
    }

    [Test]
    public void CreateFromCapFile_LargeCapFile_CreatesMultipleCommands()
    {
        var capData = new byte[500]; // Large enough to require multiple blocks
        for (var i = 0; i < capData.Length; i++)
        {
            capData[i] = (byte)(i % 256);
        }

        var result = LoadCommand.CreateFromCapFile(capData, 200);

        result.IsSuccess.Should().BeTrue();
        var commands = result.Value;
        commands.Count.Should().BeGreaterThan(1);

        // Check first block
        commands[0].BlockNumber.Should().Be(0);
        commands[0].IsFirstBlock.Should().BeTrue();
        commands[0].IsFinalBlock.Should().BeFalse();
        commands[0].TotalCapSize.Should().Be(500);

        // Check last block
        var lastCommand = commands[^1];
        lastCommand.BlockNumber.Should().Be((byte)(commands.Count - 1));
        lastCommand.IsFirstBlock.Should().BeFalse();
        lastCommand.IsFinalBlock.Should().BeTrue();
        lastCommand.TotalCapSize.Should().BeNull();

        // Check intermediate blocks
        for (var i = 1; i < commands.Count - 1; i++)
        {
            commands[i].BlockNumber.Should().Be((byte)i);
            commands[i].IsFirstBlock.Should().BeFalse();
            commands[i].IsFinalBlock.Should().BeFalse();
            commands[i].TotalCapSize.Should().BeNull();
        }
    }

    [Test]
    public void CreateFromCapFile_RespectsMaxBlockSize()
    {
        var capData = new byte[100];
        var maxBlockSize = 30;

        var result = LoadCommand.CreateFromCapFile(capData, maxBlockSize);

        result.IsSuccess.Should().BeTrue();
        var commands = result.Value;
        foreach (var command in commands)
        {
            command.Data.Length.Should().BeLessThanOrEqualTo(maxBlockSize);
        }
    }

    [Test]
    public void CreateFromCapFile_ReconstructedDataMatchesOriginal()
    {
        var capData = new byte[123]; // Odd size to test edge cases
        for (var i = 0; i < capData.Length; i++)
        {
            capData[i] = (byte)(i % 256);
        }

        var result = LoadCommand.CreateFromCapFile(capData, 50);

        result.IsSuccess.Should().BeTrue();
        var commands = result.Value;
        var reconstructed = commands.SelectMany(c => c.Data).ToArray();
        reconstructed.Should().BeEquivalentTo(capData);
    }

    [Test]
    public void CreateFromCapFile_NullData_ReturnsFailure()
    {
        byte[]? capData = null;
        var result = LoadCommand.CreateFromCapFile(capData!);

        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<SmartCardError>();
        result.Error.Message.Should().Contain("null");
        // This should ideally be NullParameterError for null parameter validation
    }

    [Test]
    public void CreateFromCapFile_EmptyData_ReturnsFailure()
    {
        var result = LoadCommand.CreateFromCapFile([]);

        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<SmartCardError>();
        result.Error.Message.Should().Contain("empty");
        // This should ideally be EmptyDataError for empty data validation
    }

    [Test]
    public void CreateFromCapFile_InvalidBlockSize_ReturnsFailure()
    {
        var capData = Convert.FromHexString("DEADBEEF");

        var result1 = LoadCommand.CreateFromCapFile(capData, 0);
        var result2 = LoadCommand.CreateFromCapFile(capData, 256);

        result1.IsFailure.Should().BeTrue();
        result1.Error.Should().BeOfType<SmartCardError>();
        result2.IsFailure.Should().BeTrue();
        result2.Error.Should().BeOfType<SmartCardError>();
    }

    [Test]
    public void ToApdu_FirstBlock_IncludesTlvHeader()
    {
        var data = Convert.FromHexString("DEADBEEF");
        var result = LoadCommand.Create((byte)0, data, false);
        var command = result.Value;

        var apdu = command.ToApdu();

        apdu[0].Should().Be(0x80); // CLA
        apdu[1].Should().Be(0xE8); // INS
        apdu[2].Should().Be(0x00); // P1 (continuation)
        apdu[3].Should().Be(0x00); // P2 (block number)

        // Data should include C4 tag and length
        var dataField = apdu.Skip(5).Take(apdu[4]).ToArray();
        dataField[0].Should().Be(0xC4); // TLV tag
        dataField[1].Should().Be(4); // Total length (actual data length)
        dataField.Skip(2).ToArray().Should().BeEquivalentTo(data); // Actual data
    }

    [Test]
    public void ToApdu_ContinuationBlock_DoesNotIncludeTlvHeader()
    {
        var data = Convert.FromHexString("DEADBEEF");
        var result = LoadCommand.Create((byte)1, data, false);
        var command = result.Value;

        var apdu = command.ToApdu();

        apdu[2].Should().Be(0x00); // P1 (continuation)
        apdu[3].Should().Be(0x01); // P2 (block number)

        // Data should be raw data without TLV header
        var dataField = apdu.Skip(5).Take(apdu[4]).ToArray();
        dataField.Should().BeEquivalentTo(data);
    }

    [Test]
    public void ToApdu_FinalBlock_SetsFinalP1()
    {
        var data = Convert.FromHexString("DEADBEEF");
        var result = LoadCommand.Create((byte)2, data, true);
        var command = result.Value;

        var apdu = command.ToApdu();

        apdu[2].Should().Be(0x80); // P1 (final)
        apdu[3].Should().Be(0x02); // P2 (block number)
    }

    [Test]
    public void ToApdu_LargeTotalSize_UsesMultiByteLengthEncoding()
    {
        // Create a large data set to trigger multi-byte length encoding
        var largeCapData = new byte[0x1234];
        for (var i = 0; i < largeCapData.Length; i++)
        {
            largeCapData[i] = (byte)(i % 256);
        }
        var result = LoadCommand.CreateFromCapFile(largeCapData, 50);
        var commands = result.Value;
        var firstCommand = commands[0]; // First block will have the TLV header

        var apdu = firstCommand.ToApdu();

        var dataField = apdu.Skip(5).Take(apdu[4]).ToArray();
        dataField[0].Should().Be(0xC4); // TLV tag
        dataField[1].Should().Be(0x82); // Length form (2 bytes follow)
        dataField[2].Should().Be(0x12); // Length high byte
        dataField[3].Should().Be(0x34); // Length low byte
    }

    [Test]
    public void ToApdu_IncludesLeField()
    {
        var data = Convert.FromHexString("DEADBEEF");
        var result = LoadCommand.Create((byte)0, data, false);
        var command = result.Value;

        var apdu = command.ToApdu();

        apdu[^1].Should().Be(0x00); // Le field
    }

    [Test]
    public void LoadResponse_Constructor_SetsProperties()
    {
        // Arrange
        var data = Convert.FromHexString("DEADBEEF");
        const ushort statusWord = 0x9000;

        // Act
        var response = new LoadResponse(data, statusWord);

        // Assert
        response.Data.Should().BeEquivalentTo(data);
        response.StatusWord.Should().Be(statusWord);
        response.IsSuccessful.Should().BeTrue();
    }

    [Test]
    public void LoadResponse_ErrorStatusWord_IsNotSuccessful()
    {
        // Arrange
        var data = Array.Empty<byte>();
        const ushort statusWord = 0x6A80;

        // Act
        var response = new LoadResponse(data, statusWord);

        // Assert
        response.IsSuccessful.Should().BeFalse();
        response.StatusWord.Should().Be(statusWord);
    }

    [Test]
    public void LoadResponse_Parse_ReturnsCorrectResponse()
    {
        // Arrange
        var data = Convert.FromHexString("DEADBEEF");
        const ushort statusWord = 0x9000;

        // Act
        var response = LoadResponse.Parse(data, statusWord);

        // Assert
        response.Data.Should().BeEquivalentTo(data);
        response.StatusWord.Should().Be(statusWord);
        response.IsSuccessful.Should().BeTrue();
    }

    [Test]
    public void LoadResponse_ParseNullData_HandlesGracefully()
    {
        // Act
        var response = LoadResponse.Parse(null, 0x9000);

        // Assert
        response.Data.Should().NotBeNull();
        response.Data.Length.Should().Be(0);
    }

    [Test]
    public void ToString_ReturnsLoad()
    {
        var data = Convert.FromHexString("DEADBEEF");
        var result = LoadCommand.Create((byte)0, data, false);
        var command = result.Value;

        var str = command.ToString();

        str.Should().Be("LOAD");
    }

    [Test]
    public void ValidateCapFile_NullData_ReturnsFalse()
    {
        // Act
        var isValid = CapFileLoader.ValidateCapFile(null);

        // Assert
        isValid.Should().BeFalse();
    }

    [Test]
    public void ValidateCapFile_EmptyData_ReturnsFalse()
    {
        // Act
        var isValid = CapFileLoader.ValidateCapFile([]);

        // Assert
        isValid.Should().BeFalse();
    }

    [Test]
    public void ValidateCapFile_TooShortData_ReturnsFalse()
    {
        // Arrange
        var shortData = new byte[5];

        // Act
        var isValid = CapFileLoader.ValidateCapFile(shortData);

        // Assert
        isValid.Should().BeFalse();
    }

    [Test]
    public void GetErrorDescription_KnownErrorCode_ReturnsDescription()
    {
        // Act
        var description = CapFileLoader.GetErrorDescription(
            CapFileLoader.ErrorCodes.IncorrectData
        );

        // Assert
        description.Should().NotBeNull();
        description.Should().Contain("Incorrect data");
    }

    [Test]
    public void GetErrorDescription_UnknownErrorCode_ReturnsUnknownMessage()
    {
        // Act
        var description = CapFileLoader.GetErrorDescription(0x1234);

        // Assert
        description.Should().Contain("Unknown error");
        description.Should().Contain("1234");
    }

    [Test]
    public void GetErrorDescription_SuccessCode_ReturnsSuccess()
    {
        // Act
        var description = CapFileLoader.GetErrorDescription(CapFileLoader.ErrorCodes.Success);

        // Assert
        description.Should().Be("Success");
    }

}
