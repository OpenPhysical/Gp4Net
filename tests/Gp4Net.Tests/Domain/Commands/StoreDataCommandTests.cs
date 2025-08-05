using System;
using AwesomeAssertions;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using NUnit.Framework;
using CSharpFunctionalExtensions;

namespace Gp4Net.Tests.Domain.Commands;

public class StoreDataCommandTests
{
    [Test]
    public void Create_WithValidData_CreatesCommand()
    {
        // Arrange
        var data = new byte[] { 0x01, 0x02, 0x03 };

        // Act
        var result = StoreDataCommand.Create(data);

        // Assert
        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.StructureFormat.Should().Be(StoreDataCommand.DataStructureFormat.Plain);
        command.Block.Should().Be(StoreDataCommand.BlockFormat.FirstOrOnly);
        command.StoreData.Should().BeEquivalentTo(data);
    }

    [Test]
    public void Create_WithNullData_ReturnsError()
    {
        // Act
        var result = StoreDataCommand.Create(null!);

        // Assert
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
    }

    [Test]
    public void ToApdu_WithPlainData_ReturnsCorrectApdu()
    {
        // Arrange
        var data = new byte[] { 0x01, 0x02, 0x03 };
        var result = StoreDataCommand.Create(data);
        result.IsSuccess.Should().BeTrue();
        var command = result.Value;

        // Act
        var apdu = command.ToApdu();

        // Assert
        apdu.Should().BeEquivalentTo(new byte[] { 0x80, 0xE2, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03 });
    }

    [Test]
    public void ToApdu_WithDgiFormat_ReturnsCorrectApdu()
    {
        // Arrange - Use CreateDefaultKeyVersionCommand which creates DGI format
        var result = StoreDataCommand.CreateDefaultKeyVersionCommand(0x01);
        result.IsSuccess.Should().BeTrue();
        var command = result.Value;

        // Act
        var apdu = command.ToApdu();

        // Assert
        apdu[0].Should().Be(0x80); // CLA
        apdu[1].Should().Be(0xE2); // INS
        apdu[2].Should().Be(0x80); // P1 (DGI format)
        apdu[3].Should().Be(0x00); // P2 (First or only block)
        apdu[4].Should().Be(0x04); // LC
        apdu[5..].Should().BeEquivalentTo(new byte[] { 0x7F, 0x0D, 0x01, 0x01 }); // Data
    }


    [Test]
    public void CreateDefaultKeyVersionCommand_CreatesCorrectCommand()
    {
        // Arrange
        byte keyVersion = 0x01;

        // Act
        var result = StoreDataCommand.CreateDefaultKeyVersionCommand(keyVersion);

        // Assert
        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.StructureFormat.Should().Be(StoreDataCommand.DataStructureFormat.Dgi);
        command.Block.Should().Be(StoreDataCommand.BlockFormat.FirstOrOnly);

        var data = command.StoreData;
        data.Should().BeEquivalentTo(new byte[] { 0x7F, 0x0D, 0x01, 0x01 });
    }

    [Test]
    public void IApduCommand_Properties_ReturnCorrectValues()
    {
        // Arrange
        var result = StoreDataCommand.CreateWithFormat(
            StoreDataCommand.DataStructureFormat.BerTlv,
            StoreDataCommand.BlockFormat.MoreBlocks,
            new byte[] { 0x01 }
        );
        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        var iapdu = (IApduCommand)command;

        // Assert
        iapdu.Cla.Should().Be(0x80);
        iapdu.Ins.Should().Be(0xE2);
        iapdu.P1.Should().Be(0x60); // BER-TLV format
        iapdu.P2.Should().Be(0x01); // More blocks
        iapdu.Data.Should().NotBeNull();
        iapdu.Data.Should().BeEquivalentTo(new byte[] { 0x01 });
        iapdu.ExpectedResponseLength.Should().BeNull();
        iapdu.IsExtendedLength.Should().BeFalse();
    }

    [Test]
    public void ToString_ReturnsStoreData()
    {
        // Arrange
        var result = StoreDataCommand.Create(new byte[] { 0x01 });
        result.IsSuccess.Should().BeTrue();
        var command = result.Value;

        // Act
        var str = command.ToString();

        // Assert
        str.Should().BeEquivalentTo("STORE DATA");
    }

    [Test]
    public void StoreDataResponse_Parse_ReturnsSuccessfulResponse()
    {
        // Arrange
        var responseData = Array.Empty<byte>();

        // Act
        var response = StoreDataResponse.Parse(responseData);

        // Assert
        response.Success.Should().BeTrue();
    }
}
