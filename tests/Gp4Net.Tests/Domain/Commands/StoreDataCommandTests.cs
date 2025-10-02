using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

public class StoreDataCommandTests
{
    [Test]
    public void Create_WithValidData_CreatesCommand()
    {
        // Arrange
        byte[] data = [0x01, 0x02, 0x03];

        // Act
        Result<StoreDataCommand, SmartCardError> result = StoreDataCommand.Create(data);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.StructureFormat.Should().Be(StoreDataCommand.DataStructureFormat.Plain);
        _ = command.Block.Should().Be(StoreDataCommand.BlockFormat.FirstOrOnly);
        _ = command.StoreData.Should().BeEquivalentTo(data);
    }

    [Test]
    public void ToApdu_WithPlainData_ReturnsCorrectApdu()
    {
        // Arrange
        byte[] data = [0x01, 0x02, 0x03];

        // Act
        Result<byte[], SmartCardError> apduResult = StoreDataCommand
            .Create(data)
            .Bind(command => ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(command)));

        // Assert
        _ = apduResult.IsSuccess.Should().BeTrue();
        if (apduResult.IsSuccess)
        {
            byte[] apdu = apduResult.Value;
            _ = apdu.Should()
                .BeEquivalentTo(new byte[] { 0x80, 0xE2, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03 });
        }
    }

    [Test]
    public void ToApdu_WithDgiFormat_ReturnsCorrectApdu()
    {
        // Arrange - Use CreateDefaultKeyVersionCommand which creates DGI format
        Result<StoreDataCommand, SmartCardError> result =
            StoreDataCommand.CreateDefaultKeyVersionCommand(0x01);
        _ = result.IsSuccess.Should().BeTrue();

        if (result.IsSuccess)
        {
            var command = result.Value;

            // Act
            Result<byte[], SmartCardError> apduResult = ApduBuilder.BuildApdu(
                Maybe<IApduCommand>.From(command)
            );
            _ = apduResult.IsSuccess.Should().BeTrue();
            if (apduResult.IsSuccess)
            {
                byte[] apdu = apduResult.Value;

                // Assert
                _ = apdu[0].Should().Be(0x80); // CLA
                _ = apdu[1].Should().Be(0xE2); // INS
                _ = apdu[2].Should().Be(0x80); // P1 (DGI format)
                _ = apdu[3].Should().Be(0x00); // P2 (First or only block)
                _ = apdu[4].Should().Be(0x04); // LC
                _ = apdu[5..].Should().BeEquivalentTo(new byte[] { 0x7F, 0x0D, 0x01, 0x01 }); // Data
            }
        }
    }

    [Test]
    public void CreateDefaultKeyVersionCommand_CreatesCorrectCommand()
    {
        // Arrange
        byte keyVersion = 0x01;

        // Act
        Result<StoreDataCommand, SmartCardError> result =
            StoreDataCommand.CreateDefaultKeyVersionCommand(keyVersion);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        if (result.IsSuccess)
        {
            var command = result.Value;
            _ = command.StructureFormat.Should().Be(StoreDataCommand.DataStructureFormat.Dgi);
            _ = command.Block.Should().Be(StoreDataCommand.BlockFormat.FirstOrOnly);

            byte[] data = command.StoreData;
            _ = data.Should().BeEquivalentTo(new byte[] { 0x7F, 0x0D, 0x01, 0x01 });
        }
    }

    [Test]
    public void IApduCommand_Properties_ReturnCorrectValues()
    {
        // Arrange
        Result<StoreDataCommand, SmartCardError> result = StoreDataCommand.CreateWithFormat(
            StoreDataCommand.DataStructureFormat.BerTlv,
            StoreDataCommand.BlockFormat.MoreBlocks,
            [0x01]
        );
        _ = result.IsSuccess.Should().BeTrue();
        if (result.IsSuccess)
        {
            var command = result.Value;
            IApduCommand iapdu = command;
            byte[] apduBytes = iapdu.ToBytes();

            // Assert - Verify APDU byte structure
            _ = apduBytes[0].Should().Be(0x80); // CLA
            _ = apduBytes[1].Should().Be(0xE2); // INS
            _ = apduBytes[2].Should().Be(0x60); // P1 (BER-TLV format)
            _ = apduBytes[3].Should().Be(0x01); // P2 (More blocks)
            _ = apduBytes[4].Should().Be(0x01); // LC (data length)
            _ = apduBytes[5].Should().Be(0x01); // Data
        }
    }

    [Test]
    public void ToString_ReturnsStoreData()
    {
        // Arrange
        Result<StoreDataCommand, SmartCardError> result = StoreDataCommand.Create([0x01]);
        _ = result.IsSuccess.Should().BeTrue();
        if (result.IsSuccess)
        {
            var command = result.Value;

            // Act
            string str = command.ToString();

            // Assert
            _ = str.Should().BeEquivalentTo("STORE DATA");
        }
    }

    [Test]
    public void StoreDataResponse_Parse_ReturnsSuccessfulResponse()
    {
        // Arrange
        byte[] responseData = [];

        // Act
        var response = StoreDataResponse.Parse(responseData);

        // Assert
        _ = response.Success.Should().BeTrue();
    }
}
