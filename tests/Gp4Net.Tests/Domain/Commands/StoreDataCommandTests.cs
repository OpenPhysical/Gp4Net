using System;
using System.Collections.Generic;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands
{
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
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;
            Assert.That(command.StructureFormat, Is.EqualTo(StoreDataCommand.DataStructureFormat.Plain));
            Assert.That(command.Block, Is.EqualTo(StoreDataCommand.BlockFormat.FirstOrOnly));
            Assert.That(command.StoreData, Is.EqualTo(data));
        }

        [Test]
        public void Create_WithNullData_ReturnsError()
        {
            // Act
            var result = StoreDataCommand.Create(null!);

            // Assert
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Code, Is.EqualTo("INVALID_ARGUMENT"));
        }

        [Test]
        public void ToApdu_WithPlainData_ReturnsCorrectApdu()
        {
            // Arrange
            var data = new byte[] { 0x01, 0x02, 0x03 };
            var result = StoreDataCommand.Create(data);
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;

            // Act
            var apdu = command.ToApdu();

            // Assert
            Assert.That(apdu, Is.EqualTo(new byte[] { 0x80, 0xE2, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03 }));
        }

        [Test]
        public void ToApdu_WithDgiFormat_ReturnsCorrectApdu()
        {
            // Arrange - Use CreateDefaultKeyVersionCommand which creates DGI format
            var result = StoreDataCommand.CreateDefaultKeyVersionCommand(0x01);
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;

            // Act
            var apdu = command.ToApdu();

            // Assert
            Assert.That(apdu[0], Is.EqualTo(0x80)); // CLA
            Assert.That(apdu[1], Is.EqualTo(0xE2)); // INS
            Assert.That(apdu[2], Is.EqualTo(0x80)); // P1 (DGI format)
            Assert.That(apdu[3], Is.EqualTo(0x00)); // P2 (First or only block)
            Assert.That(apdu[4], Is.EqualTo(0x04)); // LC
            Assert.That(apdu[5..], Is.EqualTo(new byte[] { 0x7F, 0x0D, 0x01, 0x01 })); // Data
        }


        [Test]
        public void CreateDefaultKeyVersionCommand_CreatesCorrectCommand()
        {
            // Arrange
            byte keyVersion = 0x01;

            // Act
            var result = StoreDataCommand.CreateDefaultKeyVersionCommand(keyVersion);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;
            Assert.That(command.StructureFormat, Is.EqualTo(StoreDataCommand.DataStructureFormat.Dgi));
            Assert.That(command.Block, Is.EqualTo(StoreDataCommand.BlockFormat.FirstOrOnly));

            var data = command.StoreData;
            Assert.That(data, Is.EqualTo(new byte[] { 0x7F, 0x0D, 0x01, 0x01 }));
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
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;
            var iapdu = (IApduCommand)command;

            // Assert
            Assert.That(iapdu.Cla, Is.EqualTo(0x80));
            Assert.That(iapdu.Ins, Is.EqualTo(0xE2));
            Assert.That(iapdu.P1, Is.EqualTo(0x60)); // BER-TLV format
            Assert.That(iapdu.P2, Is.EqualTo(0x01)); // More blocks
            Assert.That(iapdu.Data, Is.Not.Null);
            Assert.That(iapdu.Data, Is.EqualTo(new byte[] { 0x01 }));
            Assert.That(iapdu.ExpectedResponseLength, Is.Null);
            Assert.That(iapdu.IsExtendedLength, Is.False);
        }

        [Test]
        public void ToString_ReturnsStoreData()
        {
            // Arrange
            var result = StoreDataCommand.Create(new byte[] { 0x01 });
            Assert.That(result.IsSuccess, Is.True);
            var command = result.Value;

            // Act
            var str = command.ToString();

            // Assert
            Assert.That(str, Is.EqualTo("STORE DATA"));
        }

        [Test]
        public void StoreDataResponse_Parse_ReturnsSuccessfulResponse()
        {
            // Arrange
            var responseData = Array.Empty<byte>();

            // Act
            var response = StoreDataResponse.Parse(responseData);

            // Assert
            Assert.That(response.Success, Is.True);
        }
    }
}
