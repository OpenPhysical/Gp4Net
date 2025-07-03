using System;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using Xunit;

namespace Gp4Net.Tests.Domain.Commands
{
    public class StoreDataCommandTests
    {
        [Fact]
        public void Constructor_WithValidParameters_CreatesCommand()
        {
            // Arrange
            var structureFormat = StoreDataCommand.DataStructureFormat.Dgi;
            var block = StoreDataCommand.BlockFormat.FirstOrOnly;
            var data = new byte[] { 0x01, 0x02, 0x03 };

            // Act
            var command = new StoreDataCommand(structureFormat, block, data);

            // Assert
            Assert.Equal(structureFormat, command.StructureFormat);
            Assert.Equal(block, command.Block);
            Assert.Equal(data, command.StoreData);
        }

        [Fact]
        public void Constructor_WithNullData_ThrowsArgumentNullException()
        {
            // Act & Assert
            _ = Assert.Throws<ArgumentNullException>(
                () =>
                    new StoreDataCommand(
                        StoreDataCommand.DataStructureFormat.Plain,
                        StoreDataCommand.BlockFormat.FirstOrOnly,
                        null!
                    )
            );
        }

        [Fact]
        public void ToApdu_WithPlainData_ReturnsCorrectApdu()
        {
            // Arrange
            var data = new byte[] { 0x01, 0x02, 0x03 };
            var command = new StoreDataCommand(
                StoreDataCommand.DataStructureFormat.Plain,
                StoreDataCommand.BlockFormat.FirstOrOnly,
                data
            );

            // Act
            var apdu = command.ToApdu();

            // Assert
            Assert.Equal(new byte[] { 0x80, 0xE2, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03 }, apdu);
        }

        [Fact]
        public void ToApdu_WithDgiFormat_ReturnsCorrectApdu()
        {
            // Arrange
            var data = new byte[] { 0xDF, 0x2B, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05 };
            var command = new StoreDataCommand(
                StoreDataCommand.DataStructureFormat.Dgi,
                StoreDataCommand.BlockFormat.FirstOrOnly,
                data
            );

            // Act
            var apdu = command.ToApdu();

            // Assert
            Assert.Equal(0x80, apdu[0]); // CLA
            Assert.Equal(0xE2, apdu[1]); // INS
            Assert.Equal(0x80, apdu[2]); // P1 (DGI format)
            Assert.Equal(0x00, apdu[3]); // P2 (First or only block)
            Assert.Equal(0x08, apdu[4]); // LC
            Assert.Equal(data, apdu[5..]); // Data
        }

        [Fact]
        public void CreateScpEnableCommand_WithSingleImplementation_CreatesCorrectCommand()
        {
            // Arrange
            ushort scpImpl = 0x0370; // SCP03 i=70

            // Act
            var command = StoreDataCommand.CreateScpEnableCommand(scpImpl);

            // Assert
            Assert.Equal(StoreDataCommand.DataStructureFormat.Dgi, command.StructureFormat);
            Assert.Equal(StoreDataCommand.BlockFormat.FirstOrOnly, command.Block);

            var apdu = command.ToApdu();
            Assert.Equal(0x80, apdu[0]); // CLA
            Assert.Equal(0xE2, apdu[1]); // INS
            Assert.Equal(0x80, apdu[2]); // P1 (DGI format)
            Assert.Equal(0x00, apdu[3]); // P2

            // Verify data structure
            var data = command.StoreData;
            Assert.Equal(0xDF, data[0]); // SET CONFIG tag
            Assert.Equal(0x2B, data[1]);
            Assert.Equal(0x0D, data[2]); // Total length
            Assert.Equal(0x10, data[3]); // SCP_ENABLE tag
            Assert.Equal(0x57, data[4]);
            Assert.Equal(0x0A, data[5]); // Data length
            Assert.Equal(0x03, data[6]); // SCP03
            Assert.Equal(0x70, data[7]); // i=70
            // Rest should be zeros (empty slots)
            for (int i = 8; i < 14; i++)
            {
                Assert.Equal(0x00, data[i]);
            }
        }

        [Fact]
        public void CreateScpEnableCommand_WithMultipleImplementations_CreatesCorrectCommand()
        {
            // Arrange
            ushort[] scpImpls = { 0x0215, 0x0370 }; // SCP02 i=15, SCP03 i=70

            // Act
            var command = StoreDataCommand.CreateScpEnableCommand(scpImpls);

            // Assert
            var data = command.StoreData;
            Assert.Equal(0xDF, data[0]); // SET CONFIG tag
            Assert.Equal(0x2B, data[1]);
            Assert.Equal(0x0D, data[2]); // Total length
            Assert.Equal(0x10, data[3]); // SCP_ENABLE tag
            Assert.Equal(0x57, data[4]);
            Assert.Equal(0x0A, data[5]); // Data length
            Assert.Equal(0x02, data[6]); // SCP02
            Assert.Equal(0x15, data[7]); // i=15
            Assert.Equal(0x03, data[8]); // SCP03
            Assert.Equal(0x70, data[9]); // i=70
            // Rest should be zeros
            for (int i = 10; i < 14; i++)
            {
                Assert.Equal(0x00, data[i]);
            }
        }

        [Fact]
        public void CreateScpEnableCommand_WithNoImplementations_ThrowsArgumentException()
        {
            // Act & Assert
            _ = Assert.Throws<ArgumentException>(() => StoreDataCommand.CreateScpEnableCommand());
        }

        [Fact]
        public void CreateDefaultKeyVersionCommand_CreatesCorrectCommand()
        {
            // Arrange
            byte keyVersion = 0x01;

            // Act
            var command = StoreDataCommand.CreateDefaultKeyVersionCommand(keyVersion);

            // Assert
            Assert.Equal(StoreDataCommand.DataStructureFormat.Dgi, command.StructureFormat);
            Assert.Equal(StoreDataCommand.BlockFormat.FirstOrOnly, command.Block);

            var data = command.StoreData;
            Assert.Equal(new byte[] { 0x7F, 0x0D, 0x01, 0x01 }, data);
        }

        [Fact]
        public void IApduCommand_Properties_ReturnCorrectValues()
        {
            // Arrange
            var command = new StoreDataCommand(
                StoreDataCommand.DataStructureFormat.BerTlv,
                StoreDataCommand.BlockFormat.MoreBlocks,
                new byte[] { 0x01 }
            );
            var iapdu = (IApduCommand)command;

            // Assert
            Assert.Equal(0x80, iapdu.Cla);
            Assert.Equal(0xE2, iapdu.Ins);
            Assert.Equal(0x60, iapdu.P1); // BER-TLV format
            Assert.Equal(0x01, iapdu.P2); // More blocks
            Assert.NotNull(iapdu.Data);
            Assert.Equal(new byte[] { 0x01 }, iapdu.Data);
            Assert.Null(iapdu.ExpectedResponseLength);
            Assert.False(iapdu.IsExtendedLength);
        }

        [Fact]
        public void StoreDataResponse_Parse_ReturnsSuccessfulResponse()
        {
            // Arrange
            var responseData = Array.Empty<byte>();

            // Act
            var response = StoreDataResponse.Parse(responseData);

            // Assert
            Assert.True(response.Success);
        }
    }
}
