using System;
using System.Linq;
using Gp4Net.Domain.Commands;
using Gp4Net.Utils;

namespace Gp4Net.Tests.Domain.Commands
{
    /// <summary>
    /// Tests for the LoadCommand class.
    /// </summary>
    [TestFixture]
    public class LoadCommandTests
    {
        #region Constructor Tests

        [Test]
        public void Constructor_ValidParameters_CreatesInstance()
        {
            // Arrange
            var data = ConvertCompat.FromHexString("DEADBEEF");

            // Act
            var command = new LoadCommand(0, data, false, 100);

            // Assert
            Assert.That(command.BlockNumber, Is.EqualTo(0));
            Assert.That(command.Data, Is.EqualTo(data));
            Assert.That(command.Type, Is.EqualTo(LoadCommand.LoadType.Continuation));
            Assert.That(command.TotalCapSize, Is.EqualTo(100));
            Assert.That(command.IsFirstBlock, Is.True);
            Assert.That(command.IsFinalBlock, Is.False);
        }

        [Test]
        public void Constructor_FinalBlock_SetsFinalType()
        {
            // Arrange
            var data = ConvertCompat.FromHexString("DEADBEEF");

            // Act
            var command = new LoadCommand(1, data, true);

            // Assert
            Assert.That(command.Type, Is.EqualTo(LoadCommand.LoadType.Final));
            Assert.That(command.IsFinalBlock, Is.True);
        }

        [Test]
        public void Constructor_NullData_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new LoadCommand(0, null, false, 100));
        }

        [Test]
        public void Constructor_EmptyData_ThrowsArgumentException()
        {
            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => new LoadCommand(0, Array.Empty<byte>(), false, 100));
            Assert.That(ex.ParamName, Is.EqualTo("data"));
        }

        [Test]
        public void Constructor_FirstBlockWithoutTotalSize_ThrowsArgumentException()
        {
            // Arrange
            var data = ConvertCompat.FromHexString("DEADBEEF");

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => new LoadCommand(0, data, false));
            Assert.That(ex.ParamName, Is.EqualTo("totalCapSize"));
        }

        [Test]
        public void Constructor_NonFirstBlockWithoutTotalSize_Succeeds()
        {
            // Arrange
            var data = ConvertCompat.FromHexString("DEADBEEF");

            // Act
            var command = new LoadCommand(1, data, false);

            // Assert
            Assert.That(command.TotalCapSize, Is.Null);
        }

        #endregion

        #region CreateFromCapFile Tests

        [Test]
        public void CreateFromCapFile_SmallCapFile_CreatesSingleCommand()
        {
            // Arrange
            var capData = ConvertCompat.FromHexString("DEADBEEFCAFEBABE");

            // Act
            var commands = LoadCommand.CreateFromCapFile(capData, 255);

            // Assert
            Assert.That(commands.Count, Is.EqualTo(1));
            Assert.That(commands[0].BlockNumber, Is.EqualTo(0));
            Assert.That(commands[0].IsFirstBlock, Is.True);
            Assert.That(commands[0].IsFinalBlock, Is.True);
            Assert.That(commands[0].TotalCapSize, Is.EqualTo(8));
            Assert.That(commands[0].Data, Is.EqualTo(capData));
        }

        [Test]
        public void CreateFromCapFile_LargeCapFile_CreatesMultipleCommands()
        {
            // Arrange
            var capData = new byte[500]; // Large enough to require multiple blocks
            for (int i = 0; i < capData.Length; i++)
            {
                capData[i] = (byte)(i % 256);
            }

            // Act
            var commands = LoadCommand.CreateFromCapFile(capData, 200);

            // Assert
            Assert.That(commands.Count, Is.GreaterThan(1));
            
            // Check first block
            Assert.That(commands[0].BlockNumber, Is.EqualTo(0));
            Assert.That(commands[0].IsFirstBlock, Is.True);
            Assert.That(commands[0].IsFinalBlock, Is.False);
            Assert.That(commands[0].TotalCapSize, Is.EqualTo(500));
            
            // Check last block
            var lastCommand = commands[^1];
            Assert.That(lastCommand.BlockNumber, Is.EqualTo(commands.Count - 1));
            Assert.That(lastCommand.IsFirstBlock, Is.False);
            Assert.That(lastCommand.IsFinalBlock, Is.True);
            Assert.That(lastCommand.TotalCapSize, Is.Null);
            
            // Check intermediate blocks
            for (int i = 1; i < commands.Count - 1; i++)
            {
                Assert.That(commands[i].BlockNumber, Is.EqualTo(i));
                Assert.That(commands[i].IsFirstBlock, Is.False);
                Assert.That(commands[i].IsFinalBlock, Is.False);
                Assert.That(commands[i].TotalCapSize, Is.Null);
            }
        }

        [Test]
        public void CreateFromCapFile_RespectsMaxBlockSize()
        {
            // Arrange
            var capData = new byte[100];
            var maxBlockSize = 30;

            // Act
            var commands = LoadCommand.CreateFromCapFile(capData, maxBlockSize);

            // Assert
            foreach (var command in commands)
            {
                Assert.That(command.Data.Length, Is.LessThanOrEqualTo(maxBlockSize));
            }
        }

        [Test]
        public void CreateFromCapFile_ReconstructedDataMatchesOriginal()
        {
            // Arrange
            var capData = new byte[123]; // Odd size to test edge cases
            for (int i = 0; i < capData.Length; i++)
            {
                capData[i] = (byte)(i % 256);
            }

            // Act
            var commands = LoadCommand.CreateFromCapFile(capData, 50);
            var reconstructed = commands.SelectMany(c => c.Data).ToArray();

            // Assert
            Assert.That(reconstructed, Is.EqualTo(capData));
        }

        [Test]
        public void CreateFromCapFile_NullData_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => LoadCommand.CreateFromCapFile(null));
        }

        [Test]
        public void CreateFromCapFile_EmptyData_ThrowsArgumentException()
        {
            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => LoadCommand.CreateFromCapFile(Array.Empty<byte>()));
            Assert.That(ex.ParamName, Is.EqualTo("capFileData"));
        }

        [Test]
        public void CreateFromCapFile_InvalidBlockSize_ThrowsArgumentException()
        {
            // Arrange
            var capData = ConvertCompat.FromHexString("DEADBEEF");

            // Act & Assert
            Assert.Throws<ArgumentException>(() => LoadCommand.CreateFromCapFile(capData, 0));
            Assert.Throws<ArgumentException>(() => LoadCommand.CreateFromCapFile(capData, 256));
        }

        #endregion

        #region ToApdu Tests

        [Test]
        public void ToApdu_FirstBlock_IncludesTlvHeader()
        {
            // Arrange
            var data = ConvertCompat.FromHexString("DEADBEEF");
            var command = new LoadCommand(0, data, false, 100);

            // Act
            var apdu = command.ToApdu();

            // Assert
            Assert.That(apdu[0], Is.EqualTo(0x80)); // CLA
            Assert.That(apdu[1], Is.EqualTo(0xE8)); // INS
            Assert.That(apdu[2], Is.EqualTo(0x00)); // P1 (continuation)
            Assert.That(apdu[3], Is.EqualTo(0x00)); // P2 (block number)
            
            // Data should include C4 tag and length
            var dataField = apdu.Skip(5).Take(apdu[4]).ToArray();
            Assert.That(dataField[0], Is.EqualTo(0xC4)); // TLV tag
            Assert.That(dataField[1], Is.EqualTo(100)); // Total length (short form)
            Assert.That(dataField.Skip(2).ToArray(), Is.EqualTo(data)); // Actual data
        }

        [Test]
        public void ToApdu_ContinuationBlock_DoesNotIncludeTlvHeader()
        {
            // Arrange
            var data = ConvertCompat.FromHexString("DEADBEEF");
            var command = new LoadCommand(1, data, false);

            // Act
            var apdu = command.ToApdu();

            // Assert
            Assert.That(apdu[2], Is.EqualTo(0x00)); // P1 (continuation)
            Assert.That(apdu[3], Is.EqualTo(0x01)); // P2 (block number)
            
            // Data should be raw data without TLV header
            var dataField = apdu.Skip(5).Take(apdu[4]).ToArray();
            Assert.That(dataField, Is.EqualTo(data));
        }

        [Test]
        public void ToApdu_FinalBlock_SetsFinalP1()
        {
            // Arrange
            var data = ConvertCompat.FromHexString("DEADBEEF");
            var command = new LoadCommand(2, data, true);

            // Act
            var apdu = command.ToApdu();

            // Assert
            Assert.That(apdu[2], Is.EqualTo(0x80)); // P1 (final)
            Assert.That(apdu[3], Is.EqualTo(0x02)); // P2 (block number)
        }

        [Test]
        public void ToApdu_LargeTotalSize_UsesMultiByteLengthEncoding()
        {
            // Arrange
            var data = ConvertCompat.FromHexString("DEAD");
            var command = new LoadCommand(0, data, false, 0x1234); // Large total size

            // Act
            var apdu = command.ToApdu();

            // Assert
            var dataField = apdu.Skip(5).Take(apdu[4]).ToArray();
            Assert.That(dataField[0], Is.EqualTo(0xC4)); // TLV tag
            Assert.That(dataField[1], Is.EqualTo(0x82)); // Length form (2 bytes follow)
            Assert.That(dataField[2], Is.EqualTo(0x12)); // Length high byte
            Assert.That(dataField[3], Is.EqualTo(0x34)); // Length low byte
        }

        [Test]
        public void ToApdu_IncludesLeField()
        {
            // Arrange
            var data = ConvertCompat.FromHexString("DEADBEEF");
            var command = new LoadCommand(0, data, false, 100);

            // Act
            var apdu = command.ToApdu();

            // Assert
            Assert.That(apdu[^1], Is.EqualTo(0x00)); // Le field
        }

        #endregion

        #region LoadResponse Tests

        [Test]
        public void LoadResponse_Constructor_SetsProperties()
        {
            // Arrange
            var data = ConvertCompat.FromHexString("DEADBEEF");
            const ushort statusWord = 0x9000;

            // Act
            var response = new LoadResponse(data, statusWord);

            // Assert
            Assert.That(response.Data, Is.EqualTo(data));
            Assert.That(response.StatusWord, Is.EqualTo(statusWord));
            Assert.That(response.IsSuccessful, Is.True);
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
            Assert.That(response.IsSuccessful, Is.False);
            Assert.That(response.StatusWord, Is.EqualTo(statusWord));
        }

        [Test]
        public void LoadResponse_Parse_ReturnsCorrectResponse()
        {
            // Arrange
            var data = ConvertCompat.FromHexString("DEADBEEF");
            const ushort statusWord = 0x9000;

            // Act
            var response = LoadResponse.Parse(data, statusWord);

            // Assert
            Assert.That(response.Data, Is.EqualTo(data));
            Assert.That(response.StatusWord, Is.EqualTo(statusWord));
            Assert.That(response.IsSuccessful, Is.True);
        }

        [Test]
        public void LoadResponse_ParseNullData_HandlesGracefully()
        {
            // Act
            var response = LoadResponse.Parse(null, 0x9000);

            // Assert
            Assert.That(response.Data, Is.Not.Null);
            Assert.That(response.Data.Length, Is.EqualTo(0));
        }

        #endregion

        #region CapFileLoader Tests

        [Test]
        public void ValidateCapFile_NullData_ReturnsFalse()
        {
            // Act
            var isValid = CapFileLoader.ValidateCapFile(null);

            // Assert
            Assert.That(isValid, Is.False);
        }

        [Test]
        public void ValidateCapFile_EmptyData_ReturnsFalse()
        {
            // Act
            var isValid = CapFileLoader.ValidateCapFile(Array.Empty<byte>());

            // Assert
            Assert.That(isValid, Is.False);
        }

        [Test]
        public void ValidateCapFile_TooShortData_ReturnsFalse()
        {
            // Arrange
            var shortData = new byte[5];

            // Act
            var isValid = CapFileLoader.ValidateCapFile(shortData);

            // Assert
            Assert.That(isValid, Is.False);
        }

        [Test]
        public void GetErrorDescription_KnownErrorCode_ReturnsDescription()
        {
            // Act
            var description = CapFileLoader.GetErrorDescription(CapFileLoader.ErrorCodes.IncorrectData);

            // Assert
            Assert.That(description, Is.Not.Null);
            Assert.That(description, Does.Contain("Incorrect data"));
        }

        [Test]
        public void GetErrorDescription_UnknownErrorCode_ReturnsUnknownMessage()
        {
            // Act
            var description = CapFileLoader.GetErrorDescription(0x1234);

            // Assert
            Assert.That(description, Does.Contain("Unknown error"));
            Assert.That(description, Does.Contain("1234"));
        }

        [Test]
        public void GetErrorDescription_SuccessCode_ReturnsSuccess()
        {
            // Act
            var description = CapFileLoader.GetErrorDescription(CapFileLoader.ErrorCodes.Success);

            // Assert
            Assert.That(description, Is.EqualTo("Success"));
        }

        #endregion
    }
}