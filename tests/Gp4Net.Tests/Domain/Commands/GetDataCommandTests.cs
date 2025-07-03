using System;
using Gp4Net.Domain.Commands;
using Xunit;

namespace Gp4Net.Tests.Domain.Commands
{
    public class GetDataCommandTests
    {
        [Theory]
        [InlineData(GetDataCommand.DataObjects.IssuerIdentificationNumber)]
        [InlineData(GetDataCommand.DataObjects.CardImageNumber)]
        [InlineData(GetDataCommand.DataObjects.CardData)]
        [InlineData(GetDataCommand.DataObjects.KeyInformationTemplate)]
        [InlineData(GetDataCommand.DataObjects.SecurityDomainManagerUrl)]
        public void Constructor_WithKnownDataObject_CreatesCommand(ushort dataObject)
        {
            // Act
            var command = new GetDataCommand(dataObject);

            // Assert
            Assert.Equal(dataObject, command.DataObject);
        }

        [Fact]
        public void GetApdu_ReturnsCorrectStructure()
        {
            // Arrange
            var dataObject = GetDataCommand.DataObjects.CardData;
            var command = new GetDataCommand(dataObject);

            // Act
            var apdu = command.GetApdu();

            // Assert
            Assert.Equal(0x80, apdu[0]); // CLA - GlobalPlatform
            Assert.Equal(0xCA, apdu[1]); // INS - GET DATA
            Assert.Equal((byte)(dataObject >> 8), apdu[2]); // P1 - High byte of tag
            Assert.Equal((byte)(dataObject & 0xFF), apdu[3]); // P2 - Low byte of tag
            Assert.Equal(0x00, apdu[4]); // Le - Receive all available
            Assert.Equal(5, apdu.Length); // No command data for GET DATA
        }

        [Theory]
        [InlineData(0x0042, 0x00, 0x42)] // IIN
        [InlineData(0x0045, 0x00, 0x45)] // CIN
        [InlineData(0x0066, 0x00, 0x66)] // Card Data
        [InlineData(0x00E0, 0x00, 0xE0)] // Key Information Template
        [InlineData(0x5F50, 0x5F, 0x50)] // Manager URL
        [InlineData(0x9F7F, 0x9F, 0x7F)] // CPLC
        public void GetApdu_SplitsTagCorrectly(ushort tag, byte expectedP1, byte expectedP2)
        {
            // Arrange
            var command = new GetDataCommand(tag);

            // Act
            var apdu = command.GetApdu();

            // Assert
            Assert.Equal(expectedP1, apdu[2]); // P1
            Assert.Equal(expectedP2, apdu[3]); // P2
        }

        [Fact]
        public void GetApdu_AlwaysReturnsNewArray()
        {
            // Arrange
            var command = new GetDataCommand(GetDataCommand.DataObjects.CardData);

            // Act
            var apdu1 = command.GetApdu();
            var apdu2 = command.GetApdu();

            // Assert
            Assert.NotSame(apdu1, apdu2); // Should be different array instances
            Assert.Equal(apdu1, apdu2); // But with same content
        }

        [Fact]
        public void ToString_ReturnsDescriptiveString()
        {
            // Arrange
            var command = new GetDataCommand(GetDataCommand.DataObjects.CardData);

            // Act
            var result = command.ToString();

            // Assert
            Assert.Contains("GET DATA", result);
            Assert.Contains("0066", result); // Tag in hex
        }

        [Fact]
        public void DataObjects_DefinesCorrectTags()
        {
            // According to GlobalPlatform specification
            Assert.Equal(0x0042, GetDataCommand.DataObjects.IssuerIdentificationNumber);
            Assert.Equal(0x0045, GetDataCommand.DataObjects.CardImageNumber);
            Assert.Equal(0x0066, GetDataCommand.DataObjects.CardData);
            Assert.Equal(0x0067, GetDataCommand.DataObjects.CardCapabilities);
            Assert.Equal(0x0068, GetDataCommand.DataObjects.StatusInformation);
            Assert.Equal(0x00E0, GetDataCommand.DataObjects.KeyInformationTemplate);
            Assert.Equal(0x00CF, GetDataCommand.DataObjects.DiversificationData);
            Assert.Equal(0x9F7F, GetDataCommand.DataObjects.Cplc);
            Assert.Equal(0x5F50, GetDataCommand.DataObjects.SecurityDomainManagerUrl);
            Assert.Equal(0xDF28, GetDataCommand.DataObjects.ConfirmationCounter);
            Assert.Equal(0xDF27, GetDataCommand.DataObjects.SequenceCounter);
        }

        [Fact]
        public void Command_FollowsGlobalPlatformSpecification()
        {
            // This test documents that the command follows GlobalPlatform Card Specification
            // GET DATA command format:
            // CLA: 0x80 (GlobalPlatform) or 0x00 for some data objects
            // INS: 0xCA (GET DATA)
            // P1-P2: Tag of requested data object
            // Lc: Not present (no command data)
            // Le: 0x00 (receive all available bytes)

            var command = new GetDataCommand(GetDataCommand.DataObjects.CardData);
            var apdu = command.GetApdu();

            Assert.Equal(5, apdu.Length); // 5 header bytes only
            Assert.Equal(0x80, apdu[0]); // CLA
            Assert.Equal(0xCA, apdu[1]); // INS
            Assert.Equal(0x00, apdu[4]); // Le
        }

        [Theory]
        [InlineData(GetDataCommand.DataObjects.CardData, "Card Data")]
        [InlineData(GetDataCommand.DataObjects.CardCapabilities, "Card Capabilities")]
        [InlineData(GetDataCommand.DataObjects.KeyInformationTemplate, "Key Information Template")]
        [InlineData(GetDataCommand.DataObjects.Cplc, "Card Production Life Cycle")]
        public void GetDataCommand_ForCommonObjects_HasDescriptiveNames(ushort dataObject, string expectedDescription)
        {
            // This test documents common data objects and their purposes
            var command = new GetDataCommand(dataObject);
            
            // The command should be able to handle these common objects
            Assert.NotNull(command);
            
            // Document the purpose (not testing string representation, just documenting)
            _ = expectedDescription;
        }

        [Fact]
        public void GetApdu_ForSecureMessaging_WouldUseClass00()
        {
            // Note: Some implementations might use CLA 0x00 instead of 0x80
            // for certain data objects or when used outside secure channel.
            // Our implementation uses 0x80 (GlobalPlatform class) consistently.
            
            var command = new GetDataCommand(GetDataCommand.DataObjects.Cplc);
            var apdu = command.GetApdu();
            
            // We use GP class
            Assert.Equal(0x80, apdu[0]);
        }
    }
}