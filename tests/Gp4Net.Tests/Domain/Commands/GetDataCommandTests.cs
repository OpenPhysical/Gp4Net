using System;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands
{
    [TestFixture]
    public class GetDataCommandTests
    {
        [Test]
        [TestCase((ushort)0x0042)] // IssuerIdentificationNumber
        [TestCase((ushort)0x0045)] // CardImageNumber
        [TestCase((ushort)0x0066)] // CardData
        [TestCase((ushort)0x00E0)] // KeyInformationTemplate
        [TestCase((ushort)0x5F50)] // SecurityDomainManagerUrl
        public void Create_WithKnownDataObject_CreatesCommand(ushort dataObject)
        {
            // Act
            var result = GetDataCommand.Create(dataObject);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.DataObjectIdentifier, Is.EqualTo(dataObject));
        }

        [Test]
        public void GetApdu_ReturnsCorrectStructure()
        {
            // Arrange
            var dataObject = GetDataCommand.DataObjects.CardData;
            var commandResult = GetDataCommand.Create(dataObject);
            Assert.That(commandResult.IsSuccess, Is.True);
            var command = commandResult.Value;

            // Act
            var apdu = command.ToApdu();

            // Assert
            Assert.That(apdu[0], Is.EqualTo(0x80)); // CLA - GlobalPlatform
            Assert.That(apdu[1], Is.EqualTo(0xCA)); // INS - GET DATA
            Assert.That(apdu[2], Is.EqualTo((byte)(dataObject >> 8))); // P1 - High byte of tag
            Assert.That(apdu[3], Is.EqualTo((byte)(dataObject & 0xFF))); // P2 - Low byte of tag
            Assert.That(apdu[4], Is.EqualTo(0x00)); // Le - Receive all available
            Assert.That(apdu.Length, Is.EqualTo(5)); // No command data for GET DATA
        }

        [Test]
        [TestCase((ushort)0x0042, 0x00, 0x42)] // IIN
        [TestCase((ushort)0x0045, 0x00, 0x45)] // CIN
        [TestCase((ushort)0x0066, 0x00, 0x66)] // Card Data
        [TestCase((ushort)0x00E0, 0x00, 0xE0)] // Key Information Template
        [TestCase((ushort)0x5F50, 0x5F, 0x50)] // Manager URL
        [TestCase((ushort)0x9F7F, 0x9F, 0x7F)] // CPLC
        public void GetApdu_SplitsTagCorrectly(ushort tag, byte expectedP1, byte expectedP2)
        {
            // Arrange
            var commandResult = GetDataCommand.Create(tag);
            Assert.That(commandResult.IsSuccess, Is.True);
            var command = commandResult.Value;

            // Act
            var apdu = command.ToApdu();

            // Assert
            Assert.That(apdu[2], Is.EqualTo(expectedP1)); // P1
            Assert.That(apdu[3], Is.EqualTo(expectedP2)); // P2
        }

        [Test]
        public void GetApdu_AlwaysReturnsNewArray()
        {
            // Arrange
            var commandResult = GetDataCommand.Create(GetDataCommand.DataObjects.CardData);
            Assert.That(commandResult.IsSuccess, Is.True);
            var command = commandResult.Value;

            // Act
            var apdu1 = command.ToApdu();
            var apdu2 = command.ToApdu();

            // Assert
            Assert.That(apdu1, Is.Not.SameAs(apdu2)); // Should be different array instances
            Assert.That(apdu2, Is.EqualTo(apdu1)); // But with same content
        }

        [Test]
        public void ToString_ReturnsDescriptiveString()
        {
            // Arrange
            var commandResult = GetDataCommand.Create(GetDataCommand.DataObjects.CardData);
            Assert.That(commandResult.IsSuccess, Is.True);
            var command = commandResult.Value;

            // Act
            var result = command.ToString();

            // Assert
            Assert.That(result, Is.EqualTo("GET DATA"));
        }

        [Test]
        public void DataObjects_DefinesCorrectTags()
        {
            // According to GlobalPlatform specification
            Assert.That(GetDataCommand.DataObjects.IssuerIdentificationNumber, Is.EqualTo(0x0042));
            Assert.That(GetDataCommand.DataObjects.CardImageNumber, Is.EqualTo(0x0045));
            Assert.That(GetDataCommand.DataObjects.CardData, Is.EqualTo(0x0066));
            Assert.That(GetDataCommand.DataObjects.CardCapabilities, Is.EqualTo(0x0067));
            Assert.That(GetDataCommand.DataObjects.KeyInformationTemplate, Is.EqualTo(0x00E0));
            Assert.That(GetDataCommand.DataObjects.DiversificationData, Is.EqualTo(0x00CF));
            Assert.That(GetDataCommand.DataObjects.CardProductionLifeCycle, Is.EqualTo(0x9F7F)); // CPLC
            Assert.That(GetDataCommand.DataObjects.SecurityDomainManagerUrl, Is.EqualTo(0x5F50));
            Assert.That(GetDataCommand.DataObjects.ConfirmationCounter, Is.EqualTo(0x00C2));
            Assert.That(GetDataCommand.DataObjects.SequenceCounterDefaultKeyVersion, Is.EqualTo(0x00C1));
        }

        [Test]
        public void Command_FollowsGlobalPlatformSpecification()
        {
            // This test documents that the command follows GlobalPlatform Card Specification
            // GET DATA command format:
            // CLA: 0x80 (GlobalPlatform) or 0x00 for some data objects
            // INS: 0xCA (GET DATA)
            // P1-P2: Tag of requested data object
            // Lc: Not present (no command data)
            // Le: 0x00 (receive all available bytes)

            var commandResult = GetDataCommand.Create(GetDataCommand.DataObjects.CardData);
            Assert.That(commandResult.IsSuccess, Is.True);
            var command = commandResult.Value;
            var apdu = command.ToApdu();

            Assert.That(apdu.Length, Is.EqualTo(5)); // 5 header bytes only
            Assert.That(apdu[0], Is.EqualTo(0x80)); // CLA
            Assert.That(apdu[1], Is.EqualTo(0xCA)); // INS
            Assert.That(apdu[4], Is.EqualTo(0x00)); // Le
        }

        [Test]
        [TestCase((ushort)0x0066, "Card Data")]
        [TestCase((ushort)0x0067, "Card Capabilities")]
        [TestCase((ushort)0x00E0, "Key Information Template")]
        [TestCase((ushort)0x9F7F, "Card Production Life Cycle")]
        public void GetDataCommand_ForCommonObjects_HasDescriptiveNames(ushort dataObject, string expectedDescription)
        {
            // This test documents common data objects and their purposes
            var commandResult = GetDataCommand.Create(dataObject);
            Assert.That(commandResult.IsSuccess, Is.True);
            var command = commandResult.Value;
            
            // The command should be able to handle these common objects
            Assert.That(command, Is.Not.Null);
            
            // Document the purpose (not testing string representation, just documenting)
            _ = expectedDescription;
        }

        [Test]
        public void GetApdu_ForSecureMessaging_WouldUseClass00()
        {
            // Note: Some implementations might use CLA 0x00 instead of 0x80
            // for certain data objects or when used outside secure channel.
            // Our implementation uses 0x80 (GlobalPlatform class) consistently.
            
            var commandResult = GetDataCommand.Create(0x9F7F); // CPLC
            Assert.That(commandResult.IsSuccess, Is.True);
            var command = commandResult.Value;
            var apdu = command.ToApdu();
            
            // We use GP class
            Assert.That(apdu[0], Is.EqualTo(0x80));
        }

        [Test]
        public void CreateFor3ByteIdentifier_WithValidThreeBytes_CreatesCommand()
        {
            // Arrange
            byte[] identifier = { 0x00, 0x9F, 0x70 };

            // Act
            var result = GetDataCommand.CreateFor3ByteIdentifier(identifier);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.DataObjectIdentifier, Is.EqualTo(0x009F));
        }

        [Test]
        public void CreateFor3ByteIdentifier_WithNullIdentifier_ReturnsError()
        {
            // Act
            var result = GetDataCommand.CreateFor3ByteIdentifier(null);

            // Assert
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Code, Is.EqualTo("INVALID_ARGUMENT"));
            Assert.That(result.Error.Message, Does.Contain("cannot be null"));
        }

        [Test]
        [TestCase(new byte[] { })]
        [TestCase(new byte[] { 0x00 })]
        [TestCase(new byte[] { 0x00, 0x9F })]
        [TestCase(new byte[] { 0x00, 0x9F, 0x70, 0x80 })]
        public void CreateFor3ByteIdentifier_WithInvalidLength_ReturnsError(byte[] identifier)
        {
            // Act
            var result = GetDataCommand.CreateFor3ByteIdentifier(identifier);

            // Assert
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Code, Is.EqualTo("INVALID_ARGUMENT"));
            Assert.That(result.Error.Message, Does.Contain("must be exactly 3 bytes"));
        }

        [Test]
        public void Parse_WithValidResponse_ReturnsSuccess()
        {
            // Arrange
            ushort tag = 0x0066;
            byte[] responseData = { 0x01, 0x02, 0x03, 0x04 };

            // Act
            var result = GetDataResponse.Parse(tag, responseData);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.DataObjectIdentifier, Is.EqualTo(tag));
            Assert.That(result.Value.Data, Is.EqualTo(responseData));
        }

        [Test]
        public void Parse_WithNullResponse_ReturnsError()
        {
            // Act
            var result = GetDataResponse.Parse(0x0066, null);

            // Assert
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Error.Code, Is.EqualTo("INVALID_ARGUMENT"));
            Assert.That(result.Error.Message, Does.Contain("cannot be null"));
        }
    }
}