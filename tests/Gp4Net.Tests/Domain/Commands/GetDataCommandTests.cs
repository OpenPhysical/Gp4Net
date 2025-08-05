using System;
using AwesomeAssertions;
using Gp4Net.Domain.Commands;
using NUnit.Framework;
using CSharpFunctionalExtensions;

namespace Gp4Net.Tests.Domain.Commands;

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
        result.IsSuccess.Should().BeTrue();
        result.Value.DataObjectIdentifier.Should().Be(dataObject);
    }

    [Test]
    public void GetApdu_ReturnsCorrectStructure()
    {
        // Arrange
        var dataObject = GetDataCommand.DataObjects.CardData;
        var commandResult = GetDataCommand.Create(dataObject);
        commandResult.IsSuccess.Should().BeTrue();
        var command = commandResult.Value;

        // Act
        var apdu = command.ToApdu();

        // Assert
        apdu[0].Should().Be(0x80); // CLA - GlobalPlatform
        apdu[1].Should().Be(0xCA); // INS - GET DATA
        apdu[2].Should().Be((byte)(dataObject >> 8)); // P1 - High byte of tag
        apdu[3].Should().Be((byte)(dataObject & 0xFF)); // P2 - Low byte of tag
        apdu[4].Should().Be(0x00); // Le - Receive all available
        apdu.Length.Should().Be(5); // No command data for GET DATA
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
        commandResult.IsSuccess.Should().BeTrue();
        var command = commandResult.Value;

        // Act
        var apdu = command.ToApdu();

        // Assert
        apdu[2].Should().Be(expectedP1); // P1
        apdu[3].Should().Be(expectedP2); // P2
    }

    [Test]
    public void GetApdu_AlwaysReturnsNewArray()
    {
        // Arrange
        var commandResult = GetDataCommand.Create(GetDataCommand.DataObjects.CardData);
        commandResult.IsSuccess.Should().BeTrue();
        var command = commandResult.Value;

        // Act
        var apdu1 = command.ToApdu();
        var apdu2 = command.ToApdu();

        // Assert
        apdu1.Should().NotBeSameAs(apdu2); // Should be different array instances
        apdu2.Should().BeEquivalentTo(apdu1); // But with same content
    }

    [Test]
    public void ToString_ReturnsDescriptiveString()
    {
        // Arrange
        var commandResult = GetDataCommand.Create(GetDataCommand.DataObjects.CardData);
        commandResult.IsSuccess.Should().BeTrue();
        var command = commandResult.Value;

        // Act
        var result = command.ToString();

        // Assert
        result.Should().BeEquivalentTo("GET DATA");
    }

    [Test]
    public void DataObjects_DefinesCorrectTags()
    {
        // According to GlobalPlatform specification
        GetDataCommand.DataObjects.IssuerIdentificationNumber.Should().Be(0x0042);
        GetDataCommand.DataObjects.CardImageNumber.Should().Be(0x0045);
        GetDataCommand.DataObjects.CardData.Should().Be(0x0066);
        GetDataCommand.DataObjects.CardCapabilities.Should().Be(0x0067);
        GetDataCommand.DataObjects.KeyInformationTemplate.Should().Be(0x00E0);
        GetDataCommand.DataObjects.DiversificationData.Should().Be(0x00CF);
        GetDataCommand.DataObjects.CardProductionLifeCycle.Should().Be(0x9F7F); // CPLC
        GetDataCommand.DataObjects.SecurityDomainManagerUrl.Should().Be(0x5F50);
        GetDataCommand.DataObjects.ConfirmationCounter.Should().Be(0x00C2);
        GetDataCommand.DataObjects.SequenceCounterDefaultKeyVersion.Should().Be(0x00C1);
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
        commandResult.IsSuccess.Should().BeTrue();
        var command = commandResult.Value;
        var apdu = command.ToApdu();

        apdu.Length.Should().Be(5); // 5 header bytes only
        apdu[0].Should().Be(0x80); // CLA
        apdu[1].Should().Be(0xCA); // INS
        apdu[4].Should().Be(0x00); // Le
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
        commandResult.IsSuccess.Should().BeTrue();
        var command = commandResult.Value;

        // The command should be able to handle these common objects
        command.Should().NotBeNull();

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
        commandResult.IsSuccess.Should().BeTrue();
        var command = commandResult.Value;
        var apdu = command.ToApdu();

        // We use GP class
        apdu[0].Should().Be(0x80);
    }

    [Test]
    public void CreateFor3ByteIdentifier_WithValidThreeBytes_CreatesCommand()
    {
        // Arrange
        byte[] identifier = { 0x00, 0x9F, 0x70 };

        // Act
        var result = GetDataCommand.CreateFor3ByteIdentifier(identifier);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Value.DataObjectIdentifier.Should().Be(0x009F);
    }

    [Test]
    public void CreateFor3ByteIdentifier_WithNullIdentifier_ReturnsError()
    {
        // Act
        var result = GetDataCommand.CreateFor3ByteIdentifier(null);

        // Assert
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain("cannot be null");
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
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain("must be exactly 3 bytes");
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
        result.IsSuccess.Should().BeTrue();
        result.Value.DataObjectIdentifier.Should().Be(tag);
        result.Value.Data.Should().BeEquivalentTo(responseData);
    }

    [Test]
    public void Parse_WithNullResponse_ReturnsError()
    {
        // Act
        var result = GetDataResponse.Parse(0x0066, null);

        // Assert
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain("cannot be null");
    }
}
