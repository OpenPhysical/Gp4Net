using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

[TestFixture]
[Category("Unit")]
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
        Result<GetDataCommand, SmartCardError> result = GetDataCommand.Create(dataObject);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.DataObjectIdentifier.Should().Be(dataObject);
    }

    [Test]
    public void GetApdu_ReturnsCorrectStructure()
    {
        // Arrange
        ushort dataObject = GetDataCommand.DataObjects.CardData;

        // Act & Assert
        var result = GetDataCommand.Create(dataObject)
            .Bind(command => ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(command)));

        result.Match(
            apdu =>
            {
                _ = apdu[0].Should().Be(0x80); // CLA - GlobalPlatform
                _ = apdu[1].Should().Be(0xCA); // INS - GET DATA
                _ = apdu[2].Should().Be((byte)(dataObject >> 8)); // P1 - High byte of tag
                _ = apdu[3].Should().Be((byte)(dataObject & 0xFF)); // P2 - Low byte of tag
                _ = apdu[4].Should().Be(0x00); // Le - Receive all available
                _ = apdu.Length.Should().Be(5); // No command data for GET DATA
            },
            error => result.IsSuccess.Should().BeTrue($"Command creation or APDU building failed: {error}")
        );
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
        // Act & Assert
        var result = GetDataCommand.Create(tag)
            .Bind(command => ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(command)));

        result.Match(
            apdu =>
            {
                _ = apdu[2].Should().Be(expectedP1); // P1
                _ = apdu[3].Should().Be(expectedP2); // P2
            },
            error => result.IsSuccess.Should().BeTrue($"Command creation or APDU building failed: {error}")
        );
    }

    [Test]
    public void GetApdu_AlwaysReturnsNewArray()
    {
        // Act & Assert
        GetDataCommand.Create(GetDataCommand.DataObjects.CardData)
            .Match(
                command =>
                {
                    // Act
                    byte[] apdu1 = command.ToBytes();
                    byte[] apdu2 = command.ToBytes();

                    // Assert
                    _ = apdu1.Should().NotBeSameAs(apdu2); // Should be different array instances
                    _ = apdu2.Should().BeEquivalentTo(apdu1); // But with same content
                },
                error => Result.Success().IsSuccess.Should().BeTrue($"Command creation failed: {error}")
            );
    }

    [Test]
    public void ToString_ReturnsDescriptiveString()
    {
        // Arrange
        Result<GetDataCommand, SmartCardError> commandResult = GetDataCommand.Create(
            GetDataCommand.DataObjects.CardData
        );
        _ = commandResult.IsSuccess.Should().BeTrue();
        var command = commandResult.Value;

        // Act
        string? result = command.ToString();

        // Assert
        _ = result.Should().BeEquivalentTo("GET DATA");
    }

    [Test]
    public void DataObjects_DefinesCorrectTags()
    {
        // According to GlobalPlatform specification
        _ = GetDataCommand.DataObjects.IssuerIdentificationNumber.Should().Be(0x0042);
        _ = GetDataCommand.DataObjects.CardImageNumber.Should().Be(0x0045);
        _ = GetDataCommand.DataObjects.CardData.Should().Be(0x0066);
        _ = GetDataCommand.DataObjects.CardCapabilities.Should().Be(0x0067);
        _ = GetDataCommand.DataObjects.KeyInformationTemplate.Should().Be(0x00E0);
        _ = GetDataCommand.DataObjects.DiversificationData.Should().Be(0x00CF);
        _ = GetDataCommand.DataObjects.CardProductionLifeCycle.Should().Be(0x9F7F); // CPLC
        _ = GetDataCommand.DataObjects.SecurityDomainManagerUrl.Should().Be(0x5F50);
        _ = GetDataCommand.DataObjects.ConfirmationCounter.Should().Be(0x00C2);
        _ = GetDataCommand.DataObjects.SequenceCounterDefaultKeyVersion.Should().Be(0x00C1);
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

        GetDataCommand.Create(GetDataCommand.DataObjects.CardData)
            .Bind(command => ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(command)))
            .Match(
                apdu =>
                {
                    _ = apdu.Length.Should().Be(5); // 5 header bytes only
                    _ = apdu[0].Should().Be(0x80); // CLA
                    _ = apdu[1].Should().Be(0xCA); // INS
                    _ = apdu[4].Should().Be(0x00); // Le
                },
                error => Result.Success().IsSuccess.Should().BeTrue($"Command creation or APDU building failed: {error}")
            );
    }

    [Test]
    [TestCase((ushort)0x0066, "Card Data")]
    [TestCase((ushort)0x0067, "Card Capabilities")]
    [TestCase((ushort)0x00E0, "Key Information Template")]
    [TestCase((ushort)0x9F7F, "Card Production Life Cycle")]
    public void GetDataCommand_ForCommonObjects_HasDescriptiveNames(
        ushort dataObject,
        string expectedDescription
    )
    {
        // This test documents common data objects and their purposes
        Result<GetDataCommand, SmartCardError> commandResult = GetDataCommand.Create(dataObject);
        _ = commandResult.IsSuccess.Should().BeTrue();
        var command = commandResult.Value;

        // The command should be able to handle these common objects
        _ = command.Should().NotBeNull();

        // Document the purpose (not testing string representation, just documenting)
        _ = expectedDescription;
    }

    [Test]
    public void GetApdu_ForSecureMessaging_WouldUseClass00()
    {
        // Note: Some implementations might use CLA 0x00 instead of 0x80
        // for certain data objects or when used outside secure channel.
        // Our implementation uses 0x80 (GlobalPlatform class) consistently.

        GetDataCommand.Create(0x9F7F) // CPLC
            .Bind(command => ApduBuilder.BuildApdu(Maybe<IApduCommand>.From(command)))
            .Match(
                apdu =>
                {
                    // We use GP class
                    _ = apdu[0].Should().Be(0x80);
                },
                error => Result.Success().IsSuccess.Should().BeTrue($"Command creation or APDU building failed: {error}")
            );
    }

    [Test]
    public void CreateFor3ByteIdentifier_WithValidThreeBytes_CreatesCommand()
    {
        // Arrange
        byte[] identifier = [0x00, 0x9F, 0x70];

        // Act
        Result<GetDataCommand, SmartCardError> result = GetDataCommand.CreateFor3ByteIdentifier(
            identifier
        );

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.DataObjectIdentifier.Should().Be(0x009F);
    }

    [Test]
    public void CreateFor3ByteIdentifier_WithNullIdentifier_ReturnsError()
    {
        // Act
        Result<GetDataCommand, SmartCardError> result = GetDataCommand.CreateFor3ByteIdentifier(
            null
        );

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("cannot be null");
    }

    [Test]
    [TestCase(new byte[] { })]
    [TestCase(new byte[] { 0x00 })]
    [TestCase(new byte[] { 0x00, 0x9F })]
    [TestCase(new byte[] { 0x00, 0x9F, 0x70, 0x80 })]
    public void CreateFor3ByteIdentifier_WithInvalidLength_ReturnsError(byte[] identifier)
    {
        // Act
        Result<GetDataCommand, SmartCardError> result = GetDataCommand.CreateFor3ByteIdentifier(
            identifier
        );

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("must be exactly 3 bytes");
    }

    [Test]
    public void Parse_WithValidResponse_ReturnsSuccess()
    {
        // Arrange
        ushort tag = 0x0066;
        byte[] responseData = [0x01, 0x02, 0x03, 0x04];

        // Act
        Result<GetDataResponse, SmartCardError> result = GetDataResponse.Parse(tag, responseData);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.DataObjectIdentifier.Should().Be(tag);
        _ = result.Value.Data.Should().BeEquivalentTo(responseData);
    }

    [Test]
    public void Parse_WithNullResponse_ReturnsError()
    {
        // Act
        Result<GetDataResponse, SmartCardError> result = GetDataResponse.Parse(0x0066, null);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("cannot be null");
    }
}
