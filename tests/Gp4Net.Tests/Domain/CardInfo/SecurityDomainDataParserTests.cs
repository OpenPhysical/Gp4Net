using System;
using AwesomeAssertions;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.CardInfo;

[TestFixture]
public class SecurityDomainDataParserTests
{
    [Test]
    public void Decode_WithA5Tag_ParsesMaxApduSize()
    {
        // Arrange - A5 tag with 9F65 (Max APDU size = 255)
        var data = Convert.FromHexString("A5089F650200FF9F6E0107");

        // Act
        var result = SecurityDomainDataParser.Decode(data);

        // Assert
        _ = result.Should().Contain("Max APDU: 255 bytes");
    }

    [Test]
    public void Decode_WithA5Tag_ParsesLifecycleState()
    {
        // Arrange - A5 tag with 9F6E (Lifecycle = Selectable)
        var data = Convert.FromHexString("A5049F6E0107");

        // Act
        var result = SecurityDomainDataParser.Decode(data);

        // Assert
        _ = result.Should().Contain("Lifecycle: Selectable");
    }

    [Test]
    public void Decode_WithMultipleTags_ParsesAllValues()
    {
        // Arrange - A5 tag with both Max APDU and Lifecycle
        var data = Convert.FromHexString("A50A9F650200FF9F6E010F");

        // Act
        var result = SecurityDomainDataParser.Decode(data);

        // Assert
        _ = result.Should().Contain("Max APDU: 255 bytes");
        _ = result.Should().Contain("Lifecycle: Personalized");
    }

    [Test]
    [TestCase("01", "Loaded")]
    [TestCase("03", "Installed")]
    [TestCase("07", "Selectable")]
    [TestCase("0F", "Personalized")]
    [TestCase("83", "Blocked")]
    [TestCase("87", "Locked")]
    public void Decode_RecognizesAllLifecycleStates(string stateHex, string expectedState)
    {
        // Arrange
        var data = Convert.FromHexString($"A5049F6E01{stateHex}");

        // Act
        var result = SecurityDomainDataParser.Decode(data);

        // Assert
        _ = result.Should().Contain($"Lifecycle: {expectedState}");
    }

    [Test]
    public void Decode_WithUnknownLifecycleState_ShowsHexValue()
    {
        // Arrange - Unknown lifecycle state 0xAB
        var data = Convert.FromHexString("A5049F6E01AB");

        // Act
        var result = SecurityDomainDataParser.Decode(data);

        // Assert
        _ = result.Should().Contain("Lifecycle: 0xAB");
    }

    [Test]
    public void Decode_WithUnknownTag_ShowsTagAndValue()
    {
        // Arrange - Unknown tag 9F99
        var data = Convert.FromHexString("A5069F9903112233");

        // Act
        var result = SecurityDomainDataParser.Decode(data);

        // Assert
        _ = result.Should().Contain("Tag 9F99: 112233");
    }

    [Test]
    public void Decode_WithNonA5Tag_ReturnsHexString()
    {
        // Arrange - Data not starting with A5
        var data = Convert.FromHexString("B5041122");

        // Act
        var result = SecurityDomainDataParser.Decode(data);

        // Assert
        _ = result.Should().BeEquivalentTo("B5041122");
    }

    [Test]
    public void Decode_WithEmptyData_ReturnsEmptyString()
    {
        // Arrange
        var data = Array.Empty<byte>();

        // Act
        var result = SecurityDomainDataParser.Decode(data);

        // Assert
        _ = result.Should().BeEquivalentTo(string.Empty);
    }

    [Test]
    public void Decode_WithNullData_ReturnsEmptyString()
    {
        // Act
        var result = SecurityDomainDataParser.Decode(null);

        // Assert
        _ = result.Should().BeEquivalentTo(string.Empty);
    }

    [Test]
    public void Decode_WithMalformedTlv_ReturnsHexString()
    {
        // Arrange - A5 with invalid length
        var data = Convert.FromHexString("A5FF112233");

        // Act
        var result = SecurityDomainDataParser.Decode(data);

        // Assert
        _ = result.Should().BeEquivalentTo("A5FF112233");
    }
}