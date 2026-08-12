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
        byte[] data = Convert.FromHexString("A5089F650200FF9F6E0107");

        // Act
        string? result = SecurityDomainDataParser.Decode(data);

        // Assert
        _ = result.Should().Contain("Max APDU: 255 bytes");
    }

    /// <summary>GP Card Specification v2.3.1, Table 11-82.</summary>
    [Test]
    public void Decode_Should_Preserve_Application_Production_Lifecycle_Data()
    {
        byte[] data = Convert.FromHexString("A5059F6E0207AB");

        string? result = SecurityDomainDataParser.Decode(data);

        _ = result.Should().Contain("Application production lifecycle data: 07AB");
    }

    [Test]
    public void Decode_WithUnknownTag_ShowsTagAndValue()
    {
        // Arrange - Unknown tag 9F99
        byte[] data = Convert.FromHexString("A5069F9903112233");

        // Act
        string? result = SecurityDomainDataParser.Decode(data);

        // Assert
        _ = result.Should().Contain("Tag 9F99: 112233");
    }

    [Test]
    public void Decode_WithNonA5Tag_ReturnsHexString()
    {
        // Arrange - Data not starting with A5
        byte[] data = Convert.FromHexString("B5041122");

        // Act
        string? result = SecurityDomainDataParser.Decode(data);

        // Assert
        _ = result.Should().BeEquivalentTo("B5041122");
    }

    [Test]
    public void Decode_WithEmptyData_ReturnsEmptyString()
    {
        // Arrange
        byte[] data = [];

        // Act
        string? result = SecurityDomainDataParser.Decode(data);

        // Assert
        _ = result.Should().BeEquivalentTo(string.Empty);
    }

    [Test]
    public void Decode_WithNullData_ReturnsEmptyString()
    {
        // Act
        string? result = SecurityDomainDataParser.Decode(null!);

        // Assert
        _ = result.Should().BeEquivalentTo(string.Empty);
    }

    [Test]
    public void Decode_WithMalformedTlv_ReturnsHexString()
    {
        // Arrange - A5 with invalid length
        byte[] data = Convert.FromHexString("A5FF112233");

        // Act
        string? result = SecurityDomainDataParser.Decode(data);

        // Assert
        _ = result.Should().BeEquivalentTo("A5FF112233");
    }
}
