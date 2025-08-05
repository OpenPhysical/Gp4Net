using System;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;
using AwesomeAssertions;

namespace Gp4Net.Tests.Domain.CardInfo;

public class DiversificationDataParserTests
{
    [Test]
    public void ParseAsHex_WithValidData_ReturnsHexString()
    {
        // Arrange
        var data = Convert.FromHexString("CF0A0215031070060301060000");

        // Act
        var result = DiversificationDataParser.ParseAsHex(Maybe<byte[]>.From(data));

        // Assert
        result.Should().BeEquivalentTo("CF0A0215031070060301060000");
    }

    [Test]
    public void ParseAsHex_WithEmptyData_ReturnsEmptyString()
    {
        // Arrange
        var data = Array.Empty<byte>();

        // Act
        var result = DiversificationDataParser.ParseAsHex(Maybe<byte[]>.From(data));

        // Assert
        result.Should().BeEquivalentTo(string.Empty);
    }

    [Test]
    public void ParseAsHex_WithNullData_ReturnsEmptyString()
    {
        // Act
        var result = DiversificationDataParser.ParseAsHex(Maybe<byte[]>.None);

        // Assert
        result.Should().BeEquivalentTo(string.Empty);
    }

    [Test]
    public void ParseScpSupport_WithValidCF0AFormat_ParsesScpVersions()
    {
        // Arrange - CF0A format with SCP02 (i=15) and SCP03 (i=70)
        var data = Convert.FromHexString("CF0A0215037000000000000000");

        // Act
        var result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        result.Should().Contain("SCP02 (i=15)");
        result.Should().Contain("SCP03 (i=70)");
    }

    [Test]
    public void ParseScpSupport_WithMultipleScpVersions_ParsesAll()
    {
        // Arrange - CF0A format with multiple SCP versions
        var data = Convert.FromHexString("CF0A0215031060070301060000");

        // Act
        var result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        result.Should().Contain("SCP02 (i=15)");
        result.Should().Contain("SCP03 (i=10)");
        result.Should().Contain("SCP60 (i=07)");
        result.Should().Contain("SCP03 (i=01)");
        result.Should().Contain("SCP06 (i=00)");
    }

    [Test]
    public void ParseScpSupport_WithEmptySlots_IgnoresZeroValues()
    {
        // Arrange - CF0A format with empty slots (00 00)
        var data = Convert.FromHexString("CF0A0215000003700000000000");

        // Act
        var result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        result.Should().Contain("SCP02 (i=15)");
        result.Should().Contain("SCP03 (i=70)");
        result.Should().NotContain("SCP00");
    }

    [Test]
    public void ParseScpSupport_WithNoSupportedVersions_ReturnsNone()
    {
        // Arrange - CF0A format with all zeros
        var data = Convert.FromHexString("CF0A0000000000000000000000");

        // Act
        var result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        result.Should().BeEquivalentTo("[red]None[/]");
    }

    [Test]
    public void ParseScpSupport_WithShortData_ReturnsNone()
    {
        // Arrange - Data too short (less than 12 bytes)
        var data = Convert.FromHexString("CF0A0215");

        // Act
        var result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        result.Should().BeEquivalentTo("[red]None[/]");
    }

    [Test]
    public void ParseScpSupport_WithInvalidLength_ReturnsParseError()
    {
        // Arrange - CF tag with invalid length (less than 10)
        var data = Convert.FromHexString("CF05021503700000");

        // Act
        var result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        result.Should().BeEquivalentTo("[red]Parse error[/]");
    }

    [Test]
    public void ParseScpSupport_WithNullData_ReturnsNone()
    {
        // Act
        var result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.None);

        // Assert
        result.Should().BeEquivalentTo("[red]None[/]");
    }

    [Test]
    public void ParseScpSupport_WithEmptyData_ReturnsNone()
    {
        // Arrange
        var data = Array.Empty<byte>();

        // Act
        var result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        result.Should().BeEquivalentTo("[red]None[/]");
    }

    [Test]
    public void ParseScpSupport_FormatsMultipleVersionsWithCommas()
    {
        // Arrange - CF0A format with three SCP versions
        var data = Convert.FromHexString("CF0A0215031060070000000000");

        // Act
        var result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        result.Should().Contain(", ");
        var versions = result.Split(", ");
        versions.Length.Should().Be(3);
    }

    [Test]
    public void ParseScpSupport_PreservesParameterOrder()
    {
        // Arrange - CF0A format with specific order
        var data = Convert.FromHexString("CF0A0370021500000000000000");

        // Act
        var result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        // Should appear in the order they are in the data
        var firstCommaIndex = result.IndexOf(',');
        var scp03Index = result.IndexOf("SCP03");
        var scp02Index = result.IndexOf("SCP02");
        scp03Index.Should().BeLessThan(scp02Index);
    }
}