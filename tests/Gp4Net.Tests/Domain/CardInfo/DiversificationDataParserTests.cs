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
        byte[] data = Convert.FromHexString("CF0A0215031070060301060000");

        // Act
        string? result = DiversificationDataParser.ParseAsHex(Maybe<byte[]>.From(data));

        // Assert
        _ = result.Should().BeEquivalentTo("CF0A0215031070060301060000");
    }

    [Test]
    public void ParseAsHex_WithEmptyData_ReturnsEmptyString()
    {
        // Arrange
        byte[] data = [];

        // Act
        string? result = DiversificationDataParser.ParseAsHex(Maybe<byte[]>.From(data));

        // Assert
        _ = result.Should().BeEquivalentTo(string.Empty);
    }

    [Test]
    public void ParseAsHex_WithNullData_ReturnsEmptyString()
    {
        // Act
        string? result = DiversificationDataParser.ParseAsHex(Maybe<byte[]>.None);

        // Assert
        _ = result.Should().BeEquivalentTo(string.Empty);
    }

    [Test]
    public void ParseScpSupport_WithValidCF0AFormat_ParsesScpVersions()
    {
        // Arrange - CF0A format with SCP02 (i=15) and SCP03 (i=70)
        byte[] data = Convert.FromHexString("CF0A0215037000000000000000");

        // Act
        string? result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        _ = result.Should().Contain("SCP02 (i=15)");
        _ = result.Should().Contain("SCP03 (i=70)");
    }

    [Test]
    public void ParseScpSupport_WithMultipleScpVersions_ParsesAll()
    {
        // Arrange - CF0A format with multiple valid SCP versions
        // 02 15 - SCP02 with i=15
        // 03 10 - SCP03 with i=10
        // 10 07 - SCP10 with i=07
        // 03 01 - SCP03 with i=01 (duplicate SCP03 with different option)
        // 11 55 - SCP11 with i=55
        byte[] data = Convert.FromHexString("CF0A0215031010070301115500");

        // Act
        string? result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        _ = result.Should().Contain("SCP02 (i=15)");
        _ = result.Should().Contain("SCP03 (i=10)");
        _ = result.Should().Contain("SCP10 (i=07)");
        _ = result.Should().Contain("SCP03 (i=01)");
        _ = result.Should().Contain("SCP11 (i=55)");
    }

    [Test]
    public void ParseScpSupport_WithEmptySlots_IgnoresZeroValues()
    {
        // Arrange - CF0A format with empty slots (00 00)
        byte[] data = Convert.FromHexString("CF0A0215000003700000000000");

        // Act
        string? result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        _ = result.Should().Contain("SCP02 (i=15)");
        _ = result.Should().Contain("SCP03 (i=70)");
        _ = result.Should().NotContain("SCP00");
    }

    [Test]
    public void ParseScpSupport_WithNoSupportedVersions_ReturnsNone()
    {
        // Arrange - CF0A format with all zeros
        byte[] data = Convert.FromHexString("CF0A0000000000000000000000");

        // Act
        string? result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        _ = result.Should().BeEquivalentTo("[red]None[/]");
    }

    [Test]
    public void ParseScpSupport_WithShortData_ReturnsNone()
    {
        // Arrange - Data too short (less than 12 bytes)
        byte[] data = Convert.FromHexString("CF0A0215");

        // Act
        string? result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        _ = result.Should().BeEquivalentTo("[red]None[/]");
    }

    [Test]
    public void ParseScpSupport_WithInvalidLength_ReturnsParseError()
    {
        // Arrange - CF tag with invalid length (less than 10)
        byte[] data = Convert.FromHexString("CF05021503700000");

        // Act
        string? result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        _ = result.Should().BeEquivalentTo("[red]Parse error[/]");
    }

    [Test]
    public void ParseScpSupport_WithNullData_ReturnsNone()
    {
        // Act
        string? result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.None);

        // Assert
        _ = result.Should().BeEquivalentTo("[red]None[/]");
    }

    [Test]
    public void ParseScpSupport_WithEmptyData_ReturnsNone()
    {
        // Arrange
        byte[] data = [];

        // Act
        string? result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        _ = result.Should().BeEquivalentTo("[red]None[/]");
    }

    [Test]
    public void ParseScpSupport_FormatsMultipleVersionsWithCommas()
    {
        // Arrange - CF0A format with three SCP versions
        // 02 15 - SCP02 with i=15
        // 03 10 - SCP03 with i=10  
        // 10 70 - SCP10 with i=70
        byte[] data = Convert.FromHexString("CF0A0215031010700000000000");

        // Act
        string? result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        _ = result.Should().Contain(", ");
        string[] versions = result.Split(", ");
        _ = versions.Length.Should().Be(3);
    }

    [Test]
    public void ParseScpSupport_PreservesParameterOrder()
    {
        // Arrange - CF0A format with specific order
        byte[] data = Convert.FromHexString("CF0A0370021500000000000000");

        // Act
        string? result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        // Should appear in the order they are in the data
        int firstCommaIndex = result.IndexOf(',');
        int scp03Index = result.IndexOf("SCP03");
        int scp02Index = result.IndexOf("SCP02");
        _ = scp03Index.Should().BeLessThan(scp02Index);
    }

    [Test]
    [Category("Regression")]
    public void ParseScpSupport_WithCardIdentificationData_DoesNotProduceInvalidScpVersions()
    {
        // Arrange - Real CF tag from card containing card ID data, not SCP support
        // CF0A00002345558083204839
        // This is actually:
        // - 00 00 - padding
        // - 23 45 - IC Fabrication Date (2345)
        // - 55 80 83 20 - IC Serial Number (55808320)
        // - 48 39 - IC Batch Identifier (4839)
        byte[] data = Convert.FromHexString("CF0A00002345558083204839");

        // Act
        string? result = DiversificationDataParser.ParseScpSupport(Maybe<byte[]>.From(data));

        // Assert
        // Should not produce invalid SCP versions like SCP35, SCP85, SCP131, SCP72
        _ = result.Should().NotContain("SCP35");
        _ = result.Should().NotContain("SCP85");
        _ = result.Should().NotContain("SCP131");
        _ = result.Should().NotContain("SCP72");
        // Actually, this card doesn't have SCP support in CF tag
        _ = result.Should().BeEquivalentTo("[red]None[/]");
    }
}