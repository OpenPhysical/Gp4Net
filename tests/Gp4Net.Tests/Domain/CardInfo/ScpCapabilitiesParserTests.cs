using System;
using AwesomeAssertions;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.CardInfo;

public class ScpCapabilitiesParserTests
{
    [Test]
    public void Parse_WithSecureMessagingSupport_IdentifiesScp02()
    {
        // Arrange - A0 tag containing SCP02 info per GP Card Spec Table H-6
        // A0 06 80 01 02 81 01 15 - A0 with SCP type 02 and implementation option 15
        byte[] data = Convert.FromHexString("A006800102810115");

        // Act
        string? result = ScpCapabilitiesParser.Parse(data);

        // Assert
        _ = result.Should().BeEquivalentTo("SCP02 (i=15)");
    }

    [Test]
    public void Parse_WithSecureMessagingSupport_IdentifiesScp03()
    {
        // Arrange - A0 tag containing SCP03 info per GP Card Spec Table H-6
        // A0 06 80 01 03 81 01 70 - A0 with SCP type 03 and implementation option 70
        byte[] data = Convert.FromHexString("A006800103810170");

        // Act
        string? result = ScpCapabilitiesParser.Parse(data);

        // Assert
        _ = result.Should().BeEquivalentTo("SCP03 (i=70)");
    }

    [Test]
    public void Parse_WithMultipleProtocols_ReturnsOrderedList()
    {
        // Arrange - Multiple A0 tags with different SCPs per GP Card Spec Table H-5
        // First A0: SCP02 with options 15 and 55
        // Second A0: SCP03 with option 70
        byte[] data = Convert.FromHexString("A00780010281021555A006800103810170");

        // Act
        string? result = ScpCapabilitiesParser.Parse(data);

        // Assert
        _ = result.Should().BeEquivalentTo("SCP02 (i=15 i=55) SCP03 (i=70)");
    }

    [Test]
    public void Parse_WithTopLevelPrivilegeData_DoesNotIdentifyAsProtocol()
    {
        // Arrange - Tag 82 at top level is privileges, not SCP per GP Card Spec Table H-5
        byte[] data = Convert.FromHexString("82020203");

        // Act
        string? result = ScpCapabilitiesParser.Parse(data);

        // Assert
        // Should not identify as SCP since 82 at top level is for privileges
        _ = result.Should().BeEquivalentTo(string.Empty);
    }

    [Test]
    public void Parse_WithTopLevelAlgorithmData_DoesNotIdentifyAsProtocol()
    {
        // Arrange - Tag 83 at top level is LFDBH algorithms, not SCP per GP Card Spec Table H-5
        byte[] data = Convert.FromHexString("830103");

        // Act
        string? result = ScpCapabilitiesParser.Parse(data);

        // Assert
        // Should not identify as SCP since 83 at top level is for LFDBH algorithms
        _ = result.Should().BeEquivalentTo(string.Empty);
    }

    [Test]
    public void Parse_WithScp10Support_IdentifiesScp10()
    {
        // Arrange - A0 tag containing SCP10 info per GP Card Spec Table H-6
        // A0 06 80 01 10 81 01 10 - A0 with SCP type 10 and implementation option 10
        byte[] data = Convert.FromHexString("A006800110810110");

        // Act
        string? result = ScpCapabilitiesParser.Parse(data);

        // Assert
        _ = result.Should().BeEquivalentTo("SCP10 (i=10)");
    }

    [Test]
    public void Parse_WithMultipleTags_ParsesOnlyA0Tags()
    {
        // Arrange - Mix of A0 tags (SCP) and other tags (privileges) per GP Card Spec
        // A0 with SCP02, followed by tag 82 (privileges)
        byte[] data = Convert.FromHexString("A006800102810115820103");

        // Act
        string? result = ScpCapabilitiesParser.Parse(data);

        // Assert
        // Should only parse SCP from A0 tag, ignore tag 82
        _ = result.Should().BeEquivalentTo("SCP02 (i=15)");
    }

    [Test]
    public void Parse_RemovesDuplicatesAndSorts()
    {
        // Arrange - Multiple A0 tags with duplicate SCPs
        // First A0: SCP03 with option 70
        // Second A0: SCP02 with options 15 and 55
        // Third A0: SCP03 with option 10 (different option, same protocol)
        byte[] data = Convert.FromHexString("A006800103810170A00780010281021555A006800103810110");

        // Act
        string? result = ScpCapabilitiesParser.Parse(data);

        // Assert
        // Should merge SCP03 options and sort by protocol version
        _ = result.Should().BeEquivalentTo("SCP02 (i=15 i=55) SCP03 (i=10 i=70)");
    }

    [Test]
    public void Parse_WithEmptyData_ReturnsEmptyString()
    {
        // Arrange
        byte[] data = [];

        // Act
        string? result = ScpCapabilitiesParser.Parse(data);

        // Assert
        _ = result.Should().BeEquivalentTo(string.Empty);
    }

    [Test]
    public void Parse_WithNullData_ReturnsEmptyString()
    {
        // Act
        string? result = ScpCapabilitiesParser.Parse(null);

        // Assert
        _ = result.Should().BeEquivalentTo(string.Empty);
    }

    [Test]
    public void Parse_WithMalformedTlv_ReturnsEmptyString()
    {
        // Arrange - Tag with length exceeding data
        byte[] data = Convert.FromHexString("81FF01");

        // Act
        string? result = ScpCapabilitiesParser.Parse(data);

        // Assert
        _ = result.Should().BeEquivalentTo(string.Empty);
    }

    [Test]
    public void Parse_WithUnknownProtocolIndicators_IgnoresUnknownValues()
    {
        // Arrange - A0 tags with mix of known and unknown SCP types
        // First A0: Unknown SCP FF
        // Second A0: Valid SCP02
        // Third A0: Valid SCP03
        byte[] data = Convert.FromHexString("A0068001FF8101FFA006800102810115A006800103810170");

        // Act
        string? result = ScpCapabilitiesParser.Parse(data);

        // Assert
        // Should ignore unknown SCP FF, only parse valid ones
        _ = result.Should().BeEquivalentTo("SCP02 (i=15) SCP03 (i=70)");
    }

    [Test]
    [Category("Regression")]
    public void Parse_WithRealCardCapabilities_ParsesScpCorrectly()
    {
        // Arrange - Real card capabilities from debug output (full tag 67 value)
        // Tag 67 response: 6724A0098001028104153555758103E5BEC082031E030083010284010285017B86010C87017B
        // After removing tag 67 24: A0098001028104153555758103E5BEC082031E030083010284010285017B86010C87017B
        // This contains:
        // - A0 09 (constructed tag, length 9) containing:
        //   - 80 01 02 (SCP type = SCP02)
        //   - 81 04 15355575 (implementation options: 0x15, 0x35, 0x55, 0x75)
        // - Other tags for privileges and capabilities
        byte[] data = Convert.FromHexString(
            "A0098001028104153555758103E5BEC082031E030083010284010285017B86010C87017B"
        );

        // Act
        string? result = ScpCapabilitiesParser.Parse(data);

        // Assert
        // Should identify SCP02 with all four implementation options
        _ = result.Should().BeEquivalentTo("SCP02 (i=15 i=35 i=55 i=75)");
    }

    [Test]
    [Category("Regression")]
    public void Parse_WithScp02ImplementationOptions_DoesNotTreatAsScpVersions()
    {
        // Arrange - A0 tag with SCP02 and implementation options
        // 0x15, 0x35, 0x55, 0x75 are implementation option bytes, not SCP versions
        byte[] data = Convert.FromHexString("A009800102810415355575");

        // Act
        string? result = ScpCapabilitiesParser.Parse(data);

        // Assert
        // Should parse as SCP02 with implementation options, not as separate SCPs
        _ = result.Should().BeEquivalentTo("SCP02 (i=15 i=35 i=55 i=75)");
        _ = result.Should().NotContain("SCP15");
        _ = result.Should().NotContain("SCP35");
        _ = result.Should().NotContain("SCP55");
        _ = result.Should().NotContain("SCP75");
    }

    [Test]
    [Category("Regression")]
    public void Parse_WithNestedA0Tag_ParsesInnerTags()
    {
        // Arrange - Two A0 tags, each containing SCP information
        // Per GP Card Spec, each A0 tag contains one SCP:
        // First A0: SCP02 with no options
        // Second A0: SCP03 with no options
        byte[] data = Convert.FromHexString("A003800102A003800103");

        // Act
        string? result = ScpCapabilitiesParser.Parse(data);

        // Assert
        _ = result.Should().BeEquivalentTo("SCP02 SCP03");
    }
}
