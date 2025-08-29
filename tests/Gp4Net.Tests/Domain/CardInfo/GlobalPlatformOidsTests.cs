using System.Collections.Generic;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;
using AwesomeAssertions;

namespace Gp4Net.Tests.Domain.CardInfo;

[TestFixture]
public class GlobalPlatformOidsTests
{
    [Test]
    public void GetDescription_ShouldReturnCorrectDescriptionForKnownOids()
    {
        // Act & Assert
        _ = GlobalPlatformOids.GetDescription("1.2.840.114283.1").Should().Be("GlobalPlatform");
        _ = GlobalPlatformOids.GetDescription("1.2.840.114283.4.3")
            .Should().Be("Secure Channel Protocol 03 (SCP03)");
        _ = GlobalPlatformOids.GetDescription("1.2.840.114283.4.3.112")
            .Should().Be("SCP03 with S-ENC and S-MAC");
        _ = GlobalPlatformOids.GetDescription("1.3.6.1.4.1.42.2.110.1.3")
            .Should().Be("Oracle Java Card VM");
    }

    [Test]
    public void GetDescription_ShouldReturnNullForUnknownOids()
    {
        // Act & Assert
        _ = GlobalPlatformOids.GetDescription("1.2.3.4.5.6.7.8.9").Should().BeNull();
        _ = GlobalPlatformOids.GetDescription("").Should().BeNull();
        _ = GlobalPlatformOids.GetDescription(null).Should().BeNull();
    }

    [Test]
    public void IsGlobalPlatformOid_ShouldIdentifyGpOidsCorrectly()
    {
        // Act & Assert
        _ = GlobalPlatformOids.IsGlobalPlatformOid("1.2.840.114283.1").Should().BeTrue();
        _ = GlobalPlatformOids.IsGlobalPlatformOid("1.2.840.114283.4.3.112").Should().BeTrue();
        _ = GlobalPlatformOids.IsGlobalPlatformOid("1.3.6.1.4.1.42.2.110.1.3").Should().BeFalse();
        _ = GlobalPlatformOids.IsGlobalPlatformOid("").Should().BeFalse();
        _ = GlobalPlatformOids.IsGlobalPlatformOid(null).Should().BeFalse();
    }

    [Test]
    public void GetScpVersion_ShouldExtractScpVersionFromOid()
    {
        // Act & Assert
        _ = GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.0").Should().Be("SCP00");
        _ = GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.1").Should().Be("SCP01");
        _ = GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.2").Should().Be("SCP02");
        _ = GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.3").Should().Be("SCP03");
        _ = GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.3.112").Should().Be("SCP03");
    }

    [Test]
    public void GetScpVersion_ShouldReturnNullForNonScpOids()
    {
        // Act & Assert
        _ = GlobalPlatformOids.GetScpVersion("1.2.840.114283.1").Should().BeNull();
        _ = GlobalPlatformOids.GetScpVersion("1.3.6.1.4.1.42.2.110.1.3").Should().BeNull();
        _ = GlobalPlatformOids.GetScpVersion("").Should().BeNull();
        _ = GlobalPlatformOids.GetScpVersion(null).Should().BeNull();
    }

    [Test]
    public void FormatOid_ShouldIncludeDescriptionForKnownOids()
    {
        // Act & Assert
        _ = GlobalPlatformOids.FormatOid("1.2.840.114283.1")
            .Should().Be("1.2.840.114283.1 (GlobalPlatform)");
        _ = GlobalPlatformOids.FormatOid("1.2.840.114283.4.3.112")
            .Should().Be("1.2.840.114283.4.3.112 (SCP03 with S-ENC and S-MAC)");
    }

    [Test]
    public void FormatOid_ShouldReturnOidOnlyForUnknownOids()
    {
        // Act & Assert
        _ = GlobalPlatformOids.FormatOid("1.2.3.4.5").Should().Be("1.2.3.4.5");
        _ = GlobalPlatformOids.FormatOid("").Should().Be("");
        _ = GlobalPlatformOids.FormatOid(null).Should().BeNull();
    }

    [Test]
    public void GetAllKnownOids_ShouldReturnNonEmptyDictionary()
    {
        // Act
        IReadOnlyDictionary<string, string>? knownOids = GlobalPlatformOids.GetAllKnownOids();

        // Assert
        _ = knownOids.Should().NotBeEmpty();
        _ = knownOids.Keys.Should().Contain("1.2.840.114283.1");
        _ = knownOids.Keys.Should().Contain("1.2.840.114283.4.3.112");
    }

    [Test]
    public void AnalyzeOids_ShouldCorrectlySummarizeCapabilities()
    {
        // Arrange
        string[] oids =
        [
            "1.2.840.114283.1",
            "1.2.840.114283.2.2.3",
            "1.2.840.114283.4.2",
            "1.2.840.114283.4.3",
            "1.2.840.114283.4.3.112",
            "1.3.6.1.4.1.42.2.110.1.3"
        ];

        // Act
        GlobalPlatformOids.CapabilitiesSummary? summary = GlobalPlatformOids.AnalyzeOids(oids);

        // Assert
        _ = summary.SupportedScpVersions.Should().Contain("SCP02");
        _ = summary.SupportedScpVersions.Should().Contain("SCP03");
        _ = summary.SupportsScp03WithEncryption.Should().BeTrue();
        _ = summary.SpecificationVersions
            .Should().Contain("GlobalPlatform Card Specification 2.2.3");
        _ = summary.AllOids.Should().HaveCount(6);
    }

    [Test]
    public void AnalyzeOids_ShouldHandleEmptyList()
    {
        // Act
        GlobalPlatformOids.CapabilitiesSummary? summary = GlobalPlatformOids.AnalyzeOids(new string[0]);

        // Assert
        _ = summary.SupportedScpVersions.Should().BeEmpty();
        _ = summary.SpecificationVersions.Should().BeEmpty();
        _ = summary.AllOids.Should().BeEmpty();
        _ = summary.SupportsScp03WithEncryption.Should().BeFalse();
    }

    [Test]
    public void CapabilitiesSummary_ToString_ShouldFormatCorrectly()
    {
        // Arrange
        string[] oids =
        [
            "1.2.840.114283.4.2",
            "1.2.840.114283.4.3.112",
            "1.2.840.114283.2.2.3"
        ];
        GlobalPlatformOids.CapabilitiesSummary? summary = GlobalPlatformOids.AnalyzeOids(oids);

        // Act
        string? result = summary.ToString();

        // Assert
        _ = result.Should().Contain("Supported Secure Channel Protocols:");
        _ = result.Should().Contain("SCP02");
        _ = result.Should().Contain("SCP03");
        _ = result.Should().Contain("GlobalPlatform Specifications:");
        _ = result.Should().Contain("GlobalPlatform Card Specification 2.2.3");
        _ = result.Should().Contain("All Capabilities:");
    }
}