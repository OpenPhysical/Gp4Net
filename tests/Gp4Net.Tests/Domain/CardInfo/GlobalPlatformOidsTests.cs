using Gp4Net.Domain.CardInfo;
using NUnit.Framework;
using AwesomeAssertions;
using CSharpFunctionalExtensions;

namespace Gp4Net.Tests.Domain.CardInfo;

[TestFixture]
public class GlobalPlatformOidsTests
{
    [Test]
    public void GetDescription_ShouldReturnCorrectDescriptionForKnownOids()
    {
        // Act & Assert
        GlobalPlatformOids.GetDescription("1.2.840.114283.1").Should().Be("GlobalPlatform");
        GlobalPlatformOids.GetDescription("1.2.840.114283.4.3")
            .Should().Be("Secure Channel Protocol 03 (SCP03)");
        GlobalPlatformOids.GetDescription("1.2.840.114283.4.3.112")
            .Should().Be("SCP03 with S-ENC and S-MAC");
        GlobalPlatformOids.GetDescription("1.3.6.1.4.1.42.2.110.1.3")
            .Should().Be("Oracle Java Card VM");
    }

    [Test]
    public void GetDescription_ShouldReturnNullForUnknownOids()
    {
        // Act & Assert
        GlobalPlatformOids.GetDescription("1.2.3.4.5.6.7.8.9").Should().BeNull();
        GlobalPlatformOids.GetDescription("").Should().BeNull();
        GlobalPlatformOids.GetDescription(null).Should().BeNull();
    }

    [Test]
    public void IsGlobalPlatformOid_ShouldIdentifyGpOidsCorrectly()
    {
        // Act & Assert
        GlobalPlatformOids.IsGlobalPlatformOid("1.2.840.114283.1").Should().BeTrue();
        GlobalPlatformOids.IsGlobalPlatformOid("1.2.840.114283.4.3.112").Should().BeTrue();
        GlobalPlatformOids.IsGlobalPlatformOid("1.3.6.1.4.1.42.2.110.1.3").Should().BeFalse();
        GlobalPlatformOids.IsGlobalPlatformOid("").Should().BeFalse();
        GlobalPlatformOids.IsGlobalPlatformOid(null).Should().BeFalse();
    }

    [Test]
    public void GetScpVersion_ShouldExtractScpVersionFromOid()
    {
        // Act & Assert
        GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.0").Should().Be("SCP00");
        GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.1").Should().Be("SCP01");
        GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.2").Should().Be("SCP02");
        GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.3").Should().Be("SCP03");
        GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.3.112").Should().Be("SCP03");
    }

    [Test]
    public void GetScpVersion_ShouldReturnNullForNonScpOids()
    {
        // Act & Assert
        GlobalPlatformOids.GetScpVersion("1.2.840.114283.1").Should().BeNull();
        GlobalPlatformOids.GetScpVersion("1.3.6.1.4.1.42.2.110.1.3").Should().BeNull();
        GlobalPlatformOids.GetScpVersion("").Should().BeNull();
        GlobalPlatformOids.GetScpVersion(null).Should().BeNull();
    }

    [Test]
    public void FormatOid_ShouldIncludeDescriptionForKnownOids()
    {
        // Act & Assert
        GlobalPlatformOids.FormatOid("1.2.840.114283.1")
            .Should().Be("1.2.840.114283.1 (GlobalPlatform)");
        GlobalPlatformOids.FormatOid("1.2.840.114283.4.3.112")
            .Should().Be("1.2.840.114283.4.3.112 (SCP03 with S-ENC and S-MAC)");
    }

    [Test]
    public void FormatOid_ShouldReturnOidOnlyForUnknownOids()
    {
        // Act & Assert
        GlobalPlatformOids.FormatOid("1.2.3.4.5").Should().Be("1.2.3.4.5");
        GlobalPlatformOids.FormatOid("").Should().Be("");
        GlobalPlatformOids.FormatOid(null).Should().BeNull();
    }

    [Test]
    public void GetAllKnownOids_ShouldReturnNonEmptyDictionary()
    {
        // Act
        var knownOids = GlobalPlatformOids.GetAllKnownOids();

        // Assert
        knownOids.Should().NotBeEmpty();
        knownOids.Keys.Should().Contain("1.2.840.114283.1");
        knownOids.Keys.Should().Contain("1.2.840.114283.4.3.112");
    }

    [Test]
    public void AnalyzeOids_ShouldCorrectlySummarizeCapabilities()
    {
        // Arrange
        var oids = new[]
        {
            "1.2.840.114283.1",
            "1.2.840.114283.2.2.3",
            "1.2.840.114283.4.2",
            "1.2.840.114283.4.3",
            "1.2.840.114283.4.3.112",
            "1.3.6.1.4.1.42.2.110.1.3"
        };

        // Act
        var summary = GlobalPlatformOids.AnalyzeOids(oids);

        // Assert
        summary.SupportedScpVersions.Should().Contain("SCP02");
        summary.SupportedScpVersions.Should().Contain("SCP03");
        summary.SupportsScp03WithEncryption.Should().BeTrue();
        summary.SpecificationVersions
            .Should().Contain("GlobalPlatform Card Specification 2.2.3");
        summary.AllOids.Should().HaveCount(6);
    }

    [Test]
    public void AnalyzeOids_ShouldHandleEmptyList()
    {
        // Act
        var summary = GlobalPlatformOids.AnalyzeOids(new string[0]);

        // Assert
        summary.SupportedScpVersions.Should().BeEmpty();
        summary.SpecificationVersions.Should().BeEmpty();
        summary.AllOids.Should().BeEmpty();
        summary.SupportsScp03WithEncryption.Should().BeFalse();
    }

    [Test]
    public void CapabilitiesSummary_ToString_ShouldFormatCorrectly()
    {
        // Arrange
        var oids = new[]
        {
            "1.2.840.114283.4.2",
            "1.2.840.114283.4.3.112",
            "1.2.840.114283.2.2.3"
        };
        var summary = GlobalPlatformOids.AnalyzeOids(oids);

        // Act
        var result = summary.ToString();

        // Assert
        result.Should().Contain("Supported Secure Channel Protocols:");
        result.Should().Contain("SCP02");
        result.Should().Contain("SCP03");
        result.Should().Contain("GlobalPlatform Specifications:");
        result.Should().Contain("GlobalPlatform Card Specification 2.2.3");
        result.Should().Contain("All Capabilities:");
    }
}