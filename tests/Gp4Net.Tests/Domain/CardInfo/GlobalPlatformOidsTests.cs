using System.Linq;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.CardInfo
{
    [TestFixture]
    public class GlobalPlatformOidsTests
    {
        [Test]
        public void GetDescription_ShouldReturnCorrectDescriptionForKnownOids()
        {
            // Act & Assert
            Assert.That(GlobalPlatformOids.GetDescription("1.2.840.114283.1"), Is.EqualTo("GlobalPlatform"));
            Assert.That(
                GlobalPlatformOids.GetDescription("1.2.840.114283.4.3"),
                Is.EqualTo("Secure Channel Protocol 03 (SCP03)")
            );
            Assert.That(
                GlobalPlatformOids.GetDescription("1.2.840.114283.4.3.112"),
                Is.EqualTo("SCP03 with S-ENC and S-MAC")
            );
            Assert.That(
                GlobalPlatformOids.GetDescription("1.3.6.1.4.1.42.2.110.1.3"),
                Is.EqualTo("Oracle Java Card VM")
            );
        }

        [Test]
        public void GetDescription_ShouldReturnNullForUnknownOids()
        {
            // Act & Assert
            Assert.That(GlobalPlatformOids.GetDescription("1.2.3.4.5.6.7.8.9"), Is.Null);
            Assert.That(GlobalPlatformOids.GetDescription(""), Is.Null);
            Assert.That(GlobalPlatformOids.GetDescription(null), Is.Null);
        }

        [Test]
        public void IsGlobalPlatformOid_ShouldIdentifyGpOidsCorrectly()
        {
            // Act & Assert
            Assert.That(GlobalPlatformOids.IsGlobalPlatformOid("1.2.840.114283.1"), Is.True);
            Assert.That(GlobalPlatformOids.IsGlobalPlatformOid("1.2.840.114283.4.3.112"), Is.True);
            Assert.That(GlobalPlatformOids.IsGlobalPlatformOid("1.3.6.1.4.1.42.2.110.1.3"), Is.False);
            Assert.That(GlobalPlatformOids.IsGlobalPlatformOid(""), Is.False);
            Assert.That(GlobalPlatformOids.IsGlobalPlatformOid(null), Is.False);
        }

        [Test]
        public void GetScpVersion_ShouldExtractScpVersionFromOid()
        {
            // Act & Assert
            Assert.That(GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.0"), Is.EqualTo("SCP00"));
            Assert.That(GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.1"), Is.EqualTo("SCP01"));
            Assert.That(GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.2"), Is.EqualTo("SCP02"));
            Assert.That(GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.3"), Is.EqualTo("SCP03"));
            Assert.That(GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.3.112"), Is.EqualTo("SCP03"));
        }

        [Test]
        public void GetScpVersion_ShouldReturnNullForNonScpOids()
        {
            // Act & Assert
            Assert.That(GlobalPlatformOids.GetScpVersion("1.2.840.114283.1"), Is.Null);
            Assert.That(GlobalPlatformOids.GetScpVersion("1.3.6.1.4.1.42.2.110.1.3"), Is.Null);
            Assert.That(GlobalPlatformOids.GetScpVersion(""), Is.Null);
            Assert.That(GlobalPlatformOids.GetScpVersion(null), Is.Null);
        }

        [Test]
        public void FormatOid_ShouldIncludeDescriptionForKnownOids()
        {
            // Act & Assert
            Assert.That(
                GlobalPlatformOids.FormatOid("1.2.840.114283.1"),
                Is.EqualTo("1.2.840.114283.1 (GlobalPlatform)")
            );
            Assert.That(
                GlobalPlatformOids.FormatOid("1.2.840.114283.4.3.112"),
                Is.EqualTo("1.2.840.114283.4.3.112 (SCP03 with S-ENC and S-MAC)")
            );
        }

        [Test]
        public void FormatOid_ShouldReturnOidOnlyForUnknownOids()
        {
            // Act & Assert
            Assert.That(GlobalPlatformOids.FormatOid("1.2.3.4.5"), Is.EqualTo("1.2.3.4.5"));
            Assert.That(GlobalPlatformOids.FormatOid(""), Is.EqualTo(""));
            Assert.That(GlobalPlatformOids.FormatOid(null), Is.Null);
        }

        [Test]
        public void GetAllKnownOids_ShouldReturnNonEmptyDictionary()
        {
            // Act
            var knownOids = GlobalPlatformOids.GetAllKnownOids();

            // Assert
            Assert.That(knownOids, Is.Not.Empty);
            Assert.That(knownOids.Keys, Does.Contain("1.2.840.114283.1"));
            Assert.That(knownOids.Keys, Does.Contain("1.2.840.114283.4.3.112"));
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
            Assert.That(summary.SupportedScpVersions, Does.Contain("SCP02"));
            Assert.That(summary.SupportedScpVersions, Does.Contain("SCP03"));
            Assert.That(summary.SupportsScp03WithEncryption, Is.True);
            Assert.That(
                summary.SpecificationVersions,
                Does.Contain("GlobalPlatform Card Specification 2.2.3")
            );
            Assert.That(summary.AllOids.Count, Is.EqualTo(6));
        }

        [Test]
        public void AnalyzeOids_ShouldHandleEmptyList()
        {
            // Act
            var summary = GlobalPlatformOids.AnalyzeOids(new string[0]);

            // Assert
            Assert.That(summary.SupportedScpVersions, Is.Empty);
            Assert.That(summary.SpecificationVersions, Is.Empty);
            Assert.That(summary.AllOids, Is.Empty);
            Assert.That(summary.SupportsScp03WithEncryption, Is.False);
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
            Assert.That(result, Does.Contain("Supported Secure Channel Protocols:"));
            Assert.That(result, Does.Contain("SCP02"));
            Assert.That(result, Does.Contain("SCP03"));
            Assert.That(result, Does.Contain("GlobalPlatform Specifications:"));
            Assert.That(result, Does.Contain("GlobalPlatform Card Specification 2.2.3"));
            Assert.That(result, Does.Contain("All Capabilities:"));
        }
    }
}
