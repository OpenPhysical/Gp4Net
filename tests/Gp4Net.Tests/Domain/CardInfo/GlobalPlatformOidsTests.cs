using System.Linq;
using Gp4Net.Domain.CardInfo;
using Xunit;

namespace Gp4Net.Tests.Domain.CardInfo
{
    public class GlobalPlatformOidsTests
    {
        [Fact]
        public void GetDescription_ShouldReturnCorrectDescriptionForKnownOids()
        {
            // Act & Assert
            Assert.Equal("GlobalPlatform", GlobalPlatformOids.GetDescription("1.2.840.114283.1"));
            Assert.Equal(
                "Secure Channel Protocol 03 (SCP03)",
                GlobalPlatformOids.GetDescription("1.2.840.114283.4.3")
            );
            Assert.Equal(
                "SCP03 with S-ENC and S-MAC",
                GlobalPlatformOids.GetDescription("1.2.840.114283.4.3.112")
            );
            Assert.Equal(
                "Oracle Java Card VM",
                GlobalPlatformOids.GetDescription("1.3.6.1.4.1.42.2.110.1.3")
            );
        }

        [Fact]
        public void GetDescription_ShouldReturnNullForUnknownOids()
        {
            // Act & Assert
            Assert.Null(GlobalPlatformOids.GetDescription("1.2.3.4.5.6.7.8.9"));
            Assert.Null(GlobalPlatformOids.GetDescription(""));
            Assert.Null(GlobalPlatformOids.GetDescription(null));
        }

        [Fact]
        public void IsGlobalPlatformOid_ShouldIdentifyGpOidsCorrectly()
        {
            // Act & Assert
            Assert.True(GlobalPlatformOids.IsGlobalPlatformOid("1.2.840.114283.1"));
            Assert.True(GlobalPlatformOids.IsGlobalPlatformOid("1.2.840.114283.4.3.112"));
            Assert.False(GlobalPlatformOids.IsGlobalPlatformOid("1.3.6.1.4.1.42.2.110.1.3"));
            Assert.False(GlobalPlatformOids.IsGlobalPlatformOid(""));
            Assert.False(GlobalPlatformOids.IsGlobalPlatformOid(null));
        }

        [Fact]
        public void GetScpVersion_ShouldExtractScpVersionFromOid()
        {
            // Act & Assert
            Assert.Equal("SCP00", GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.0"));
            Assert.Equal("SCP01", GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.1"));
            Assert.Equal("SCP02", GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.2"));
            Assert.Equal("SCP03", GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.3"));
            Assert.Equal("SCP03", GlobalPlatformOids.GetScpVersion("1.2.840.114283.4.3.112"));
        }

        [Fact]
        public void GetScpVersion_ShouldReturnNullForNonScpOids()
        {
            // Act & Assert
            Assert.Null(GlobalPlatformOids.GetScpVersion("1.2.840.114283.1"));
            Assert.Null(GlobalPlatformOids.GetScpVersion("1.3.6.1.4.1.42.2.110.1.3"));
            Assert.Null(GlobalPlatformOids.GetScpVersion(""));
            Assert.Null(GlobalPlatformOids.GetScpVersion(null));
        }

        [Fact]
        public void FormatOid_ShouldIncludeDescriptionForKnownOids()
        {
            // Act & Assert
            Assert.Equal(
                "1.2.840.114283.1 (GlobalPlatform)",
                GlobalPlatformOids.FormatOid("1.2.840.114283.1")
            );
            Assert.Equal(
                "1.2.840.114283.4.3.112 (SCP03 with S-ENC and S-MAC)",
                GlobalPlatformOids.FormatOid("1.2.840.114283.4.3.112")
            );
        }

        [Fact]
        public void FormatOid_ShouldReturnOidOnlyForUnknownOids()
        {
            // Act & Assert
            Assert.Equal("1.2.3.4.5", GlobalPlatformOids.FormatOid("1.2.3.4.5"));
            Assert.Equal("", GlobalPlatformOids.FormatOid(""));
            Assert.Null(GlobalPlatformOids.FormatOid(null));
        }

        [Fact]
        public void GetAllKnownOids_ShouldReturnNonEmptyDictionary()
        {
            // Act
            var knownOids = GlobalPlatformOids.GetAllKnownOids();

            // Assert
            Assert.NotEmpty(knownOids);
            Assert.Contains("1.2.840.114283.1", knownOids.Keys);
            Assert.Contains("1.2.840.114283.4.3.112", knownOids.Keys);
        }

        [Fact]
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
            Assert.Contains("SCP02", summary.SupportedScpVersions);
            Assert.Contains("SCP03", summary.SupportedScpVersions);
            Assert.True(summary.SupportsScp03WithEncryption);
            Assert.Contains(
                "GlobalPlatform Card Specification 2.2.3",
                summary.SpecificationVersions
            );
            Assert.Equal(6, summary.AllOids.Count);
        }

        [Fact]
        public void AnalyzeOids_ShouldHandleEmptyList()
        {
            // Act
            var summary = GlobalPlatformOids.AnalyzeOids(new string[0]);

            // Assert
            Assert.Empty(summary.SupportedScpVersions);
            Assert.Empty(summary.SpecificationVersions);
            Assert.Empty(summary.AllOids);
            Assert.False(summary.SupportsScp03WithEncryption);
        }

        [Fact]
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
            Assert.Contains("Supported Secure Channel Protocols:", result);
            Assert.Contains("SCP02", result);
            Assert.Contains("SCP03", result);
            Assert.Contains("GlobalPlatform Specifications:", result);
            Assert.Contains("GlobalPlatform Card Specification 2.2.3", result);
            Assert.Contains("All Capabilities:", result);
        }
    }
}
