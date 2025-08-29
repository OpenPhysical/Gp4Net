using System.Collections.Immutable;
using AwesomeAssertions;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.CardInfo;

/// <summary>
/// Unit tests for ChipInfo and chip identification functionality.
/// </summary>
public class ChipInfoTests
{
    [Test]
    public void FromCplcData_WithP71D321_ReturnsCorrectChipInfo()
    {
        // Arrange
        CplcData cplc = new CplcData
        {
            IcFabricator = 0x4790, // NXP
            IcType = 0xD321,       // P71D321
            OperatingSystemId = 0x4700 // JCOP4
        };

        // Act
        ChipInfo? chipInfo = ChipInfo.FromCplcData(cplc);

        // Assert
        _ = chipInfo.Manufacturer.Should().Be(IcFabricator.NXP);
        _ = chipInfo.ChipType.Should().Be(IcType.P71D321);
        _ = chipInfo.Platform.Should().Be(ChipPlatform.SmartMX3);
        _ = chipInfo.Architecture.Should().Be("IntegralSecurity 2.0");
        _ = chipInfo.OperatingSystem.Should().Be(OperatingSystemId.JCOP4);
        _ = chipInfo.JavaCardVersion.HasValue.Should().BeTrue();
        _ = chipInfo.JavaCardVersion.Value.Should().Be("3.0.5");
        _ = chipInfo.GlobalPlatformVersion.HasValue.Should().BeTrue();
        _ = chipInfo.GlobalPlatformVersion.Value.Should().Be("2.3.1");
        _ = chipInfo.JcopVersion.HasValue.Should().BeTrue();
        _ = chipInfo.JcopVersion.Value.Should().Be("4");
        _ = chipInfo.CryptoCapabilities.Should().Be(CryptoCapabilities.P71D321Standard);
        _ = chipInfo.SecurityFeatures.Should().Be(SecurityFeatures.P71D321Standard);
        _ = chipInfo.Certifications.Should().Contain(SecurityCertification.CommonCriteriaEAL6Plus);
        _ = chipInfo.Certifications.Should().Contain(SecurityCertification.FIPS140_2_Level3);
    }

    [Test]
    public void FromCplcData_WithUnknownChip_ReturnsUnknownValues()
    {
        // Arrange
        CplcData cplc = new CplcData
        {
            IcFabricator = 0x9999, // Unknown
            IcType = 0x8888,       // Unknown
            OperatingSystemId = 0x7777 // Unknown
        };

        // Act
        ChipInfo? chipInfo = ChipInfo.FromCplcData(cplc);

        // Assert
        _ = chipInfo.Manufacturer.Should().Be(IcFabricator.Unknown);
        _ = chipInfo.ChipType.Should().Be(IcType.Unknown);
        _ = chipInfo.Platform.Should().Be(ChipPlatform.Unknown);
        _ = chipInfo.OperatingSystem.Should().Be(OperatingSystemId.Unknown);
        _ = chipInfo.JavaCardVersion.HasValue.Should().BeFalse();
        _ = chipInfo.GlobalPlatformVersion.HasValue.Should().BeFalse();
        _ = chipInfo.JcopVersion.HasValue.Should().BeFalse();
    }

    [Test]
    public void GetDescription_WithP71D321_ReturnsFormattedDescription()
    {
        // Arrange
        ChipInfo chipInfo = new ChipInfo
        {
            Manufacturer = IcFabricator.NXP,
            ChipType = IcType.P71D321,
            Platform = ChipPlatform.SmartMX3,
            MemoryConfig = P71MemoryConfiguration.P71D351
        };

        // Act
        string? description = chipInfo.GetDescription();

        // Assert
        _ = description.Should().Be("NXP SmartMX3 P71D321 344KB Flash / 12KB RAM");
    }

    [TestCase(P71MemoryConfiguration.P71D251, "256KB Flash / 12KB RAM")]
    [TestCase(P71MemoryConfiguration.P71D301, "304KB Flash / 12KB RAM")]
    [TestCase(P71MemoryConfiguration.P71D351, "344KB Flash / 12KB RAM")]
    [TestCase(P71MemoryConfiguration.P71D352, "344KB Flash / 1KB RAM")]
    public void GetMemoryDescription_WithDifferentConfigs_ReturnsCorrectDescription(
        P71MemoryConfiguration config, string expected)
    {
        // Arrange
        ChipInfo chipInfo = new ChipInfo
        {
            MemoryConfig = config
        };

        // Act
        string? description = chipInfo.GetMemoryDescription();

        // Assert
        _ = description.Should().Be(expected);
    }

    [Test]
    public void GetCertificationsString_WithMultipleCerts_ReturnsFormattedList()
    {
        // Arrange
        ChipInfo chipInfo = new ChipInfo
        {
            Certifications = new[]
            {
                SecurityCertification.CommonCriteriaEAL6Plus,
                SecurityCertification.FIPS140_2_Level3,
                SecurityCertification.EMVCo
            }.ToImmutableList()
        };

        // Act
        string? certifications = chipInfo.GetCertificationsString();

        // Assert
        _ = certifications.Should().Be("CC EAL6+, FIPS 140-2 L3, EMVCo");
    }

    [Test]
    public void GetOperatingSystemDescription_WithJCOP4_ReturnsFullDescription()
    {
        // Arrange
        ChipInfo chipInfo = new ChipInfo
        {
            JcopVersion = "4",
            JavaCardVersion = "3.0.5",
            GlobalPlatformVersion = "2.3.1"
        };

        // Act
        string? description = chipInfo.GetOperatingSystemDescription();

        // Assert
        _ = description.Should().Be("JCOP 4 / Java Card 3.0.5 / GP 2.3.1");
    }

    [Test]
    public void GetCryptoSummary_WithP71Capabilities_ReturnsComprehensiveSummary()
    {
        // Arrange
        ChipInfo chipInfo = new ChipInfo
        {
            CryptoCapabilities = CryptoCapabilities.P71D321Standard
        };

        // Act
        string? summary = chipInfo.GetCryptoSummary();

        // Assert
        _ = summary.Should().Contain("3DES");
        _ = summary.Should().Contain("AES-128/192/256");
        _ = summary.Should().Contain("RSA-2048/4096");
        _ = summary.Should().Contain("ECC P-256/384/521/544");
    }

    [Test]
    public void CplcData_GetManufacturerName_WithKnownManufacturer_ReturnsName()
    {
        // Arrange
        CplcData cplc = new CplcData
        {
            IcFabricator = 0x4790 // NXP
        };

        // Act
        string? name = cplc.GetManufacturerName();

        // Assert
        _ = name.Should().Be("NXP");
    }

    [Test]
    public void CplcData_GetManufacturerName_WithUnknownManufacturer_ReturnsHexCode()
    {
        // Arrange
        CplcData cplc = new CplcData
        {
            IcFabricator = 0x9999
        };

        // Act
        string? name = cplc.GetManufacturerName();

        // Assert
        _ = name.Should().Be("Unknown (0x9999)");
    }

    [Test]
    public void CplcData_GetChipModel_WithKnownModel_ReturnsName()
    {
        // Arrange
        CplcData cplc = new CplcData
        {
            IcType = 0xD321 // P71D321
        };

        // Act
        string? model = cplc.GetChipModel();

        // Assert
        _ = model.Should().Be("P71D321");
    }

    [Test]
    public void CplcData_GetOperatingSystemName_WithKnownOS_ReturnsName()
    {
        // Arrange
        CplcData cplc = new CplcData
        {
            OperatingSystemId = 0x4700 // JCOP4
        };

        // Act
        string? osName = cplc.GetOperatingSystemName();

        // Assert
        _ = osName.Should().Be("JCOP4");
    }
}