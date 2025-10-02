using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Comprehensive information about a smart card chip including manufacturer,
/// platform, capabilities, and certifications.
/// </summary>
public class ChipInfo
{
    /// <summary>
    /// Gets or sets the IC fabricator/manufacturer.
    /// </summary>
    public IcFabricator Manufacturer { get; set; }

    /// <summary>
    /// Gets or sets the specific chip type/model.
    /// </summary>
    public IcType ChipType { get; set; }

    /// <summary>
    /// Gets or sets the chip platform family.
    /// </summary>
    public ChipPlatform Platform { get; set; }

    /// <summary>
    /// Gets or sets the memory configuration for P71 chips.
    /// </summary>
    public Maybe<P71MemoryConfiguration> MemoryConfig { get; set; }

    /// <summary>
    /// Gets or sets the security architecture name.
    /// </summary>
    public string Architecture { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the list of security certifications.
    /// </summary>
    public ImmutableList<SecurityCertification> Certifications { get; set; } =
        ImmutableList<SecurityCertification>.Empty;

    /// <summary>
    /// Gets or sets the cryptographic capabilities.
    /// </summary>
    public CryptoCapabilities CryptoCapabilities { get; set; }

    /// <summary>
    /// Gets or sets the security features.
    /// </summary>
    public SecurityFeatures SecurityFeatures { get; set; }

    /// <summary>
    /// Gets or sets the operating system identifier.
    /// </summary>
    public OperatingSystemId OperatingSystem { get; set; }

    /// <summary>
    /// Gets or sets the Java Card version if applicable.
    /// </summary>
    public Maybe<string> JavaCardVersion { get; set; }

    /// <summary>
    /// Gets or sets the GlobalPlatform version if applicable.
    /// </summary>
    public Maybe<string> GlobalPlatformVersion { get; set; }

    /// <summary>
    /// Gets or sets the JCOP version if applicable.
    /// </summary>
    public Maybe<string> JcopVersion { get; set; }

    /// <summary>
    /// Creates chip information from CPLC data.
    /// </summary>
    /// <param name="cplc">The CPLC data to analyze.</param>
    /// <returns>Chip information derived from CPLC data.</returns>
    public static ChipInfo FromCplcData(CplcData cplc)
    {
        var info = new ChipInfo
        {
            Manufacturer = Enum.IsDefined(typeof(IcFabricator), cplc.IcFabricator)
                ? (IcFabricator)cplc.IcFabricator
                : IcFabricator.Unknown,
            ChipType = Enum.IsDefined(typeof(IcType), cplc.IcType)
                ? (IcType)cplc.IcType
                : IcType.Unknown,
            OperatingSystem = Enum.IsDefined(typeof(OperatingSystemId), cplc.OperatingSystemId)
                ? (OperatingSystemId)cplc.OperatingSystemId
                : OperatingSystemId.Unknown,
        };

        // Determine platform and capabilities based on chip type
        switch (info.ChipType)
        {
            case IcType.P71D321:
            case IcType.P71D320:
                info.Platform = ChipPlatform.SmartMx3;
                info.Architecture = "IntegralSecurity 2.0";
                info.Certifications = ImmutableList.Create(
                    SecurityCertification.CommonCriteriaEal6Plus,
                    SecurityCertification.Fips1402Level3
                );
                info.CryptoCapabilities = CryptoCapabilities.P71D321Standard;
                info.SecurityFeatures = SecurityFeatures.P71D321Standard;
                info.MemoryConfig = P71MemoryConfiguration.P71D351; // Default, should be determined from actual config
                break;

            case IcType.P61:
            case IcType.P60:
                info.Platform = ChipPlatform.SmartMx2;
                info.Architecture = "IntegralSecurity";
                info.Certifications = ImmutableList.Create(
                    SecurityCertification.CommonCriteriaEal5Plus
                );
                break;

            case IcType.P5Cd081:
            case IcType.P5Cd041:
                info.Platform = ChipPlatform.SmartMx;
                info.Architecture = "IntegralSecurity";
                info.Certifications = ImmutableList.Create(
                    SecurityCertification.CommonCriteriaEal5Plus
                );
                break;

            default:
                info.Platform = ChipPlatform.Unknown;
                break;
        }

        // Determine OS-specific information
        switch (info.OperatingSystem)
        {
            case OperatingSystemId.Jcop4:
                info.JcopVersion = "4";
                info.JavaCardVersion = "3.0.5";
                info.GlobalPlatformVersion = "2.3.1";
                break;

            case OperatingSystemId.Jcop3:
                info.JcopVersion = "3";
                info.JavaCardVersion = "3.0.4";
                info.GlobalPlatformVersion = "2.2.1";
                break;

            case OperatingSystemId.Jcop242:
                info.JcopVersion = "2.4.2";
                info.JavaCardVersion = "2.2.2";
                info.GlobalPlatformVersion = "2.1.1";
                break;

            case OperatingSystemId.Jcop241:
                info.JcopVersion = "2.4.1";
                info.JavaCardVersion = "2.2.2";
                info.GlobalPlatformVersion = "2.1.1";
                break;
        }

        return info;
    }

    /// <summary>
    /// Gets a human-readable description of the chip.
    /// </summary>
    /// <returns>Formatted chip description.</returns>
    public string GetDescription()
    {
        var parts = new[]
        {
            Manufacturer != IcFabricator.Unknown ? GetManufacturerName(Manufacturer) : null,
            Platform != ChipPlatform.Unknown ? GetPlatformName(Platform) : null,
            ChipType != IcType.Unknown ? ChipType.ToString() : null,
            MemoryConfig.HasValue ? GetMemoryDescription() : null,
        }.Where(p => !string.IsNullOrEmpty(p));

        return string.Join(" ", parts);
    }

    private static string GetManufacturerName(IcFabricator manufacturer) =>
        manufacturer switch
        {
            IcFabricator.NXP => "NXP",
            IcFabricator.Infineon => "Infineon",
            IcFabricator.StMicroelectronics => "STMicroelectronics",
            IcFabricator.Samsung => "Samsung",
            IcFabricator.Gemalto => "Gemalto",
            IcFabricator.Atmel => "Atmel",
            _ => manufacturer.ToString(),
        };

    private static string GetPlatformName(ChipPlatform platform) =>
        platform switch
        {
            ChipPlatform.SmartMx3 => "SmartMX3",
            ChipPlatform.SmartMx2 => "SmartMX2",
            ChipPlatform.SmartMx => "SmartMX",
            ChipPlatform.Sle66 => "SLE66",
            ChipPlatform.Sle78 => "SLE78",
            ChipPlatform.St31 => "ST31",
            ChipPlatform.St33 => "ST33",
            _ => platform.ToString(),
        };

    /// <summary>
    /// Gets a description of the memory configuration.
    /// </summary>
    /// <returns>Memory configuration description.</returns>
    public string GetMemoryDescription()
    {
        return MemoryConfig.Match(
            Some: config =>
                config switch
                {
                    P71MemoryConfiguration.P71D251 => "256KB Flash / 12KB RAM",
                    P71MemoryConfiguration.P71D301 => "304KB Flash / 12KB RAM",
                    P71MemoryConfiguration.P71D351 => "344KB Flash / 12KB RAM",
                    P71MemoryConfiguration.P71D352 => "344KB Flash / 1KB RAM",
                    _ => "Unknown memory configuration",
                },
            None: () => "Unknown memory configuration"
        );
    }

    /// <summary>
    /// Gets a formatted string of security certifications.
    /// </summary>
    /// <returns>Comma-separated list of certifications.</returns>
    public string GetCertificationsString()
    {
        if (!Certifications.Any())
            return "None";

        return string.Join(
            ", ",
            Certifications.Select(c =>
                c switch
                {
                    SecurityCertification.CommonCriteriaEal4Plus => "CC EAL4+",
                    SecurityCertification.CommonCriteriaEal5Plus => "CC EAL5+",
                    SecurityCertification.CommonCriteriaEal6Plus => "CC EAL6+",
                    SecurityCertification.Fips1402Level1 => "FIPS 140-2 L1",
                    SecurityCertification.Fips1402Level2 => "FIPS 140-2 L2",
                    SecurityCertification.Fips1402Level3 => "FIPS 140-2 L3",
                    SecurityCertification.EmvCo => "EMVCo",
                    _ => c.ToString(),
                }
            )
        );
    }

    /// <summary>
    /// Gets the operating system description including version information.
    /// </summary>
    /// <returns>Operating system description.</returns>
    public string GetOperatingSystemDescription()
    {
        var parts = new[]
        {
            JcopVersion.Match(v => $"JCOP {v}", () => null),
            JavaCardVersion.Match(v => $"Java Card {v}", () => null),
            GlobalPlatformVersion.Match(v => $"GP {v}", () => null),
        }.Where(p => p != null);

        return string.Join(" / ", parts);
    }

    /// <summary>
    /// Gets a summary of cryptographic capabilities.
    /// </summary>
    /// <returns>Crypto capabilities summary.</returns>
    public string GetCryptoSummary()
    {
        var capabilities = new[]
        {
            CryptoCapabilities.HasFlag(CryptoCapabilities.TripleDes) ? "3DES" : null,
            CryptoCapabilities.HasFlag(CryptoCapabilities.Aes256)
                ? "AES-128/192/256"
                : CryptoCapabilities.HasFlag(CryptoCapabilities.Aes192)
                    ? "AES-128/192"
                    : CryptoCapabilities.HasFlag(CryptoCapabilities.Aes128)
                        ? "AES-128"
                        : null,
            CryptoCapabilities.HasFlag(CryptoCapabilities.Rsa4096)
                ? "RSA-2048/4096"
                : CryptoCapabilities.HasFlag(CryptoCapabilities.Rsa2048)
                    ? "RSA-2048"
                    : null,
            CryptoCapabilities.HasFlag(CryptoCapabilities.Ecc544)
                ? "ECC P-256/384/521/544"
                : CryptoCapabilities.HasFlag(CryptoCapabilities.Ecc521)
                    ? "ECC P-256/384/521"
                    : CryptoCapabilities.HasFlag(CryptoCapabilities.Ecc256)
                        ? "ECC P-256"
                        : null,
        }.Where(c => c != null);

        return string.Join(", ", capabilities);
    }
}
