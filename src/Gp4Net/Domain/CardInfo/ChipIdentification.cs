namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// IC (Integrated Circuit) fabricator identification codes per ISO 7816-6.
/// These values are found in CPLC data bytes 0-1.
/// </summary>
public enum IcFabricator : ushort
{
    /// <summary>
    /// NXP Semiconductors (formerly Philips).
    /// </summary>
    NXP = 0x4790,

    /// <summary>
    /// Infineon Technologies.
    /// </summary>
    Infineon = 0x4090,

    /// <summary>
    /// STMicroelectronics.
    /// </summary>
    StMicroelectronics = 0x0205,

    /// <summary>
    /// Samsung.
    /// </summary>
    Samsung = 0x5354,

    /// <summary>
    /// Gemalto.
    /// </summary>
    Gemalto = 0x0182,

    /// <summary>
    /// Atmel.
    /// </summary>
    Atmel = 0x4180,

    /// <summary>
    /// Unknown fabricator.
    /// </summary>
    Unknown = 0x0000,
}

/// <summary>
/// IC (Integrated Circuit) type identification codes.
/// These values are found in CPLC data bytes 2-3.
/// </summary>
public enum IcType : ushort
{
    /// <summary>
    /// NXP SmartMX3 P71D321 secure microcontroller.
    /// Features: Java Card 3.0.5, GlobalPlatform 2.3.1, JCOP 4.
    /// </summary>
    P71D321 = 0xD321,

    /// <summary>
    /// NXP SmartMX3 P71D320 secure microcontroller.
    /// Features: Java Card 3.0.5, GlobalPlatform 2.3.1, JCOP 4.
    /// </summary>
    P71D320 = 0xD320,

    /// <summary>
    /// NXP SmartMX2 P61 secure microcontroller.
    /// </summary>
    P61 = 0x6100,

    /// <summary>
    /// NXP SmartMX2 P60 secure microcontroller.
    /// </summary>
    P60 = 0x6000,

    /// <summary>
    /// NXP SmartMX P5CD081 secure microcontroller.
    /// </summary>
    P5Cd081 = 0x5081,

    /// <summary>
    /// NXP SmartMX P5CD041 secure microcontroller.
    /// </summary>
    P5Cd041 = 0x5041,

    /// <summary>
    /// Unknown IC type.
    /// </summary>
    Unknown = 0x0000,
}

/// <summary>
/// Chip platform families for smart card microcontrollers.
/// </summary>
public enum ChipPlatform
{
    /// <summary>
    /// Unknown or unidentified platform.
    /// </summary>
    Unknown,

    /// <summary>
    /// NXP SmartMX3 platform with IntegralSecurity 2.0.
    /// Features: Common Criteria EAL6+, advanced crypto coprocessors.
    /// </summary>
    SmartMx3,

    /// <summary>
    /// NXP SmartMX2 platform.
    /// </summary>
    SmartMx2,

    /// <summary>
    /// NXP SmartMX platform (first generation).
    /// </summary>
    SmartMx,

    /// <summary>
    /// Infineon SLE66 platform.
    /// </summary>
    Sle66,

    /// <summary>
    /// Infineon SLE78 platform.
    /// </summary>
    Sle78,

    /// <summary>
    /// STMicroelectronics ST31 platform.
    /// </summary>
    St31,

    /// <summary>
    /// STMicroelectronics ST33 platform.
    /// </summary>
    St33,
}

/// <summary>
/// P71 memory configurations available for the SmartMX3 platform.
/// All P71D321 chips support these memory configurations.
/// </summary>
public enum P71MemoryConfiguration
{
    /// <summary>
    /// 256KB Flash memory with 12KB RAM.
    /// </summary>
    P71D251,

    /// <summary>
    /// 304KB Flash memory with 12KB RAM.
    /// </summary>
    P71D301,

    /// <summary>
    /// 344KB Flash memory with 12KB RAM.
    /// </summary>
    P71D351,

    /// <summary>
    /// 344KB Flash memory with 1KB RAM.
    /// Specialized configuration with minimal RAM.
    /// </summary>
    P71D352,
}

/// <summary>
/// Security certification levels for smart card chips.
/// </summary>
public enum SecurityCertification
{
    /// <summary>
    /// No formal security certification.
    /// </summary>
    None,

    /// <summary>
    /// Common Criteria EAL4+ certification.
    /// </summary>
    CommonCriteriaEal4Plus,

    /// <summary>
    /// Common Criteria EAL5+ certification.
    /// </summary>
    CommonCriteriaEal5Plus,

    /// <summary>
    /// Common Criteria EAL6+ certification.
    /// Highest commercially available security level.
    /// </summary>
    CommonCriteriaEal6Plus,

    /// <summary>
    /// FIPS 140-2 Level 1 certification.
    /// </summary>
    Fips1402Level1,

    /// <summary>
    /// FIPS 140-2 Level 2 certification.
    /// </summary>
    Fips1402Level2,

    /// <summary>
    /// FIPS 140-2 Level 3 certification.
    /// Physical security requirements.
    /// </summary>
    Fips1402Level3,

    /// <summary>
    /// EMVCo security certification for payment cards.
    /// </summary>
    EmvCo,
}

/// <summary>
/// Operating system identification codes.
/// These values are found in CPLC data bytes 4-5.
/// </summary>
public enum OperatingSystemId : ushort
{
    /// <summary>
    /// JCOP 4 operating system.
    /// Java Card Open Platform version 4.
    /// </summary>
    Jcop4 = 0x4700,

    /// <summary>
    /// JCOP 3 operating system.
    /// </summary>
    Jcop3 = 0x4600,

    /// <summary>
    /// JCOP 2.4.2 operating system.
    /// </summary>
    Jcop242 = 0x4242,

    /// <summary>
    /// JCOP 2.4.1 operating system.
    /// </summary>
    Jcop241 = 0x4241,

    /// <summary>
    /// Unknown operating system.
    /// </summary>
    Unknown = 0x0000,
}
