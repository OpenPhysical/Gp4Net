using System.Linq;
using JetBrains.Annotations;

namespace Gp4Net.Constants;

/// <summary>
/// SCP implementation parameters as defined in GlobalPlatform Card Specification v2.3.1.
/// For SCP02, the "i" parameter is a bitmap on one byte according to Table E-1.
/// For SCP03, implementation options are defined separately.
/// </summary>
[PublicAPI]
public enum ScpImplementation : byte
{
    // ==========================================
    // SCP02 Implementation Options (Complete)
    // Based on bitmap structure from GP Card Spec v2.3.1 Table E-1
    // ==========================================

    /// <summary>
    /// SCP02 i=00: Implicit mode, modified APDU, zero ICV, no ICV encryption, 1 base key, unspecified challenge, no R-MAC
    /// Bitmap: 00000000 (b1=0, b2=0, b3=0, b4=0, b5=0, b6=0, b7=0)
    /// </summary>
    Scp02I00 = 0x00,

    /// <summary>
    /// SCP02 i=02: Implicit mode, unmodified APDU, zero ICV, no ICV encryption, 1 base key, unspecified challenge, no R-MAC
    /// Bitmap: 00000010 (b1=0, b2=1, b3=0, b4=0, b5=0, b6=0, b7=0)
    /// </summary>
    Scp02I02 = 0x02,

    /// <summary>
    /// SCP02 i=04: Explicit mode, modified APDU, zero ICV, no ICV encryption, 1 base key, unspecified challenge, no R-MAC
    /// Bitmap: 00000100 (b1=0, b2=0, b3=1, b4=0, b5=0, b6=0, b7=0)
    /// </summary>
    Scp02I04 = 0x04,

    /// <summary>
    /// SCP02 i=05: Explicit mode, modified APDU, zero ICV, no ICV encryption, 3 keys, unspecified challenge, no R-MAC
    /// Bitmap: 00000101 (b1=1, b2=0, b3=1, b4=0, b5=0, b6=0, b7=0)
    /// </summary>
    Scp02I05 = 0x05,

    /// <summary>
    /// SCP02 i=0A: Implicit mode, unmodified APDU, MAC over AID, no ICV encryption, 1 base key, unspecified challenge, no R-MAC
    /// Bitmap: 00001010 (b1=0, b2=1, b3=0, b4=1, b5=0, b6=0, b7=0)
    /// </summary>
    Scp02I0A = 0x0A,

    /// <summary>
    /// SCP02 i=14: Explicit mode, modified APDU, zero ICV, ICV encryption, 1 base key, unspecified challenge, no R-MAC
    /// Bitmap: 00010100 (b1=0, b2=0, b3=1, b4=0, b5=1, b6=0, b7=0)
    /// </summary>
    Scp02I14 = 0x14,

    /// <summary>
    /// SCP02 i=15: Explicit mode, modified APDU, zero ICV, ICV encryption, 3 keys, unspecified challenge, no R-MAC
    /// Bitmap: 00010101 (b1=1, b2=0, b3=1, b4=0, b5=1, b6=0, b7=0)
    /// </summary>
    Scp02I15 = 0x15,

    /// <summary>
    /// SCP02 i=1A: Implicit mode, unmodified APDU, MAC over AID, ICV encryption, 1 base key, unspecified challenge, no R-MAC
    /// Bitmap: 00011010 (b1=0, b2=1, b3=0, b4=1, b5=1, b6=0, b7=0)
    /// </summary>
    Scp02I1A = 0x1A,

    /// <summary>
    /// SCP02 i=24: Explicit mode, modified APDU, zero ICV, no ICV encryption, 1 base key, unspecified challenge, R-MAC support
    /// Bitmap: 00100100 (b1=0, b2=0, b3=1, b4=0, b5=0, b6=1, b7=0)
    /// </summary>
    Scp02I24 = 0x24,

    /// <summary>
    /// SCP02 i=25: Explicit mode, modified APDU, zero ICV, no ICV encryption, 3 keys, unspecified challenge, R-MAC support
    /// Bitmap: 00100101 (b1=1, b2=0, b3=1, b4=0, b5=0, b6=1, b7=0)
    /// </summary>
    Scp02I25 = 0x25,

    /// <summary>
    /// SCP02 i=2A: Implicit mode, unmodified APDU, MAC over AID, no ICV encryption, 1 base key, unspecified challenge, R-MAC support
    /// Bitmap: 00101010 (b1=0, b2=1, b3=0, b4=1, b5=0, b6=1, b7=0)
    /// </summary>
    Scp02I2A = 0x2A,

    /// <summary>
    /// SCP02 i=34: Explicit mode, modified APDU, zero ICV, ICV encryption, 1 base key, unspecified challenge, R-MAC support
    /// Bitmap: 00110100 (b1=0, b2=0, b3=1, b4=0, b5=1, b6=1, b7=0)
    /// </summary>
    Scp02I34 = 0x34,

    /// <summary>
    /// SCP02 i=35: Explicit mode, modified APDU, zero ICV, ICV encryption, 3 keys, unspecified challenge, R-MAC support
    /// Bitmap: 00110101 (b1=1, b2=0, b3=1, b4=0, b5=1, b6=1, b7=0)
    /// </summary>
    Scp02I35 = 0x35,

    /// <summary>
    /// SCP02 i=3A: Implicit mode, unmodified APDU, MAC over AID, ICV encryption, 1 base key, unspecified challenge, R-MAC support
    /// Bitmap: 00111010 (b1=0, b2=1, b3=0, b4=1, b5=1, b6=1, b7=0)
    /// </summary>
    Scp02I3A = 0x3A,

    /// <summary>
    /// SCP02 i=44: Explicit mode, modified APDU, zero ICV, no ICV encryption, 1 base key, well-known challenge, no R-MAC
    /// Bitmap: 01000100 (b1=0, b2=0, b3=1, b4=0, b5=0, b6=0, b7=1)
    /// </summary>
    Scp02I44 = 0x44,

    /// <summary>
    /// SCP02 i=45: Explicit mode, modified APDU, zero ICV, no ICV encryption, 3 keys, well-known challenge, no R-MAC
    /// Bitmap: 01000101 (b1=1, b2=0, b3=1, b4=0, b5=0, b6=0, b7=1)
    /// </summary>
    Scp02I45 = 0x45,

    /// <summary>
    /// SCP02 i=4A: Implicit mode, unmodified APDU, MAC over AID, no ICV encryption, 1 base key, well-known challenge, no R-MAC
    /// Bitmap: 01001010 (b1=0, b2=1, b3=0, b4=1, b5=0, b6=0, b7=1)
    /// </summary>
    Scp02I4A = 0x4A,

    /// <summary>
    /// SCP02 i=54: Explicit mode, modified APDU, zero ICV, ICV encryption, 1 base key, well-known challenge, no R-MAC
    /// Bitmap: 01010100 (b1=0, b2=0, b3=1, b4=0, b5=1, b6=0, b7=1)
    /// </summary>
    Scp02I54 = 0x54,

    /// <summary>
    /// SCP02 i=55: Explicit mode, modified APDU, zero ICV, ICV encryption, 3 keys, well-known challenge, no R-MAC
    /// Bitmap: 01010101 (b1=1, b2=0, b3=1, b4=0, b5=1, b6=0, b7=1)
    /// </summary>
    Scp02I55 = 0x55,

    /// <summary>
    /// SCP02 i=64: Explicit mode, modified APDU, zero ICV, no ICV encryption, 1 base key, well-known challenge, R-MAC support
    /// Bitmap: 01100100 (b1=0, b2=0, b3=1, b4=0, b5=0, b6=1, b7=1)
    /// </summary>
    Scp02I64 = 0x64,

    /// <summary>
    /// SCP02 i=65: Explicit mode, modified APDU, zero ICV, no ICV encryption, 3 keys, well-known challenge, R-MAC support
    /// Bitmap: 01100101 (b1=1, b2=0, b3=1, b4=0, b5=0, b6=1, b7=1)
    /// </summary>
    Scp02I65 = 0x65,

    /// <summary>
    /// SCP02 i=6A: Implicit mode, unmodified APDU, MAC over AID, no ICV encryption, 1 base key, well-known challenge, R-MAC support
    /// Bitmap: 01101010 (b1=0, b2=1, b3=0, b4=1, b5=0, b6=1, b7=1)
    /// </summary>
    Scp02I6A = 0x6A,

    /// <summary>
    /// SCP02 i=74: Explicit mode, modified APDU, zero ICV, ICV encryption, 1 base key, well-known challenge, R-MAC support
    /// Bitmap: 01110100 (b1=0, b2=0, b3=1, b4=0, b5=1, b6=1, b7=1)
    /// </summary>
    Scp02I74 = 0x74,

    /// <summary>
    /// SCP02 i=75: Explicit mode, modified APDU, zero ICV, ICV encryption, 3 keys, well-known challenge, R-MAC support
    /// Bitmap: 01110101 (b1=1, b2=0, b3=1, b4=0, b5=1, b6=1, b7=1)
    /// </summary>
    Scp02I75 = 0x75,

    /// <summary>
    /// SCP02 i=7A: Implicit mode, unmodified APDU, MAC over AID, ICV encryption, 1 base key, well-known challenge, R-MAC support
    /// Bitmap: 01111010 (b1=0, b2=1, b3=0, b4=1, b5=1, b6=1, b7=1)
    /// </summary>
    Scp02I7A = 0x7A,

    /// <summary>SCP03 i=00: S8, random challenge, no response protection.</summary>
    Scp03I00 = 0x00,

    /// <summary>SCP03 i=10: S8, pseudo-random challenge, no response protection.</summary>
    Scp03I10 = 0x10,

    /// <summary>SCP03 i=20: S8, random challenge, R-MAC.</summary>
    Scp03I20 = 0x20,

    /// <summary>SCP03 i=30: S8, pseudo-random challenge, R-MAC.</summary>
    Scp03I30 = 0x30,

    /// <summary>SCP03 i=60: S8, random challenge, R-MAC and R-ENC.</summary>
    Scp03I60 = 0x60,

    /// <summary>SCP03 i=70: S8, pseudo-random challenge, R-MAC and R-ENC.</summary>
    Scp03I70 = 0x70,
}

/// <summary>
/// Extension methods for ScpImplementation enum based on bitmap analysis per GP Card Spec v2.3.1 Table E-1.
/// </summary>
[PublicAPI]
public static class ScpImplementationExtensions
{
    /// <summary>
    /// Determines if this implementation has R-MAC support.
    /// Per GP Card Spec Table E-1, bit b6 (0x20) indicates R-MAC support.
    /// </summary>
    /// <param name="impl">The SCP implementation to check</param>
    /// <returns>True if R-MAC is supported, false otherwise</returns>
    public static bool HasRMacSupport(this ScpImplementation impl)
    {
        return ((byte)impl & 0x20) != 0;
    }

    /// <summary>
    /// Determines if this implementation uses 3 separate keys (ENC/MAC/DEK).
    /// Per GP Card Spec Table E-1, bit b1 (0x01) indicates 3 Secure Channel Keys vs 1 base key.
    /// </summary>
    /// <param name="impl">The SCP implementation to check</param>
    /// <returns>True if 3 keys are used, false if 1 base key is used</returns>
    public static bool Uses3Keys(this ScpImplementation impl)
    {
        return ((byte)impl & 0x01) != 0;
    }

    /// <summary>
    /// Determines if this implementation uses explicit initiation mode.
    /// Per GP Card Spec Table E-1, bit b3 (0x04) indicates initiation mode.
    /// </summary>
    /// <param name="impl">The SCP implementation to check</param>
    /// <returns>True for explicit mode, false for implicit mode</returns>
    public static bool IsExplicitMode(this ScpImplementation impl)
    {
        return ((byte)impl & 0x04) != 0;
    }

    /// <summary>
    /// Determines if this implementation has ICV encryption for C-MAC session.
    /// Per GP Card Spec Table E-1, bit b5 (0x10) indicates ICV encryption.
    /// </summary>
    /// <param name="impl">The SCP implementation to check</param>
    /// <returns>True if ICV encryption is enabled, false otherwise</returns>
    public static bool HasIcvEncryption(this ScpImplementation impl)
    {
        return ((byte)impl & 0x10) != 0;
    }

    /// <summary>
    /// Determines if this implementation uses well-known pseudo-random algorithm for card challenge.
    /// Per GP Card Spec Table E-1, bit b7 (0x40) indicates challenge generation method.
    /// </summary>
    /// <param name="impl">The SCP implementation to check</param>
    /// <returns>True for well-known algorithm, false for unspecified method</returns>
    public static bool UsesWellKnownChallenge(this ScpImplementation impl)
    {
        return ((byte)impl & 0x40) != 0;
    }

    /// <summary>
    /// Determines if this implementation has ICV set to MAC over AID.
    /// Per GP Card Spec Table E-1, bit b4 (0x08) indicates ICV initialization.
    /// </summary>
    /// <param name="impl">The SCP implementation to check</param>
    /// <returns>True for MAC over AID, false for zero ICV</returns>
    public static bool HasMacOverAid(this ScpImplementation impl)
    {
        return ((byte)impl & 0x08) != 0;
    }

    /// <summary>
    /// Determines if this implementation uses C-MAC on modified APDU.
    /// Per GP Card Spec Table E-1, bit b2 (0x02) indicates APDU modification.
    /// </summary>
    /// <param name="impl">The SCP implementation to check</param>
    /// <returns>True for modified APDU, false for unmodified APDU</returns>
    public static bool UsesModifiedApdu(this ScpImplementation impl)
    {
        return ((byte)impl & 0x02) == 0;
    }

    /// <summary>
    /// Gets a human-readable description of the implementation features.
    /// </summary>
    /// <param name="impl">The SCP implementation to describe</param>
    /// <returns>A detailed description string</returns>
    public static string GetDescription(this ScpImplementation impl)
    {
        var baseFeatures = new[]
        {
            impl.IsExplicitMode() ? "Explicit" : "Implicit",
            impl.UsesModifiedApdu() ? "Modified APDU" : "Unmodified APDU",
            impl.Uses3Keys() ? "3 Keys" : "1 Base Key",
        };

        var optionalFeatures = new[]
        {
            impl.HasIcvEncryption() ? "ICV Encryption" : "",
            impl.HasRMacSupport() ? "R-MAC" : "",
            impl.UsesWellKnownChallenge() ? "Well-known Challenge" : "",
            impl.HasMacOverAid() ? "MAC over AID" : "",
        }.Where(static f => !string.IsNullOrEmpty(f));

        var allFeatures = baseFeatures.Concat(optionalFeatures);
        return $"i={(byte)impl:X2}: {string.Join(", ", allFeatures)}";
    }

    /// <summary>
    /// Gets the specific alias for common implementations.
    /// </summary>
    /// <param name="impl">The SCP implementation</param>
    /// <returns>The alias string if available, otherwise the hex representation</returns>
    public static string GetAlias(this ScpImplementation impl)
    {
        return impl switch
        {
            ScpImplementation.Scp02I15 => "CLR",
            ScpImplementation.Scp02I35 => "MAC",
            ScpImplementation.Scp02I55 => "ENC",
            ScpImplementation.Scp02I75 => "RENC",
            ScpImplementation.Scp02I1A => "IMPLICIT",
            ScpImplementation.Scp02I14 => "BASE_KEY",
            _ => $"{(byte)impl:X2}",
        };
    }

    /// <summary>SCP03 Amendment D v1.1.2, Table 5-1: b5 selects pseudo-random challenge generation.</summary>
    public static bool UsesScp03PseudoRandomChallenge(this ScpImplementation impl) =>
        ((byte)impl & 0x10) != 0;

    /// <summary>SCP03 Amendment D v1.1.2, Table 5-1: b7 and b6 set together enable R-ENC.</summary>
    public static bool HasScp03ResponseEncryption(this ScpImplementation impl) =>
        ((byte)impl & 0x60) == 0x60;

    /// <summary>SCP03 Amendment D v1.1.2, Table 5-1.</summary>
    public static string GetScp03Description(this ScpImplementation impl)
    {
        string responseProtection = impl.HasScp03ResponseEncryption()
            ? "R-MAC and R-ENC"
            : impl.HasRMacSupport()
                ? "R-MAC"
                : "No response protection";
        return string.Join(
            ", ",
            "S8",
            impl.UsesScp03PseudoRandomChallenge() ? "Pseudo-random challenge" : "Random challenge",
            responseProtection
        );
    }
}
