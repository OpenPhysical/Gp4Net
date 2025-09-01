using System;

namespace Gp4Net.Domain;

/// <summary>
/// Security level flags for secure channel protocols.
/// </summary>
[Flags]
public enum SecurityLevel : byte
{
    /// <summary>
    /// No security.
    /// </summary>
    None = 0x00,

    /// <summary>
    /// C-MAC on commands.
    /// </summary>
    CMac = 0x01,

    /// <summary>
    /// C-DECRYPTION and C-MAC.
    /// GP Card Specification v2.3.1: Combined flag for command MAC and decryption.
    /// </summary>
    CDecryption = 0x03,

    /// <summary>
    /// Command encryption capability (separate from decryption for protocol flexibility).
    /// Note: In most GP implementations, encryption and decryption use the same key material,
    /// but this flag allows distinguishing encryption vs decryption operations.
    /// </summary>
    CEncryption = 0x02,

    /// <summary>
    /// R-MAC on responses.
    /// </summary>
    RMac = 0x10,

    /// <summary>
    /// R-ENCRYPTION on responses.
    /// </summary>
    REncryption = 0x20,
}

/// <summary>
/// Functional extension methods for SecurityLevel operations.
/// </summary>
public static class SecurityLevelExtensions
{
    /// <summary>
    /// Checks if the security level includes C-MAC.
    /// </summary>
    public static bool HasCMac(this SecurityLevel level)
    {
        return (level & SecurityLevel.CMac) != 0;
    }

    /// <summary>
    /// Checks if the security level includes C-DECRYPTION.
    /// </summary>
    public static bool HasCDecryption(this SecurityLevel level)
    {
        return (level & SecurityLevel.CDecryption) == SecurityLevel.CDecryption;
    }

    /// <summary>
    /// Checks if the security level includes C-ENCRYPTION.
    /// GP Card Specification v2.3.1: Command encryption capability for outbound operations.
    /// </summary>
    public static bool HasCEncryption(this SecurityLevel level)
    {
        return (level & SecurityLevel.CEncryption) != 0;
    }

    /// <summary>
    /// Checks if the security level includes R-MAC.
    /// </summary>
    public static bool HasRMac(this SecurityLevel level)
    {
        return (level & SecurityLevel.RMac) != 0;
    }

    /// <summary>
    /// Checks if the security level includes R-ENCRYPTION.
    /// </summary>
    public static bool HasREncryption(this SecurityLevel level)
    {
        return (level & SecurityLevel.REncryption) != 0;
    }

    /// <summary>
    /// Combines two security levels.
    /// </summary>
    public static SecurityLevel Combine(this SecurityLevel level, SecurityLevel other)
    {
        return level | other;
    }

    /// <summary>
    /// Removes security level flags.
    /// </summary>
    public static SecurityLevel Remove(this SecurityLevel level, SecurityLevel toRemove)
    {
        return level & ~toRemove;
    }

    /// <summary>
    /// Checks if the security level has any secure messaging.
    /// </summary>
    public static bool HasSecureMessaging(this SecurityLevel level)
    {
        return level != SecurityLevel.None;
    }

    /// <summary>
    /// Gets a human-readable description of the security level.
    /// </summary>
    public static string ToDescription(this SecurityLevel level)
    {
        return level switch
        {
            SecurityLevel.None => "No security",
            SecurityLevel.CMac => "C-MAC",
            SecurityLevel.CEncryption => "C-ENCRYPTION",
            SecurityLevel.CDecryption => "C-MAC + C-DECRYPTION",
            SecurityLevel.RMac => "R-MAC",
            SecurityLevel.REncryption => "R-ENCRYPTION",
            _ => $"Combined security level: {(int)level:X2}",
        };
    }
}
