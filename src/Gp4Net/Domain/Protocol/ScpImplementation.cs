using System;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// SCP implementation parameters as defined in GlobalPlatform Card Specification.
/// These flags control various protocol behaviors for SCP02 and SCP03.
/// </summary>
[PublicAPI]
[Flags]
public enum ScpImplementation : byte
{
    /// <summary>
    /// SCP02: 3 Secure Channel Keys (no derivation)
    /// </summary>
    Scp02NoDerivation = 0x00,
    
    /// <summary>
    /// SCP02: 3 Secure Channel base keys (ENC/MAC/DEK)
    /// Session keys derived from base keys
    /// </summary>
    Scp02ThreeKeys = 0x05,
    
    /// <summary>
    /// SCP02: 1 Secure Channel base key (ENC=MAC=DEK)
    /// Session keys derived from single base key
    /// </summary>
    Scp02OneKey = 0x04,
    
    /// <summary>
    /// SCP02: 3 Secure Channel Keys with static MAC
    /// S-MAC session key replaced by static MAC key
    /// </summary>
    Scp02StaticMac = 0x15,
    
    /// <summary>
    /// SCP02: 1 Secure Channel base key with static MAC
    /// S-MAC session key replaced by static MAC key from single base key
    /// </summary>
    Scp02OneKeyStaticMac = 0x14,
    
    /// <summary>
    /// SCP02: 3 Secure Channel Keys with AES
    /// Uses AES instead of 3DES (vendor extension)
    /// </summary>
    Scp02AesKeys = 0x1A,
    
    /// <summary>
    /// SCP02: 3 Secure Channel Keys with R-MAC support (35)
    /// Initiation mode explicit, C-MAC on modified APDU, ICV set to zero,
    /// ICV encryption for C-MAC session, R-MAC support
    /// </summary>
    Scp02ThreeKeysRMac = 0x35,
    
    /// <summary>
    /// SCP02: Well-known pseudo-random algorithm (55)
    /// Uses specific PRF for key derivation
    /// </summary>
    Scp02PseudoRandom = 0x55,
    
    /// <summary>
    /// SCP02: CMAC with multiplication (55)
    /// Per GlobalPlatform Card Specification v2.3.1 Section E.4.2
    /// Alias for Scp02PseudoRandom - same implementation value
    /// </summary>
    Scp02CmacMult = 0x55,
    
    /// <summary>
    /// SCP02: CMAC with XOR (1A)
    /// Per GlobalPlatform Card Specification v2.3.1 Section E.4.2
    /// Alias for Scp02AesKeys - same implementation value
    /// </summary>
    Scp02CmacXor = 0x1A,
    
    /// <summary>
    /// SCP02: Explicit initialization vector (04)
    /// Per GlobalPlatform Card Specification v2.3.1 Section E.4.2
    /// Alias for Scp02OneKey - same implementation value
    /// </summary>
    Scp02ExplicitInitVector = 0x04,
    
    /// <summary>
    /// SCP02: Implicit initialization vector (05)
    /// Per GlobalPlatform Card Specification v2.3.1 Section E.4.2
    /// Alias for Scp02ThreeKeys - same implementation value
    /// </summary>
    Scp02ImplicitInitVector = 0x05,
    
    /// <summary>
    /// SCP02: 3 Secure Channel Keys with pseudo-random and R-MAC support (75)
    /// Initiation mode explicit, C-MAC on modified APDU, ICV set to zero,
    /// ICV encryption for C-MAC session, well-known pseudo-random algorithm,
    /// R-MAC support
    /// </summary>
    Scp02PseudoRandomRMac = 0x75,
    
    /// <summary>
    /// SCP03: AES with 128-bit keys
    /// Standard SCP03 implementation
    /// </summary>
    Scp03Aes128 = 0x10,
    
    /// <summary>
    /// SCP03: AES with 192-bit keys
    /// </summary>
    Scp03Aes192 = 0x20,
    
    /// <summary>
    /// SCP03: AES with 256-bit keys
    /// </summary>
    Scp03Aes256 = 0x30,
    
    /// <summary>
    /// SCP03: Pseudo-random card challenge
    /// Card challenge derived using KDF instead of random
    /// </summary>
    Scp03PseudoRandom = 0x70,
    
    /// <summary>
    /// SCP03: Random card challenge (60)
    /// Per GlobalPlatform SCP03 v1.1.1 Section 6.2.1
    /// Card generates truly random challenge instead of pseudo-random
    /// </summary>
    Scp03RandomChallenge = 0x60,
    
    /// <summary>
    /// SCP03: No response MAC (11)
    /// Per GlobalPlatform SCP03 v1.1.1 Section 6.2.5
    /// Response MAC calculation and verification is disabled
    /// </summary>
    Scp03NoResponseMac = 0x11,
    
    // Flags that can be combined with base implementations
    
    /// <summary>
    /// Flag: Use static MAC key (bit 4)
    /// When set, S-MAC session key is replaced by static MAC key
    /// </summary>
    StaticMacFlag = 0x10,
    
    /// <summary>
    /// Flag: Use AES encryption (bit 4 in different context)
    /// Vendor-specific extension for SCP02
    /// </summary>
    AesFlag = 0x10,
    
    /// <summary>
    /// Flag: Use pseudo-random generation (bit 6)
    /// </summary>
    PseudoRandomFlag = 0x40,
    
    /// <summary>
    /// Mask for key length in SCP03 (bits 4-5)
    /// </summary>
    Scp03KeyLengthMask = 0x30,
}

/// <summary>
/// Extension methods for ScpImplementation enum.
/// </summary>
[PublicAPI]
public static class ScpImplementationExtensions
{
    /// <summary>
    /// Determines if this implementation uses static MAC key.
    /// </summary>
    public static bool UsesStaticMac(this ScpImplementation implementation)
    {
        var value = (byte)implementation;
        // SCP02: Check bit 4 for i=15, i=14, i=1A
        return value is 0x15 or 0x14 or 0x1A;
    }
    
    /// <summary>
    /// Determines if this implementation uses single base key.
    /// </summary>
    public static bool UsesSingleKey(this ScpImplementation implementation)
    {
        var value = (byte)implementation;
        // SCP02: i=04, i=14
        return value is 0x04 or 0x14;
    }
    
    /// <summary>
    /// Determines if this implementation uses AES encryption.
    /// </summary>
    public static bool UsesAes(this ScpImplementation implementation)
    {
        var value = (byte)implementation;
        // SCP02: i=1A
        // SCP03: All implementations use AES
        return value == 0x1A || (value & 0xF0) == 0x10 || (value & 0xF0) == 0x20 || 
               (value & 0xF0) == 0x30 || (value & 0xF0) == 0x70;
    }
    
    /// <summary>
    /// Determines if this implementation uses pseudo-random challenge generation.
    /// </summary>
    public static bool UsesPseudoRandom(this ScpImplementation implementation)
    {
        var value = (byte)implementation;
        // SCP02: i=55, i=75
        // SCP03: i=70
        return value is 0x55 or 0x75 or 0x70;
    }
    
    /// <summary>
    /// Determines if this implementation supports R-MAC (Response MAC).
    /// </summary>
    public static bool SupportsRMac(this ScpImplementation implementation)
    {
        var value = (byte)implementation;
        // SCP02: Check bit 6 (0x20) for R-MAC support
        // i=35, i=75 have R-MAC support
        return (value & 0x20) != 0;
    }
    
    /// <summary>
    /// Gets the AES key length in bits for SCP03 implementations.
    /// </summary>
    public static int GetAesKeyLength(this ScpImplementation implementation)
    {
        var value = (byte)implementation;
        return (value & 0xF0) switch
        {
            0x10 => 128, // SCP03 AES-128
            0x20 => 192, // SCP03 AES-192
            0x30 => 256, // SCP03 AES-256
            0x70 => 128, // SCP03 pseudo-random uses AES-128
            _ => 0       // Not an SCP03 implementation
        };
    }
    
    /// <summary>
    /// Determines if this is an SCP02 implementation.
    /// </summary>
    public static bool IsScp02(this ScpImplementation implementation)
    {
        var value = (byte)implementation;
        // SCP02: i=00, 04, 05, 14, 15, 1A, 35, 55, 75
        // Note: Some values have multiple enum names (aliases) for clarity
        return value is 0x00 or 0x04 or 0x05 or 0x14 or 0x15 or 0x1A or 0x35 or 0x55 or 0x75;
    }
    
    /// <summary>
    /// Determines if this is an SCP03 implementation.
    /// </summary>
    public static bool IsScp03(this ScpImplementation implementation)
    {
        var value = (byte)implementation;
        // SCP03: i=10, 11, 20, 30, 60, 70
        return value is 0x10 or 0x11 or 0x20 or 0x30 or 0x60 or 0x70;
    }
}