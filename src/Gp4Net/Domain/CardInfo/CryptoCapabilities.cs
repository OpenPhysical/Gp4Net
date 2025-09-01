using System;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Cryptographic capabilities supported by smart card chips.
/// These flags can be combined to indicate multiple algorithm support.
/// </summary>
[Flags]
public enum CryptoCapabilities
{
    /// <summary>
    /// No cryptographic capabilities.
    /// </summary>
    None = 0x0000,

    /// <summary>
    /// DES (Data Encryption Standard) support.
    /// Single DES with 56-bit effective key length.
    /// </summary>
    DES = 0x0001,

    /// <summary>
    /// Triple DES (3DES) support.
    /// 168-bit effective key length (3 x 56-bit).
    /// </summary>
    TripleDES = 0x0002,

    /// <summary>
    /// AES-128 (Advanced Encryption Standard) support.
    /// 128-bit key length.
    /// </summary>
    AES128 = 0x0004,

    /// <summary>
    /// AES-192 support.
    /// 192-bit key length.
    /// </summary>
    AES192 = 0x0008,

    /// <summary>
    /// AES-256 support.
    /// 256-bit key length.
    /// </summary>
    AES256 = 0x0010,

    /// <summary>
    /// RSA-1024 support.
    /// 1024-bit key length (legacy, not recommended).
    /// </summary>
    RSA1024 = 0x0020,

    /// <summary>
    /// RSA-2048 support.
    /// 2048-bit key length (minimum recommended).
    /// </summary>
    RSA2048 = 0x0040,

    /// <summary>
    /// RSA-3072 support.
    /// 3072-bit key length.
    /// </summary>
    RSA3072 = 0x0080,

    /// <summary>
    /// RSA-4096 support.
    /// 4096-bit key length (maximum for P71).
    /// </summary>
    RSA4096 = 0x0100,

    /// <summary>
    /// ECC P-256 (secp256r1) support.
    /// 256-bit elliptic curve.
    /// </summary>
    ECC256 = 0x0200,

    /// <summary>
    /// ECC P-384 (secp384r1) support.
    /// 384-bit elliptic curve.
    /// </summary>
    ECC384 = 0x0400,

    /// <summary>
    /// ECC P-521 (secp521r1) support.
    /// 521-bit elliptic curve.
    /// </summary>
    ECC521 = 0x0800,

    /// <summary>
    /// ECC P-544 support.
    /// 544-bit elliptic curve (P71 maximum).
    /// </summary>
    ECC544 = 0x1000,

    /// <summary>
    /// SHA-1 hash algorithm support.
    /// 160-bit hash (legacy, not recommended).
    /// </summary>
    SHA1 = 0x2000,

    /// <summary>
    /// SHA-256 hash algorithm support.
    /// 256-bit hash.
    /// </summary>
    SHA256 = 0x4000,

    /// <summary>
    /// SHA-384 hash algorithm support.
    /// 384-bit hash.
    /// </summary>
    SHA384 = 0x8000,

    /// <summary>
    /// SHA-512 hash algorithm support.
    /// 512-bit hash.
    /// </summary>
    SHA512 = 0x10000,

    /// <summary>
    /// Hardware random number generator support.
    /// True RNG (TRNG) for cryptographic use.
    /// </summary>
    HardwareRNG = 0x20000,

    /// <summary>
    /// DPA (Differential Power Analysis) countermeasures.
    /// Hardware-level protection against side-channel attacks.
    /// </summary>
    DPACountermeasures = 0x40000,

    /// <summary>
    /// Standard P71D321 cryptographic capabilities.
    /// Includes all algorithms supported by the SmartMX3 platform.
    /// </summary>
    P71D321Standard =
        DES
        | TripleDES
        | AES128
        | AES192
        | AES256
        | RSA2048
        | RSA3072
        | RSA4096
        | ECC256
        | ECC384
        | ECC521
        | ECC544
        | SHA1
        | SHA256
        | SHA384
        | SHA512
        | HardwareRNG
        | DPACountermeasures,
}

/// <summary>
/// Symmetric cipher modes of operation.
/// </summary>
[Flags]
public enum CipherMode
{
    /// <summary>
    /// No cipher mode.
    /// </summary>
    None = 0x00,

    /// <summary>
    /// Electronic Codebook mode.
    /// </summary>
    ECB = 0x01,

    /// <summary>
    /// Cipher Block Chaining mode.
    /// </summary>
    CBC = 0x02,

    /// <summary>
    /// Counter mode.
    /// </summary>
    CTR = 0x04,

    /// <summary>
    /// Output Feedback mode.
    /// </summary>
    OFB = 0x08,

    /// <summary>
    /// Cipher Feedback mode.
    /// </summary>
    CFB = 0x10,
}

/// <summary>
/// MAC (Message Authentication Code) algorithms.
/// </summary>
[Flags]
public enum MacAlgorithm
{
    /// <summary>
    /// No MAC algorithm.
    /// </summary>
    None = 0x00,

    /// <summary>
    /// DES MAC (legacy).
    /// </summary>
    DesMac = 0x01,

    /// <summary>
    /// CBC-MAC using block cipher.
    /// </summary>
    CbcMac = 0x02,

    /// <summary>
    /// CMAC (Cipher-based MAC) per NIST SP 800-38B.
    /// </summary>
    Cmac = 0x04,

    /// <summary>
    /// HMAC (Hash-based MAC) per FIPS 198.
    /// </summary>
    Hmac = 0x08,

    /// <summary>
    /// Retail MAC (ISO/IEC 9797-1 Algorithm 3).
    /// </summary>
    RetailMac = 0x10,
}

/// <summary>
/// RSA padding schemes.
/// </summary>
[Flags]
public enum RsaPadding
{
    /// <summary>
    /// No padding.
    /// </summary>
    None = 0x00,

    /// <summary>
    /// PKCS#1 v1.5 padding.
    /// </summary>
    Pkcs1 = 0x01,

    /// <summary>
    /// PKCS#1 PSS (Probabilistic Signature Scheme) padding.
    /// </summary>
    Pss = 0x02,

    /// <summary>
    /// PKCS#1 OAEP (Optimal Asymmetric Encryption Padding).
    /// </summary>
    Oaep = 0x04,
}

/// <summary>
/// Key types supported by the smart card.
/// Values correspond to GlobalPlatform key type identifiers.
/// </summary>
public enum CryptoKeyType : byte
{
    /// <summary>
    /// No key type specified.
    /// </summary>
    None = 0x00,

    /// <summary>
    /// DES key (56-bit effective).
    /// GlobalPlatform identifier: 0x80.
    /// </summary>
    DES = 0x80,

    /// <summary>
    /// Triple DES key (168-bit effective).
    /// GlobalPlatform identifier: 0x82.
    /// </summary>
    TripleDES = 0x82,

    /// <summary>
    /// AES key (variable length based on key data).
    /// GlobalPlatform identifier: 0x88.
    /// </summary>
    AES = 0x88,

    /// <summary>
    /// RSA public key.
    /// GlobalPlatform identifier: 0xA0.
    /// </summary>
    RSAPublic = 0xA0,

    /// <summary>
    /// RSA private key (CRT format).
    /// GlobalPlatform identifier: 0xA1.
    /// </summary>
    RSAPrivateCRT = 0xA1,

    /// <summary>
    /// RSA private key (modulus format).
    /// GlobalPlatform identifier: 0xA2.
    /// </summary>
    RSAPrivateModulus = 0xA2,

    /// <summary>
    /// ECC public key.
    /// GlobalPlatform identifier: 0xB0.
    /// </summary>
    ECCPublic = 0xB0,

    /// <summary>
    /// ECC private key.
    /// GlobalPlatform identifier: 0xB1.
    /// </summary>
    ECCPrivate = 0xB1,

    /// <summary>
    /// ECC key pair (public and private).
    /// GlobalPlatform identifier: 0xB2.
    /// </summary>
    ECCKeyPair = 0xB2,

    /// <summary>
    /// Extended key type for future use.
    /// GlobalPlatform identifier: 0xFF.
    /// </summary>
    Extended = 0xFF,
}

/// <summary>
/// Security features supported by the chip.
/// </summary>
[Flags]
public enum SecurityFeatures
{
    /// <summary>
    /// No security features.
    /// </summary>
    None = 0x0000,

    /// <summary>
    /// Physical Unclonable Function for unique chip identification.
    /// </summary>
    PhysicalUnclonableFunction = 0x0001,

    /// <summary>
    /// Secure key storage with hardware protection.
    /// </summary>
    SecureKeyStorage = 0x0002,

    /// <summary>
    /// Tamper detection and response.
    /// </summary>
    TamperDetection = 0x0004,

    /// <summary>
    /// Environmental sensors (voltage, temperature, etc.).
    /// </summary>
    EnvironmentalSensors = 0x0008,

    /// <summary>
    /// Memory encryption for data at rest.
    /// </summary>
    MemoryEncryption = 0x0010,

    /// <summary>
    /// Secure boot verification.
    /// </summary>
    SecureBoot = 0x0020,

    /// <summary>
    /// Hardware firewall between applications.
    /// </summary>
    HardwareFirewall = 0x0040,

    /// <summary>
    /// Side-channel attack countermeasures.
    /// </summary>
    SideChannelProtection = 0x0080,

    /// <summary>
    /// Fault injection countermeasures.
    /// </summary>
    FaultInjectionProtection = 0x0100,

    /// <summary>
    /// Glitch detection and protection.
    /// </summary>
    GlitchProtection = 0x0200,

    /// <summary>
    /// Standard P71D321 security features.
    /// Includes all IntegralSecurity 2.0 features.
    /// </summary>
    P71D321Standard =
        PhysicalUnclonableFunction
        | SecureKeyStorage
        | TamperDetection
        | EnvironmentalSensors
        | MemoryEncryption
        | SecureBoot
        | HardwareFirewall
        | SideChannelProtection
        | FaultInjectionProtection
        | GlitchProtection,
}
