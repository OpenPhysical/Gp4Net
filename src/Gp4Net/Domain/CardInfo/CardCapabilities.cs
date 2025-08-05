using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.Tlv;
using JetBrains.Annotations;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Card capabilities parser for GlobalPlatform tag 0x67.
/// Provides detailed parsing of SCP options, privileges, algorithms, and cipher suites.
/// </summary>
[PublicAPI]
public class CardCapabilities
{
    /// <summary>
    /// Gets the raw capabilities data.
    /// </summary>
    public byte[] RawData { get; }

    /// <summary>
    /// Gets the supported SCP options.
    /// </summary>
    public ImmutableList<ScpOption> ScpOptions { get; private set; } = [];

    /// <summary>
    /// Gets the supported key lengths for each SCP.
    /// </summary>
    public ImmutableDictionary<byte, ImmutableList<int>> SupportedKeyLengths { get; private set; } = ImmutableDictionary<byte, ImmutableList<int>>.Empty;

    /// <summary>
    /// Gets the supported Security Domain privileges.
    /// </summary>
    public Maybe<SecurityDomainPrivileges> SdPrivileges { get; private set; }

    /// <summary>
    /// Gets the supported Application privileges.
    /// </summary>
    public Maybe<ApplicationPrivileges> AppPrivileges { get; private set; }

    /// <summary>
    /// Gets the supported algorithms.
    /// </summary>
    public Maybe<SupportedAlgorithms> Algorithms { get; private set; }

    /// <summary>
    /// Gets the supported cipher suites for various operations.
    /// </summary>
    public ImmutableDictionary<CipherUsage, ImmutableList<CipherSuite>> CipherSuites { get; private set; } = ImmutableDictionary<CipherUsage, ImmutableList<CipherSuite>>.Empty;

    /// <summary>
    /// Gets a value indicating whether SCP02 is supported.
    /// </summary>
    public bool SupportsScp02 => ScpOptions.Any(o => o.ScpId == 0x02);

    /// <summary>
    /// Gets a value indicating whether SCP03 is supported.
    /// </summary>
    public bool SupportsScp03 => ScpOptions.Any(o => o.ScpId == 0x03);

    private CardCapabilities(byte[] rawData)
    {
        RawData = rawData; // Validation done in TryParse
    }

    /// <summary>
    /// Parses card capabilities from tag 0x67 data.
    /// </summary>
    /// <param name="data">The capabilities data bytes.</param>
    /// <returns>The parsed capabilities.</returns>
    /// <exception cref="ArgumentException">Thrown when data is null or empty.</exception>
    /// <exception cref="InvalidOperationException">Thrown when parsing fails.</exception>
    /// <remarks>Consider using TryParse for functional error handling.</remarks>
    public static CardCapabilities Parse(byte[] data)
    {
        return TryParse(Maybe<byte[]>.From(data)).Match(
            onSuccess: caps => caps,
            onFailure: error => throw new InvalidOperationException(error.Message));
    }

    /// <summary>
    /// Attempts to parse card capabilities data using functional error handling.
    /// </summary>
    /// <param name="data">The capabilities data bytes.</param>
    /// <returns>A result containing the parsed capabilities or an error.</returns>
    public static Result<CardCapabilities, SmartCardError> TryParse(Maybe<byte[]> data)
    {
        return data.Match(
            Some: bytes => bytes.Length == 0 
                ? Result.Failure<CardCapabilities, SmartCardError>(SmartCardError.InvalidData("Capabilities data cannot be empty"))
                : TryParseFromBytes(bytes),
            None: () => Result.Failure<CardCapabilities, SmartCardError>(SmartCardError.InvalidData("Capabilities data cannot be null"))
        );
    }

    private static Result<CardCapabilities, SmartCardError> TryParseFromBytes(byte[] data)
    {

        try
        {
            var capabilities = new CardCapabilities(data);

            // Parse DER structure
            foreach (var element in TlvParser.ParseAll(data))
            {
                switch (element.TagNumber)
                {
                    case 0xA0: // SCP options
                        capabilities.ParseScpOptions(element.Value);
                        break;
                    case 0x80: // Security Domain privileges
                        capabilities.SdPrivileges = Maybe<SecurityDomainPrivileges>.From(ParseSecurityDomainPrivileges(element.Value));
                        break;
                    case 0x81: // Application privileges
                        capabilities.AppPrivileges = Maybe<ApplicationPrivileges>.From(ParseApplicationPrivileges(element.Value));
                        break;
                    case 0x82: // Supported algorithms
                        capabilities.Algorithms = Maybe<SupportedAlgorithms>.From(ParseSupportedAlgorithms(element.Value));
                        break;
                    case 0x83: // LFDB hash algorithms
                        capabilities.ParseCipherSuite(CipherUsage.LfdbHash, element.Value);
                        break;
                    case 0x84: // Token verification ciphers
                        capabilities.ParseCipherSuite(CipherUsage.TokenVerification, element.Value);
                        break;
                    case 0x85: // Receipt generation ciphers
                        capabilities.ParseCipherSuite(CipherUsage.ReceiptGeneration, element.Value);
                        break;
                    case 0x86: // DAP verification ciphers
                        capabilities.ParseCipherSuite(CipherUsage.DapVerification, element.Value);
                        break;
                    case 0x87: // Mandated DAP verification ciphers
                        capabilities.ParseCipherSuite(
                            CipherUsage.MandatedDapVerification,
                            element.Value
                        );
                        break;
                }
            }

            return capabilities;
        }
        catch (Exception ex)
        {
            return SmartCardError.InvalidData($"Failed to parse card capabilities: {ex.Message}");
        }
    }

    internal void ParseScpOptions(byte[] data)
    {
        // Parse according to Table H-6: SCP Information
        byte scpType = 0;
        var supportedOptions = Maybe<byte[]>.None;
        var supportedKeys = Maybe<byte[]>.None;

        foreach (var element in TlvParser.ParseAll(data))
        {
            switch (element.TagNumber)
            {
                case 0x80: // SCP type
                    if (element.Value.Length > 0)
                    {
                        scpType = element.Value[0];
                    }

                    break;
                case 0x81: // List of supported options
                    supportedOptions = Maybe<byte[]>.From(element.Value);
                    break;
                case 0x82: // Supported keys for SCP03
                    supportedKeys = Maybe<byte[]>.From(element.Value);
                    break;
            }
        }

        // Parse supported options (i parameters)
        supportedOptions.Match(
            Some: options => {
                if (scpType > 0)
                {
                    // Parse supported key lengths for SCP03
                    if (scpType == 0x03)
                    {
                        supportedKeys.Match(
                            Some: keys => {
                                if (keys.Length > 0)
                                {
                                    var keyLengthsBuilder = ImmutableList.CreateBuilder<int>();
                                    var keyByte = keys[0];
                                    if ((keyByte & 0x01) != 0)
                                    {
                                        keyLengthsBuilder.Add(128);
                                    }

                                    if ((keyByte & 0x02) != 0)
                                    {
                                        keyLengthsBuilder.Add(192);
                                    }

                                    if ((keyByte & 0x04) != 0)
                                    {
                                        keyLengthsBuilder.Add(256);
                                    }

                                    SupportedKeyLengths = SupportedKeyLengths.SetItem(scpType, keyLengthsBuilder.ToImmutable());
                                }
                                return new object();
                            },
                            None: () => new object()
                        );
                    }

                    // Each byte in supportedOptions represents one supported implementation parameter
                    var scpOptionsBuilder = ScpOptions.ToBuilder();
                    foreach (var option in options)
                    {
                        scpOptionsBuilder.Add(
                            new ScpOption(
                                scpType,
                                option,
                                DetermineKeyLength(scpType, supportedKeys)
                            )
                        );
                    }
                    ScpOptions = scpOptionsBuilder.ToImmutable();
                }
                return new object();
            },
            None: () => new object()
        );
    }

    private static int DetermineKeyLength(byte scpId, Maybe<byte[]> supportedKeys)
    {
        // For SCP03, parse supported keys according to Table H-7
        if (scpId == 0x03)
        {
            return supportedKeys.Match(
                Some: keys => {
                    if (keys.Length > 0)
                    {
                        var keyByte = keys[0];
                        // Multiple key lengths can be supported
                        if ((keyByte & 0x04) != 0)
                        {
                            return 256; // Prefer highest
                        }

                        if ((keyByte & 0x02) != 0)
                        {
                            return 192;
                        }

                        if ((keyByte & 0x01) != 0)
                        {
                            return 128;
                        }
                    }
                    return 128; // Default
                },
                None: () => 128 // Default
            );
        }
        return 128; // Default
    }

    private static SecurityDomainPrivileges ParseSecurityDomainPrivileges(byte[] data)
    {
        if (data.Length < 3)
        {
            return new SecurityDomainPrivileges(0, 0, 0);
        }

        return new SecurityDomainPrivileges(
            data[0],
            data[1],
            data.Length > 2 ? data[2] : (byte)0
        );
    }

    private static ApplicationPrivileges ParseApplicationPrivileges(byte[] data)
    {
        if (data.Length < 3)
        {
            return new ApplicationPrivileges(0, 0, 0);
        }

        return new ApplicationPrivileges(
            data[0],
            data[1],
            data.Length > 2 ? data[2] : (byte)0
        );
    }

    private static SupportedAlgorithms ParseSupportedAlgorithms(byte[] data)
    {
        if (data.Length < 2)
        {
            return new SupportedAlgorithms(0, 0);
        }

        return new SupportedAlgorithms(
            data[0],
            data.Length > 1 ? data[1] : (byte)0
        );
    }

    private void ParseCipherSuite(CipherUsage usage, byte[] data)
    {
        if (data.Length == 0)
        {
            return;
        }

        var suitesBuilder = ImmutableList.CreateBuilder<CipherSuite>();

        for (var i = 0; i < data.Length; i++)
        {
            var suite = ParseCipherSuiteByte(data[i]);
            if (suite != CipherSuite.Unknown)
            {
                suitesBuilder.Add(suite);
            }
        }

        if (suitesBuilder.Count > 0)
        {
            CipherSuites = CipherSuites.SetItem(usage, suitesBuilder.ToImmutable());
        }
    }

    private static CipherSuite ParseCipherSuiteByte(byte value)
    {
        return value switch
        {
            0x01 => CipherSuite.Des3Mac,
            0x02 => CipherSuite.AesCmac128,
            0x03 => CipherSuite.AesCmac192,
            0x04 => CipherSuite.AesCmac256,
            0x11 => CipherSuite.Rsa1024Sha1,
            0x12 => CipherSuite.Rsa1024Sha256,
            0x13 => CipherSuite.Rsa2048Sha1,
            0x14 => CipherSuite.Rsa2048Sha256,
            0x15 => CipherSuite.RsaPssSha256,
            0x21 => CipherSuite.EcdsaP256Sha256,
            0x22 => CipherSuite.EcdsaP384Sha384,
            0x23 => CipherSuite.EcdsaP521Sha512,
            0x31 => CipherSuite.Sha1,
            0x32 => CipherSuite.Sha256,
            0x33 => CipherSuite.Sha384,
            0x34 => CipherSuite.Sha512,
            _ => CipherSuite.Unknown
        };
    }

    /// <summary>
    /// Formats capabilities as a human-readable string.
    /// </summary>
    public override string ToString()
    {
        var sb = new StringBuilder();
        _ = sb.AppendLine("Card Capabilities:");

        // SCP options - group by SCP type
        var scpGroups = ScpOptions.GroupBy(o => o.ScpId);
        foreach (var group in scpGroups)
        {
            var scpId = group.Key;
            var options = string.Join(" ", group.Select(o => $"i={o.Implementation:X2}"));

            // Get key lengths from the dedicated dictionary if available
            var keyLengthStr = "";
            if (SupportedKeyLengths.TryGetValue(scpId, out var lengths) && lengths.Count > 0)
            {
                keyLengthStr = " with " + string.Join(" ", lengths.Select(k => $"AES-{k}"));
            }

            _ = sb.AppendLine($"Supports SCP{scpId:X2} {options}{keyLengthStr}");
        }

        // Privileges
        if (SdPrivileges.HasValue)
        {
            _ = sb.AppendLine($"Supported DOM privileges: {SdPrivileges.Value}");
        }

        if (AppPrivileges.HasValue)
        {
            _ = sb.AppendLine($"Supported APP privileges: {AppPrivileges.Value}");
        }

        // Algorithms
        if (Algorithms.HasValue)
        {
            _ = sb.AppendLine($"Supported LFDB hash: {Algorithms.Value.GetHashAlgorithms()}");
        }

        // Cipher suites
        foreach (var kvp in CipherSuites.OrderBy(x => x.Key))
        {
            var cipherNames = string.Join(", ", kvp.Value.Select(c => c.ToFriendlyString()));
            _ = sb.AppendLine(
                $"Supported {GetCipherUsageDescription(kvp.Key)} ciphers: {cipherNames}"
            );
        }

        return sb.ToString();
    }

    private static string GetCipherUsageDescription(CipherUsage usage)
    {
        return usage switch
        {
            CipherUsage.LfdbHash => "LFDB hash",
            CipherUsage.TokenVerification => "Token Verification",
            CipherUsage.ReceiptGeneration => "Receipt Generation",
            CipherUsage.DapVerification => "DAP Verification",
            CipherUsage.MandatedDapVerification => "Mandated DAP Verification",
            _ => usage.ToString()
        };
    }
}

/// <summary>
/// Represents an SCP option with implementation parameter.
/// </summary>
public record ScpOption(
    byte ScpId,
    byte Implementation,
    int KeyLength
);

/// <summary>
/// Security Domain privileges.
/// </summary>
public record SecurityDomainPrivileges(
    byte Byte1,
    byte Byte2,
    byte Byte3
)
{
    public bool SecurityDomain => (Byte1 & 0x80) != 0;
    public bool DapVerification => (Byte1 & 0x40) != 0;
    public bool DelegatedManagement => (Byte1 & 0x20) != 0;
    public bool CardLock => (Byte1 & 0x10) != 0;
    public bool CardTerminate => (Byte1 & 0x08) != 0;
    public bool CardReset => (Byte1 & 0x04) != 0;
    public bool CvmManagement => (Byte1 & 0x02) != 0;
    public bool MandatedDapVerification => (Byte1 & 0x01) != 0;

    public bool TrustedPath => (Byte2 & 0x80) != 0;
    public bool AuthorizedManagement => (Byte2 & 0x40) != 0;
    public bool TokenVerification => (Byte2 & 0x20) != 0;
    public bool GlobalDelete => (Byte2 & 0x10) != 0;
    public bool GlobalLock => (Byte2 & 0x08) != 0;
    public bool GlobalRegistry => (Byte2 & 0x04) != 0;
    public bool FinalApplication => (Byte2 & 0x02) != 0;
    public bool GlobalService => (Byte2 & 0x01) != 0;

    public bool ReceiptGeneration => (Byte3 & 0x80) != 0;
    public bool CipheredLoadFileDataBlock => (Byte3 & 0x40) != 0;
    public bool ContactlessActivation => (Byte3 & 0x20) != 0;
    public bool ContactlessSelfActivation => (Byte3 & 0x10) != 0;

    public override string ToString()
    {
        var privs = new List<string>();

        if (SecurityDomain)
        {
            privs.Add("SecurityDomain");
        }

        if (DapVerification)
        {
            privs.Add("DAPVerification");
        }

        if (DelegatedManagement)
        {
            privs.Add("DelegatedManagement");
        }

        if (CardLock)
        {
            privs.Add("CardLock");
        }

        if (CardTerminate)
        {
            privs.Add("CardTerminate");
        }

        if (CardReset)
        {
            privs.Add("CardReset");
        }

        if (CvmManagement)
        {
            privs.Add("CVMManagement");
        }

        if (MandatedDapVerification)
        {
            privs.Add("MandatedDAPVerification");
        }

        if (TrustedPath)
        {
            privs.Add("TrustedPath");
        }

        if (AuthorizedManagement)
        {
            privs.Add("AuthorizedManagement");
        }

        if (TokenVerification)
        {
            privs.Add("TokenVerification");
        }

        if (GlobalDelete)
        {
            privs.Add("GlobalDelete");
        }

        if (GlobalLock)
        {
            privs.Add("GlobalLock");
        }

        if (GlobalRegistry)
        {
            privs.Add("GlobalRegistry");
        }

        if (FinalApplication)
        {
            privs.Add("FinalApplication");
        }

        if (GlobalService)
        {
            privs.Add("GlobalService");
        }

        if (ReceiptGeneration)
        {
            privs.Add("ReceiptGeneration");
        }

        if (CipheredLoadFileDataBlock)
        {
            privs.Add("CipheredLoadFileDataBlock");
        }

        if (ContactlessActivation)
        {
            privs.Add("ContactlessActivation");
        }

        if (ContactlessSelfActivation)
        {
            privs.Add("ContactlessSelfActivation");
        }

        return string.Join(", ", privs);
    }
}

/// <summary>
/// Application privileges.
/// </summary>
public record ApplicationPrivileges(
    byte Byte1,
    byte Byte2,
    byte Byte3
)
{
    // Note: Many privilege bits have same meaning as SecurityDomainPrivileges
    public bool CardLock => (Byte1 & 0x10) != 0;
    public bool CardTerminate => (Byte1 & 0x08) != 0;
    public bool CardReset => (Byte1 & 0x04) != 0;
    public bool CvmManagement => (Byte1 & 0x02) != 0;

    public bool FinalApplication => (Byte2 & 0x02) != 0;
    public bool GlobalService => (Byte2 & 0x01) != 0;

    public override string ToString()
    {
        var privs = new List<string>();

        if (CardLock)
        {
            privs.Add("CardLock");
        }

        if (CardTerminate)
        {
            privs.Add("CardTerminate");
        }

        if (CardReset)
        {
            privs.Add("CardReset");
        }

        if (CvmManagement)
        {
            privs.Add("CVMManagement");
        }

        if (FinalApplication)
        {
            privs.Add("FinalApplication");
        }

        if (GlobalService)
        {
            privs.Add("GlobalService");
        }

        return string.Join(", ", privs);
    }
}

/// <summary>
/// Supported algorithms.
/// </summary>
public record SupportedAlgorithms(
    byte HashAlgorithms,
    byte CipherAlgorithms
)
{
    public string GetHashAlgorithms()
    {
        var algs = new List<string>();

        if ((HashAlgorithms & 0x01) != 0)
        {
            algs.Add("SHA-1");
        }

        if ((HashAlgorithms & 0x02) != 0)
        {
            algs.Add("SHA-256");
        }

        if ((HashAlgorithms & 0x04) != 0)
        {
            algs.Add("SHA-384");
        }

        if ((HashAlgorithms & 0x08) != 0)
        {
            algs.Add("SHA-512");
        }

        return algs.Count > 0 ? string.Join(", ", algs) : "None";
    }
}

/// <summary>
/// Cipher usage context.
/// </summary>
public enum CipherUsage
{
    LfdbHash,
    TokenVerification,
    ReceiptGeneration,
    DapVerification,
    MandatedDapVerification
}

/// <summary>
/// Supported cipher suites.
/// </summary>
public enum CipherSuite
{
    Unknown,
    Des3Mac,
    AesCmac128,
    AesCmac192,
    AesCmac256,
    Rsa1024Sha1,
    Rsa1024Sha256,
    Rsa2048Sha1,
    Rsa2048Sha256,
    RsaPssSha256,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    EcdsaP521Sha512,
    Sha1,
    Sha256,
    Sha384,
    Sha512
}

/// <summary>
/// Extension methods for cipher suite formatting.
/// </summary>
public static class CipherSuiteExtensions
{
    public static string ToFriendlyString(this CipherSuite suite)
    {
        return suite switch
        {
            CipherSuite.Des3Mac => "DES_MAC",
            CipherSuite.AesCmac128 => "CMAC_AES128",
            CipherSuite.AesCmac192 => "CMAC_AES192",
            CipherSuite.AesCmac256 => "CMAC_AES256",
            CipherSuite.Rsa1024Sha1 => "RSA1024_SHA1",
            CipherSuite.Rsa1024Sha256 => "RSA1024_SHA256",
            CipherSuite.Rsa2048Sha1 => "RSA2048_SHA1",
            CipherSuite.Rsa2048Sha256 => "RSA2048_SHA256",
            CipherSuite.RsaPssSha256 => "RSAPSS_SHA256",
            CipherSuite.EcdsaP256Sha256 => "ECCP256_SHA256",
            CipherSuite.EcdsaP384Sha384 => "ECCP384_SHA384",
            CipherSuite.EcdsaP521Sha512 => "ECCP521_SHA512",
            CipherSuite.Sha1 => "SHA-1",
            CipherSuite.Sha256 => "SHA-256",
            CipherSuite.Sha384 => "SHA-384",
            CipherSuite.Sha512 => "SHA-512",
            _ => suite.ToString()
        };
    }
}