using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Services.Helpers;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants.GlobalPlatform;
using static Gp4Net.Services.TlvService;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Card capabilities parser for GlobalPlatform tag 0x67.
/// Provides detailed parsing of SCP options, privileges, algorithms, and cipher suites.
/// </summary>
[PublicAPI]
public class CardCapabilities
{
    /// <summary>
    /// Gets the card capabilities data from GET DATA(0x0067) response.
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Gets the supported SCP options.
    /// </summary>
    public ImmutableList<ScpOption> ScpOptions { get; private set; } = [];

    /// <summary>
    /// Gets the supported key lengths for each SCP.
    /// </summary>
    public ImmutableDictionary<byte, ImmutableList<int>> SupportedKeyLengths { get; private set; } =
        ImmutableDictionary<byte, ImmutableList<int>>.Empty;

    /// <summary>
    /// Gets the supported Security Domain privileges.
    /// </summary>
    public Maybe<SecurityDomainPrivileges> SdPrivileges { get; private set; }

    /// <summary>
    /// Gets the supported Application privileges.
    /// </summary>
    public Maybe<Privilege> AppPrivileges { get; private set; }

    /// <summary>
    /// Gets the supported algorithms.
    /// </summary>
    public Maybe<SupportedAlgorithms> Algorithms { get; private set; }

    /// <summary>
    /// Gets the supported cipher suites for various operations.
    /// </summary>
    public ImmutableDictionary<CipherUsage, ImmutableList<CipherSuite>> CipherSuites
    {
        get;
        private set;
    } = ImmutableDictionary<CipherUsage, ImmutableList<CipherSuite>>.Empty;

    public bool SupportsLfdbEncryptionIcv { get; private set; }

    public ImmutableList<byte> KeyParameterReferences { get; private set; } = [];

    /// <summary>
    /// Gets a value indicating whether SCP02 is supported.
    /// </summary>
    public bool SupportsScp02
    {
        get { return ScpOptions.Any(o => o.ScpId == 0x02); }
    }

    /// <summary>
    /// Gets a value indicating whether SCP03 is supported.
    /// </summary>
    public bool SupportsScp03
    {
        get { return ScpOptions.Any(o => o.ScpId == 0x03); }
    }

    private CardCapabilities(byte[] rawData)
    {
        Data = rawData; // Validation done in TryParse
    }

    /// <summary>
    /// Attempts to parse card capabilities data.
    /// </summary>
    /// <param name="data">The capabilities data bytes.</param>
    /// <returns>A result containing the parsed capabilities or an error.</returns>
    public static Result<CardCapabilities, SmartCardError> TryParse(Maybe<byte[]> data)
    {
        return data.Match(
            bytes =>
                bytes.Length == 0
                    ? Result.Failure<CardCapabilities, SmartCardError>(
                        SmartCardError.InvalidData("Capabilities data cannot be empty")
                    )
                    : TryParseFromBytes(bytes),
            () =>
                Result.Failure<CardCapabilities, SmartCardError>(
                    SmartCardError.InvalidData("Capabilities data cannot be null")
                )
        );
    }

    private static Result<CardCapabilities, SmartCardError> TryParseFromBytes(byte[] data)
    {
        var capabilities = new CardCapabilities(data);

        return TlvParser
            .ParseMultiple([.. data])
            .Bind(parseResult =>
            {
                // Process all TLV objects functionally
                return parseResult
                    .Objects.Select(element => ProcessTlvObject(capabilities, element))
                    .Aggregate(
                        seed: UnitResult.Success<SmartCardError>(),
                        func: (acc, current) => acc.IsSuccess ? current : acc
                    )
                    .Map(() => capabilities);
            });
    }

    private static UnitResult<SmartCardError> ProcessTlvObject(
        CardCapabilities capabilities,
        TlvObject element
    )
    {
        return element
            .Tag.ToNumber()
            .Match(
                tagNumber =>
                {
                    switch (tagNumber)
                    {
                        case 0x67: // Card Capabilities container - recursively parse inner TLVs
                            return TlvParser
                                .ParseMultiple([.. element.TlvData.Bytes])
                                .Match(
                                    parseResult =>
                                    {
                                        return parseResult
                                            .Objects.Select(innerElement =>
                                                ProcessTlvObject(capabilities, innerElement)
                                            )
                                            .Aggregate(
                                                seed: UnitResult.Success<SmartCardError>(),
                                                func: (acc, current) =>
                                                    acc.IsSuccess ? current : acc
                                            );
                                    },
                                    error => UnitResult.Failure(error)
                                );
                        case 0xA0: // SCP options
                            capabilities.ParseScpOptions(element.TlvData.Bytes.ToArray());
                            break;
                        // GP Card Specification v2.3.1, Table H-5.
                        case 0x81:
                            capabilities.SdPrivileges = Maybe<SecurityDomainPrivileges>.From(
                                ParseSecurityDomainPrivileges(element.TlvData.Bytes.ToArray())
                            );
                            break;
                        case 0x82:
                            capabilities.AppPrivileges = PrivilegeHelpers
                                .FromBytes(element.TlvData.Bytes.ToArray())
                                .Map(Maybe<Privilege>.From)
                                .Match(success => success, _ => Maybe<Privilege>.None);
                            break;
                        case 0x83:
                            capabilities.Algorithms = Maybe<SupportedAlgorithms>.From(
                                ParseSupportedAlgorithms(element.TlvData.Bytes.ToArray())
                            );
                            break;
                        case 0x84:
                            capabilities.ParseCipherSuite(
                                CipherUsage.LfdbEncryption,
                                element.TlvData.Bytes.ToArray()
                            );
                            break;
                        case 0x85:
                            capabilities.ParseCipherSuite(
                                CipherUsage.TokenVerification,
                                element.TlvData.Bytes.ToArray()
                            );
                            break;
                        case 0x86:
                            capabilities.ParseCipherSuite(
                                CipherUsage.ReceiptGeneration,
                                element.TlvData.Bytes.ToArray()
                            );
                            break;
                        case 0x87:
                            capabilities.ParseCipherSuite(
                                CipherUsage.DapVerification,
                                element.TlvData.Bytes.ToArray()
                            );
                            break;
                        case 0x88:
                            capabilities.KeyParameterReferences = [.. element.TlvData.Bytes];
                            break;
                    }
                    return UnitResult.Success<SmartCardError>();
                },
                error => UnitResult.Failure(error)
            );
    }

    internal void ParseScpOptions(byte[] data)
    {
        // Parse according to Table H-6: SCP Information
        TlvParser
            .ParseMultiple([.. data])
            .Match(
                parseResult =>
                {
                    var elementsByTag = parseResult
                        .Objects.Select(element =>
                            element.Tag.ToNumber().Map(tagNum => (element, tagNum))
                        )
                        .Where(result => result.IsSuccess)
                        .Select(result => result.Value)
                        .ToLookup(tuple => tuple.tagNum, tuple => tuple.element);

                    var scpType = elementsByTag[0x80].Any()
                        ? elementsByTag[0x80].First().TlvData.Bytes.Length > 0
                            ? elementsByTag[0x80].First().TlvData.Bytes[0]
                            : (byte)0
                        : (byte)0;

                    var supportedOptions = elementsByTag[0x81].Any()
                        ? Maybe<byte[]>.From(elementsByTag[0x81].First().TlvData.Bytes.ToArray())
                        : Maybe<byte[]>.None;

                    var supportedKeys = elementsByTag[0x82].Any()
                        ? Maybe<byte[]>.From(elementsByTag[0x82].First().TlvData.Bytes.ToArray())
                        : Maybe<byte[]>.None;

                    // Parse supported options (i parameters)
                    _ = supportedOptions.Match(
                        options =>
                        {
                            if (scpType > 0)
                            {
                                // Parse supported key lengths for SCP03
                                if (scpType == 0x03)
                                {
                                    _ = supportedKeys.Match(
                                        keys =>
                                        {
                                            if (keys.Length > 0)
                                            {
                                                var keyLengthsBuilder =
                                                    ImmutableList.CreateBuilder<int>();
                                                byte keyByte = keys[0];
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

                                                SupportedKeyLengths = SupportedKeyLengths.SetItem(
                                                    scpType,
                                                    keyLengthsBuilder.ToImmutable()
                                                );
                                            }
                                            return new object();
                                        },
                                        () => new object()
                                    );
                                }

                                // Each byte in supportedOptions represents one supported implementation parameter
                                var newOptions = options
                                    .Select(option => new ScpOption(
                                        scpType,
                                        option,
                                        DetermineKeyLength(scpType, supportedKeys)
                                    ))
                                    .ToImmutableList();
                                ScpOptions = ScpOptions.AddRange(newOptions);
                            }
                            return new object();
                        },
                        () => new object()
                    );

                    return true;
                },
                _ => false
            );
    }

    private static int DetermineKeyLength(byte scpId, Maybe<byte[]> supportedKeys)
    {
        // For SCP03, parse supported keys according to Table H-7
        if (scpId == 0x03)
        {
            return supportedKeys.Match(
                keys =>
                {
                    if (keys.Length > 0)
                    {
                        byte keyByte = keys[0];
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
                () => 128 // Default
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

        return new SecurityDomainPrivileges(data[0], data[1], data.Length > 2 ? data[2] : (byte)0);
    }

    private static SupportedAlgorithms ParseSupportedAlgorithms(byte[] data)
    {
        byte hashAlgorithms = 0;
        foreach (byte algorithm in data)
        {
            if (algorithm is >= 0x01 and <= 0x04)
                hashAlgorithms |= (byte)(1 << (algorithm - 1));
        }

        return new SupportedAlgorithms(hashAlgorithms, 0);
    }

    private void ParseCipherSuite(CipherUsage usage, byte[] data)
    {
        if (data.Length == 0)
        {
            return;
        }

        ImmutableList<CipherSuite> allSuites =
            usage == CipherUsage.LfdbEncryption
                ? ParseLfdbEncryptionSuites(data[0])
                : ParseSignatureSuites(data);

        if (usage == CipherUsage.LfdbEncryption)
            SupportsLfdbEncryptionIcv = (data[0] & 0x80) != 0;

        if (allSuites.Count > 0)
        {
            CipherSuites = CipherSuites.SetItem(usage, allSuites);
        }
    }

    private static ImmutableList<CipherSuite> ParseLfdbEncryptionSuites(byte value)
    {
        var suites = ImmutableList.CreateBuilder<CipherSuite>();
        if ((value & 0x01) != 0)
            suites.Add(CipherSuite.TripleDes16);
        if ((value & 0x02) != 0)
            suites.Add(CipherSuite.Aes128);
        if ((value & 0x04) != 0)
            suites.Add(CipherSuite.Aes192);
        if ((value & 0x08) != 0)
            suites.Add(CipherSuite.Aes256);
        return suites.ToImmutable();
    }

    private static ImmutableList<CipherSuite> ParseSignatureSuites(byte[] data)
    {
        var suites = ImmutableList.CreateBuilder<CipherSuite>();
        byte first = data[0];
        if ((first & 0x01) != 0)
            suites.Add(CipherSuite.Rsa1024Sha1);
        if ((first & 0x02) != 0)
            suites.Add(CipherSuite.RsaPssSha256);
        if ((first & 0x04) != 0)
            suites.Add(CipherSuite.Des3Mac);
        if ((first & 0x08) != 0)
            suites.Add(CipherSuite.AesCmac128);
        if ((first & 0x10) != 0)
            suites.Add(CipherSuite.AesCmac192);
        if ((first & 0x20) != 0)
            suites.Add(CipherSuite.AesCmac256);
        if ((first & 0x40) != 0)
            suites.Add(CipherSuite.EcdsaP256Sha256);
        if ((first & 0x80) != 0)
            suites.Add(CipherSuite.EcdsaP384Sha384);

        if (data.Length > 1)
        {
            if ((data[1] & 0x01) != 0)
                suites.Add(CipherSuite.EcdsaP512Sha512);
            if ((data[1] & 0x02) != 0)
                suites.Add(CipherSuite.EcdsaP521Sha512);
        }

        return suites.ToImmutable();
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
            byte scpId = group.Key;
            string options = string.Join(" ", group.Select(o => $"i={o.Implementation:X2}"));

            // Get key lengths from the dedicated dictionary if available
            string keyLengthStr = "";
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

        _ = AppPrivileges.Match(
            privileges =>
                sb.AppendLine(
                    $"Supported APP privileges: {Services.Helpers.PrivilegeHelpers.ToHumanReadableString(privileges)}"
                ),
            () => sb
        );

        // Algorithms
        if (Algorithms.HasValue)
        {
            _ = sb.AppendLine($"Supported LFDB hash: {Algorithms.Value.GetHashAlgorithms()}");
        }

        // Cipher suites
        foreach (var kvp in CipherSuites.OrderBy(x => x.Key))
        {
            string cipherNames = string.Join(", ", kvp.Value.Select(c => c.ToFriendlyString()));
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
            CipherUsage.LfdbEncryption => "LFDB encryption",
            CipherUsage.TokenVerification => "Token Verification",
            CipherUsage.ReceiptGeneration => "Receipt Generation",
            CipherUsage.DapVerification => "DAP Verification",
            _ => usage.ToString(),
        };
    }
}

/// <summary>
/// Represents an SCP option with implementation parameter.
/// </summary>
public record ScpOption(byte ScpId, byte Implementation, int KeyLength);

/// <summary>
/// Security Domain privileges.
/// </summary>
public record SecurityDomainPrivileges(byte Byte1, byte Byte2, byte Byte3)
{
    public bool SecurityDomain
    {
        get { return (Byte1 & 0x80) != 0; }
    }
    public bool DapVerification
    {
        get { return (Byte1 & 0x40) != 0; }
    }
    public bool DelegatedManagement
    {
        get { return (Byte1 & 0x20) != 0; }
    }
    public bool CardLock
    {
        get { return (Byte1 & 0x10) != 0; }
    }
    public bool CardTerminate
    {
        get { return (Byte1 & 0x08) != 0; }
    }
    public bool CardReset
    {
        get { return (Byte1 & 0x04) != 0; }
    }
    public bool CvmManagement
    {
        get { return (Byte1 & 0x02) != 0; }
    }
    public bool MandatedDapVerification
    {
        get { return (Byte1 & 0x01) != 0; }
    }

    public bool TrustedPath
    {
        get { return (Byte2 & 0x80) != 0; }
    }
    public bool AuthorizedManagement
    {
        get { return (Byte2 & 0x40) != 0; }
    }
    public bool TokenVerification
    {
        get { return (Byte2 & 0x20) != 0; }
    }
    public bool GlobalDelete
    {
        get { return (Byte2 & 0x10) != 0; }
    }
    public bool GlobalLock
    {
        get { return (Byte2 & 0x08) != 0; }
    }
    public bool GlobalRegistry
    {
        get { return (Byte2 & 0x04) != 0; }
    }
    public bool FinalApplication
    {
        get { return (Byte2 & 0x02) != 0; }
    }
    public bool GlobalService
    {
        get { return (Byte2 & 0x01) != 0; }
    }

    public bool ReceiptGeneration
    {
        get { return (Byte3 & 0x80) != 0; }
    }
    public bool CipheredLoadFileDataBlock
    {
        get { return (Byte3 & 0x40) != 0; }
    }
    public bool ContactlessActivation
    {
        get { return (Byte3 & 0x20) != 0; }
    }
    public bool ContactlessSelfActivation
    {
        get { return (Byte3 & 0x10) != 0; }
    }

    public override string ToString()
    {
        List<string> privs = [];

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
/// Supported algorithms.
/// </summary>
public record SupportedAlgorithms(byte HashAlgorithms, byte CipherAlgorithms)
{
    public string GetHashAlgorithms()
    {
        List<string> algs = [];

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
    LfdbEncryption,
    TokenVerification,
    ReceiptGeneration,
    DapVerification,
}

/// <summary>
/// Supported cipher suites.
/// </summary>
public enum CipherSuite
{
    Unknown,
    TripleDes16,
    Aes128,
    Aes192,
    Aes256,
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
    EcdsaP512Sha512,
    EcdsaP521Sha512,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
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
            CipherSuite.TripleDes16 => "3DES-16",
            CipherSuite.Aes128 => "AES-128",
            CipherSuite.Aes192 => "AES-192",
            CipherSuite.Aes256 => "AES-256",
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
            CipherSuite.EcdsaP512Sha512 => "ECCP512_SHA512",
            CipherSuite.EcdsaP521Sha512 => "ECCP521_SHA512",
            CipherSuite.Sha1 => "SHA-1",
            CipherSuite.Sha256 => "SHA-256",
            CipherSuite.Sha384 => "SHA-384",
            CipherSuite.Sha512 => "SHA-512",
            _ => suite.ToString(),
        };
    }
}
