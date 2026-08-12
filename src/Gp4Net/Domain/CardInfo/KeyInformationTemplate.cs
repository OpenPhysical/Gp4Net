using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.DataObjects;
using JetBrains.Annotations;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Key Information Template parser for GlobalPlatform tag 0xE0.
/// GlobalPlatform Card Specification v2.3.1, section 11.3.3.1.1.
/// </summary>
[PublicAPI]
public class KeyInformationTemplate
{
    /// <summary>
    /// Gets the key information template data from GET DATA(0x00E0) response.
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Gets the list of key entries.
    /// </summary>
    public IReadOnlyList<KeyEntry> Keys { get; }

    private KeyInformationTemplate(byte[] rawData, IReadOnlyList<KeyEntry> keys)
    {
        ArgumentNullException.ThrowIfNull(rawData);
        ArgumentNullException.ThrowIfNull(keys);

        Data = rawData;
        Keys = keys;
    }

    /// <summary>
    /// Parses Key Information Template from tag 0xE0 data.
    /// </summary>
    public static Result<KeyInformationTemplate, SmartCardError> Parse(byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return SmartCardError.InvalidArgument("Key information data cannot be null or empty");
        }

        return KeyInfoTemplateCodec
            .Decode(data)
            .Map(template => new KeyInformationTemplate(
                data,
                template
                    .Keys.Select(key =>
                    {
                        IReadOnlyList<KeyType> keyTypes = key
                            .Components.Select(component => ParseKeyType(component.Type))
                            .Where(keyType => keyType != KeyType.Unknown)
                            .ToImmutableList();
                        return new KeyEntry
                        {
                            KeyId = key.KeyIdentifier,
                            KeyVersion = key.KeyVersionNumber,
                            Components = key.Components,
                            KeyTypes = keyTypes,
                        };
                    })
                    .ToImmutableList()
            ));
    }

    private static KeyType ParseKeyType(ushort value)
    {
        return value switch
        {
            0x80 => KeyType.Des,
            0x85 => KeyType.PreSharedTls,
            0x88 => KeyType.Aes,
            0x90 => KeyType.HmacSha1,
            0x91 => KeyType.HmacSha1_160,
            0xA0 => KeyType.RsaPublicExponentECleartext,
            0xA1 => KeyType.RsaModulusNCleartext,
            0xA2 => KeyType.RsaModulusN,
            0xA3 => KeyType.RsaPrivateExponentD,
            0xA4 => KeyType.RsaChineseRemainderP,
            0xA5 => KeyType.RsaChineseRemainderQ,
            0xA6 => KeyType.RsaChineseRemainderPq,
            0xA7 => KeyType.RsaChineseRemainderDpi,
            0xA8 => KeyType.RsaChineseRemainderDqi,
            0xB0 => KeyType.EccPublic,
            0xB1 => KeyType.EccPrivate,
            0xB2 => KeyType.EccFieldP,
            0xB3 => KeyType.EccFieldA,
            0xB4 => KeyType.EccFieldB,
            0xB5 => KeyType.EccGenerator,
            0xB6 => KeyType.EccGeneratorOrder,
            0xB7 => KeyType.EccCofactor,
            0xF0 => KeyType.EccParametersReference,
            _ => KeyType.Unknown,
        };
    }

    /// <summary>
    /// Formats the key information as a human-readable string.
    /// </summary>
    public override string ToString()
    {
        var sb = new StringBuilder();
        _ = sb.AppendLine("Key Information Template:");

        foreach (var key in Keys)
        {
            _ = sb.AppendLine(key.ToString());
        }

        return sb.ToString();
    }
}

/// <summary>
/// Represents a single key entry in the Key Information Template.
/// </summary>
public record KeyEntry
{
    /// <summary>
    /// Gets the key identifier.
    /// </summary>
    public required byte KeyId { get; init; }

    /// <summary>
    /// Gets the key version number.
    /// </summary>
    public required byte KeyVersion { get; init; }

    /// <summary>
    /// Gets the list of key types supported for this key.
    /// </summary>
    public required IReadOnlyList<KeyType> KeyTypes { get; init; } = [];

    /// <summary>
    /// Key component type and length pairs from GP Card Specification v2.3.1 Tables 11-28 and 11-29.
    /// </summary>
    public required IReadOnlyList<KeyTypeAndLength> Components { get; init; } = [];

    /// <summary>
    /// Gets the primary key type (first in the list).
    /// </summary>
    public Maybe<KeyType> PrimaryKeyType =>
        KeyTypes.Any() ? Maybe<KeyType>.From(KeyTypes.First()) : Maybe<KeyType>.None;

    /// <summary>
    /// Gets the key length in bits based on the primary key type.
    /// </summary>
    public int KeyLength => Components.Count > 0 ? Components[0].Length * 8 : 0;

    /// <summary>
    /// Formats the key entry as a human-readable string.
    /// </summary>
    public override string ToString()
    {
        string keyTypeStr = PrimaryKeyType
            .Map(keyType => keyType.ToFriendlyString())
            .GetValueOrDefault("Unknown");
        string lengthStr = KeyLength > 0 ? $"length: {KeyLength / 8} ({keyTypeStr})" : keyTypeStr;

        return $"Version: {KeyVersion} (0x{KeyVersion:X2}) ID: {KeyId} (0x{KeyId:X2}) type: {keyTypeStr, -12} {lengthStr}";
    }
}

/// <summary>
/// Key types as defined in GlobalPlatform specification.
/// </summary>
public enum KeyType
{
    Unknown = 0,
    Des = 0x80,
    PreSharedTls = 0x85,
    Aes = 0x88,
    HmacSha1 = 0x90,
    HmacSha1_160 = 0x91,
    RsaPublicExponentECleartext = 0xA0,
    RsaModulusNCleartext = 0xA1,
    RsaModulusN = 0xA2,
    RsaPrivateExponentD = 0xA3,
    RsaChineseRemainderP = 0xA4,
    RsaChineseRemainderQ = 0xA5,
    RsaChineseRemainderPq = 0xA6,
    RsaChineseRemainderDpi = 0xA7,
    RsaChineseRemainderDqi = 0xA8,
    EccPublic = 0xB0,
    EccPrivate = 0xB1,
    EccFieldP = 0xB2,
    EccFieldA = 0xB3,
    EccFieldB = 0xB4,
    EccGenerator = 0xB5,
    EccGeneratorOrder = 0xB6,
    EccCofactor = 0xB7,
    EccParametersReference = 0xF0,
}

/// <summary>
/// Extension methods for KeyType formatting.
/// </summary>
public static class KeyTypeExtensions
{
    public static string ToFriendlyString(this KeyType keyType)
    {
        return keyType switch
        {
            KeyType.Des => "DES",
            KeyType.PreSharedTls => "TLS-PSK",
            KeyType.Aes => "AES",
            KeyType.HmacSha1 => "HMAC-SHA1",
            KeyType.HmacSha1_160 => "HMAC-SHA1-160",
            KeyType.RsaPublicExponentECleartext => "RSA-PUB-E",
            KeyType.RsaModulusNCleartext => "RSA-MOD-N",
            KeyType.RsaModulusN => "RSA-MOD-N-ENC",
            KeyType.RsaPrivateExponentD => "RSA-PRIV-D",
            KeyType.RsaChineseRemainderP => "RSA-CRT-P",
            KeyType.RsaChineseRemainderQ => "RSA-CRT-Q",
            KeyType.RsaChineseRemainderPq => "RSA-CRT-PQ",
            KeyType.RsaChineseRemainderDpi => "RSA-CRT-DPI",
            KeyType.RsaChineseRemainderDqi => "RSA-CRT-DQI",
            KeyType.EccPublic => "ECC-PUBLIC",
            KeyType.EccPrivate => "ECC-PRIVATE",
            KeyType.EccFieldP => "ECC-P",
            KeyType.EccFieldA => "ECC-A",
            KeyType.EccFieldB => "ECC-B",
            KeyType.EccGenerator => "ECC-G",
            KeyType.EccGeneratorOrder => "ECC-N",
            KeyType.EccCofactor => "ECC-K",
            KeyType.EccParametersReference => "ECC-PARAMETERS",
            _ => $"Unknown(0x{(byte)keyType:X2})",
        };
    }
}
