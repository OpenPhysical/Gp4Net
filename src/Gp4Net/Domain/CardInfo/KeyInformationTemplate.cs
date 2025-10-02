using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;
using static Gp4Net.Services.TlvService;

namespace Gp4Net.Domain.CardInfo;

/// <summary>
/// Key Information Template parser for GlobalPlatform tag 0xE0.
/// Based on GlobalPlatform Card Specification section 9.3.3.1.
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
    public IReadOnlyList<KeyEntry> Keys { get; init; } = [];

    private KeyInformationTemplate(byte[] rawData, IReadOnlyList<KeyEntry> keys = null)
    {
        // rawData is guaranteed to be non-null by static factory methods
        Data = rawData;
        Keys = keys ?? [];
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

        var template = new KeyInformationTemplate(data, []);

        // Check if data starts with E0 tag and extract the content
        byte[] contentToParse = data;
        if (data.Length >= 2 && data[0] == 0xE0)
        {
            // This is an E0 tag, extract its content
            int offset = 1;
            int length = 0;

            if ((data[1] & 0x80) == 0)
            {
                // Short form length
                length = data[1];
                offset = 2;
            }
            else
            {
                // Long form length
                int lenLength = data[1] & 0x7F;
                if (lenLength is > 0 and <= 4 && 2 + lenLength <= data.Length)
                {
                    offset = 2;
                    for (int i = 0; i < lenLength; i++)
                    {
                        length = length << 8 | data[offset++];
                    }
                }
            }

            if (length > 0 && offset + length <= data.Length)
            {
                contentToParse = new byte[length];
                Array.Copy(data, offset, contentToParse, 0, length);
            }
        }

        // Parse the content for C0 tags
        return TlvParser
            .ParseMultiple([.. contentToParse])
            .Map(parseResult =>
            {
                IReadOnlyList<KeyEntry> keys = parseResult
                    .Objects.Where(element =>
                        element
                            .Tag.ToNumber()
                            .Match(onSuccess: tagNumber => tagNumber == 0xC0, onFailure: _ => false)
                    )
                    .Select(element => ParseKeyInformationData(element.TlvData.Bytes.ToArray()))
                    .Where(maybeKey => maybeKey.HasValue)
                    .Select(maybeKey => maybeKey.Value)
                    .ToImmutableList();

                return new KeyInformationTemplate(data, keys);
            });
    }

    private static Maybe<KeyEntry> ParseKeyInformationData(byte[] data)
    {
        if (data.Length < 3)
        {
            return Maybe<KeyEntry>.None;
        }

        IReadOnlyList<KeyType> keyTypes = data.Skip(2)
            .Select(ParseKeyType)
            .Where(keyType => keyType != KeyType.Unknown)
            .ToImmutableList();

        return Maybe<KeyEntry>.From(new KeyEntry
        {
            KeyId = data[0],
            KeyVersion = data[1],
            KeyTypes = keyTypes,
        });
    }

    private static KeyType ParseKeyType(byte value)
    {
        return value switch
        {
            0x80 => KeyType.Des,
            0x81 => KeyType.TripleDes2Key,
            0x82 => KeyType.TripleDes3Key,
            0x83 => KeyType.Des3,
            0x88 => KeyType.Aes,
            0xA0 => KeyType.RsaPublicExponentECleartext,
            0xA1 => KeyType.RsaModulusNCleartext,
            0xA2 => KeyType.RsaModulusN,
            0xA3 => KeyType.RsaPrivateExponentD,
            0xA4 => KeyType.RsaChineseRemainderP,
            0xA5 => KeyType.RsaChineseRemainderQ,
            0xA6 => KeyType.RsaChineseRemainderPq,
            0xA7 => KeyType.RsaChineseRemainderDpi,
            0xA8 => KeyType.RsaChineseRemainderDqi,
            0xFF => KeyType.NotAvailable,
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
    /// Gets the primary key type (first in the list).
    /// </summary>
    public Maybe<KeyType> PrimaryKeyType =>
        KeyTypes.Any() ? Maybe<KeyType>.From(KeyTypes.First()) : Maybe<KeyType>.None;

    /// <summary>
    /// Gets the key length in bits based on the primary key type.
    /// </summary>
    public int KeyLength => PrimaryKeyType.Map(DetermineKeyLength).GetValueOrDefault(0);

    private static int DetermineKeyLength(KeyType keyType)
    {
        return keyType switch
        {
            KeyType.Des => 64,
            KeyType.TripleDes2Key => 128,
            KeyType.TripleDes3Key => 192,
            KeyType.Des3 => 192,
            KeyType.Aes => 128, // Default AES, actual length may vary
            _ => 0,
        };
    }

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
    TripleDes2Key = 0x81,
    TripleDes3Key = 0x82,
    Des3 = 0x83,
    Aes = 0x88,
    RsaPublicExponentECleartext = 0xA0,
    RsaModulusNCleartext = 0xA1,
    RsaModulusN = 0xA2,
    RsaPrivateExponentD = 0xA3,
    RsaChineseRemainderP = 0xA4,
    RsaChineseRemainderQ = 0xA5,
    RsaChineseRemainderPq = 0xA6,
    RsaChineseRemainderDpi = 0xA7,
    RsaChineseRemainderDqi = 0xA8,
    NotAvailable = 0xFF,
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
            KeyType.TripleDes2Key => "3DES-2KEY",
            KeyType.TripleDes3Key => "3DES-3KEY",
            KeyType.Des3 => "3DES",
            KeyType.Aes => "AES",
            KeyType.RsaPublicExponentECleartext => "RSA-PUB-E",
            KeyType.RsaModulusNCleartext => "RSA-MOD-N",
            KeyType.RsaModulusN => "RSA-MOD-N-ENC",
            KeyType.RsaPrivateExponentD => "RSA-PRIV-D",
            KeyType.RsaChineseRemainderP => "RSA-CRT-P",
            KeyType.RsaChineseRemainderQ => "RSA-CRT-Q",
            KeyType.RsaChineseRemainderPq => "RSA-CRT-PQ",
            KeyType.RsaChineseRemainderDpi => "RSA-CRT-DPI",
            KeyType.RsaChineseRemainderDqi => "RSA-CRT-DQI",
            KeyType.NotAvailable => "N/A",
            _ => $"Unknown(0x{(byte)keyType:X2})",
        };
    }
}
