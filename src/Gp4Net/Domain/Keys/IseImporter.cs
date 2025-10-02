using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Domain.Keys;

/// <summary>
/// Imports ISE (Issuer Security Domain Extension) key files into the secure key store.
/// Supports various ISE formats including standard GP test keys and custom key sets.
/// </summary>
public static class IseImporter
{
    /// <summary>
    /// Represents an ISE key entry.
    /// </summary>
    public record IseKeyEntry(
        string KeyId,
        byte[] KeyValue,
        KeyType Type,
        byte KeyVersion,
        string Description
    );

    /// <summary>
    /// Key types supported in ISE files.
    /// </summary>
    public enum KeyType
    {
        /// <summary>
        /// Encryption key (ENC).
        /// </summary>
        Enc,

        /// <summary>
        /// Message Authentication Code key (MAC).
        /// </summary>
        Mac,

        /// <summary>
        /// Data Encryption Key (DEK/KEK).
        /// </summary>
        Dek,

        /// <summary>
        /// Key Encryption Key (KEK).
        /// </summary>
        Kek,
    }

    /// <summary>
    /// Imports an ISE file into the secure key store.
    /// </summary>
    /// <param name="store">The secure key store to import into.</param>
    /// <param name="filePath">The path to the ISE file.</param>
    /// <returns>A Result containing the updated store with imported keys or an error.</returns>
    public static Result<SecureKeyStore, SmartCardError> ImportFromFile(
        SecureKeyStore store,
        string filePath
    )
    {
        if (store == null)
        {
            return Result.Failure<SecureKeyStore, SmartCardError>(
                SmartCardError.InvalidArgument("Store cannot be null")
            );
        }

        if (string.IsNullOrWhiteSpace(filePath))
        {
            return Result.Failure<SecureKeyStore, SmartCardError>(
                SmartCardError.InvalidArgument("File path cannot be null or empty")
            );
        }

        if (!File.Exists(filePath))
        {
            return Result.Failure<SecureKeyStore, SmartCardError>(SmartCardError.FileNotFound());
        }

        return Result
            .Try(
                () => File.ReadAllText(filePath),
                ex => SmartCardError.UnexpectedError($"Failed to read ISE file: {ex.Message}", ex)
            )
            .Bind(content => ImportFromString(store, content));
    }

    /// <summary>
    /// Imports ISE content from a string into the secure key store.
    /// </summary>
    /// <param name="store">The secure key store to import into.</param>
    /// <param name="content">The ISE content as a string.</param>
    /// <returns>A Result containing the updated store with imported keys or an error.</returns>
    public static Result<SecureKeyStore, SmartCardError> ImportFromString(
        SecureKeyStore store,
        string content
    )
    {
        if (store == null)
        {
            return Result.Failure<SecureKeyStore, SmartCardError>(
                SmartCardError.InvalidArgument("Store cannot be null")
            );
        }

        if (string.IsNullOrWhiteSpace(content))
        {
            return Result.Failure<SecureKeyStore, SmartCardError>(
                SmartCardError.InvalidArgument("Content cannot be null or empty")
            );
        }

        var parseResult = ParseIseContent(content);
        if (parseResult.IsFailure)
        {
            return Result.Failure<SecureKeyStore, SmartCardError>(parseResult.Error);
        }

        var entries = parseResult.Value;
        var currentStore = store;

        // Import each key entry into the store
        foreach (var entry in entries)
        {
            string keyId = GenerateKeyId(entry);
            var addResult = currentStore.AddKey(keyId, entry.KeyValue);

            if (addResult.IsFailure)
            {
                return Result.Failure<SecureKeyStore, SmartCardError>(addResult.Error);
            }

            currentStore = addResult.Value;
        }

        return Result.Success<SecureKeyStore, SmartCardError>(currentStore);
    }

    /// <summary>
    /// Imports a standard GP test key set into the secure key store.
    /// </summary>
    /// <param name="store">The secure key store to import into.</param>
    /// <param name="keySetName">The name for this key set.</param>
    /// <param name="keyVersion">The key version.</param>
    /// <param name="isScp03">Whether this is for SCP03 (true) or SCP02 (false).</param>
    /// <returns>A Result containing the updated store or an error.</returns>
    public static Result<SecureKeyStore, SmartCardError> ImportGpTestKeys(
        SecureKeyStore store,
        string keySetName,
        byte keyVersion = 0x00,
        bool isScp03 = false
    )
    {
        if (store == null)
        {
            return Result.Failure<SecureKeyStore, SmartCardError>(
                SmartCardError.InvalidArgument("Store cannot be null")
            );
        }

        if (string.IsNullOrWhiteSpace(keySetName))
        {
            return Result.Failure<SecureKeyStore, SmartCardError>(
                SmartCardError.InvalidArgument("Key set name cannot be null or empty")
            );
        }

        var currentStore = store;
        string protocol = isScp03 ? "SCP03" : "SCP02";

        // Import the three standard GP test keys
        KeyType[] keyTypes = [KeyType.Enc, KeyType.Mac, KeyType.Dek];

        foreach (var keyType in keyTypes)
        {
            string keyId = $"{keySetName}_{protocol}_{keyType}_{keyVersion:X2}";
            var addResult = currentStore.AddKey(keyId, GpTestKeys.GpTestKey);

            if (addResult.IsFailure)
            {
                return Result.Failure<SecureKeyStore, SmartCardError>(addResult.Error);
            }

            currentStore = addResult.Value;
        }

        return Result.Success<SecureKeyStore, SmartCardError>(currentStore);
    }

    /// <summary>
    /// Creates a key set from imported ISE keys in the store.
    /// </summary>
    /// <param name="store">The secure key store containing the keys.</param>
    /// <param name="keySetName">The name of the key set.</param>
    /// <param name="keyVersion">The key version.</param>
    /// <param name="isScp03">Whether this is for SCP03 (true) or SCP02 (false).</param>
    /// <returns>A Result containing the key set or an error.</returns>
    public static Result<IKeySet, SmartCardError> CreateKeySetFromImported(
        SecureKeyStore store,
        string keySetName,
        byte keyVersion = 0x00,
        bool isScp03 = false
    )
    {
        if (store == null)
        {
            return Result.Failure<IKeySet, SmartCardError>(
                SmartCardError.InvalidArgument("Store cannot be null")
            );
        }

        if (string.IsNullOrWhiteSpace(keySetName))
        {
            return Result.Failure<IKeySet, SmartCardError>(
                SmartCardError.InvalidArgument("Key set name cannot be null or empty")
            );
        }

        string protocol = isScp03 ? "SCP03" : "SCP02";
        string encKeyId = $"{keySetName}_{protocol}_{KeyType.Enc}_{keyVersion:X2}";
        string macKeyId = $"{keySetName}_{protocol}_{KeyType.Mac}_{keyVersion:X2}";
        string dekKeyId = $"{keySetName}_{protocol}_{KeyType.Dek}_{keyVersion:X2}";

        return store.CreateKeySet(encKeyId, macKeyId, dekKeyId, keyVersion, isScp03);
    }

    /// <summary>
    /// Parses ISE content into key entries.
    /// Supports multiple ISE formats including hex strings and structured formats.
    /// </summary>
    private static Result<List<IseKeyEntry>, SmartCardError> ParseIseContent(string content)
    {
        List<IseKeyEntry> entries = [];
        List<string> lines =
        [
            .. content
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Trim())
                .Where(line => !string.IsNullOrWhiteSpace(line) && !line.StartsWith('#')),
        ];

        if (lines.Count == 0)
        {
            return Result.Failure<List<IseKeyEntry>, SmartCardError>(
                SmartCardError.InvalidArgument("No valid key entries found in ISE content")
            );
        }

        // Try to detect format
        if (lines.Any(line => line.Contains('=')))
        {
            // Key-value format: KEY_TYPE=HEX_VALUE
            return ParseKeyValueFormat(lines);
        }
        switch (lines.Count)
        {
            case 3 when lines.All(line => IsHexString(line)):
                // Three hex lines format (ENC, MAC, DEK)
                return ParseThreeLineFormat(lines);
            case 1 when IsHexString(lines[0]):
                // Single hex line (use same key for all)
                return ParseSingleLineFormat(lines[0]);
            default:
                return Result.Failure<List<IseKeyEntry>, SmartCardError>(
                    SmartCardError.InvalidArgument("Unrecognized ISE format")
                );
        }
    }

    /// <summary>
    /// Parses key-value format ISE content.
    /// Format: KEY_TYPE=HEX_VALUE
    /// </summary>
    private static Result<List<IseKeyEntry>, SmartCardError> ParseKeyValueFormat(List<string> lines)
    {
        List<IseKeyEntry> entries = [];
        byte keyVersion = 0x00;

        foreach (string line in lines)
        {
            string[] parts = line.Split('=', 2);
            if (parts.Length != 2)
            {
                continue;
            }

            string keyName = parts[0].Trim().ToUpperInvariant();
            string hexValue = parts[1].Trim();

            if (keyName == "KEY_VERSION")
            {
                if (byte.TryParse(hexValue, NumberStyles.HexNumber, null, out byte version))
                {
                    keyVersion = version;
                }
                continue;
            }

            var keyTypeResult = ParseKeyType(keyName);
            if (keyTypeResult.IsFailure)
            {
                continue;
            }

            var hexParseResult = Result.Try(
                () =>
                {
                    string cleanedHex = hexValue.Replace(" ", "").Replace("-", "");
                    return Convert.FromHexString(cleanedHex);
                },
                _ => SmartCardError.InvalidArgument($"Invalid hex value for {keyName}")
            );

            if (hexParseResult.IsFailure)
            {
                return hexParseResult.Error;
            }

            entries.Add(
                new IseKeyEntry(
                    KeyId: keyName,
                    KeyValue: hexParseResult.Value,
                    Type: keyTypeResult.Value,
                    KeyVersion: keyVersion,
                    Description: $"ISE imported {keyName}"
                )
            );
        }

        if (entries.Count == 0)
        {
            return Result.Failure<List<IseKeyEntry>, SmartCardError>(
                SmartCardError.InvalidArgument("No valid keys found in key-value format")
            );
        }

        return Result.Success<List<IseKeyEntry>, SmartCardError>(entries);
    }

    /// <summary>
    /// Parses three-line format ISE content (ENC, MAC, DEK).
    /// </summary>
    private static Result<List<IseKeyEntry>, SmartCardError> ParseThreeLineFormat(
        List<string> lines
    )
    {
        List<IseKeyEntry> entries = [];
        KeyType[] keyTypes = [KeyType.Enc, KeyType.Mac, KeyType.Dek];

        for (int i = 0; i < 3; i++)
        {
            var hexParseResult = Result.Try(
                () =>
                {
                    string cleanedHex = lines[i].Replace(" ", "").Replace("-", "");
                    return Convert.FromHexString(cleanedHex);
                },
                _ => SmartCardError.InvalidArgument($"Invalid hex on line {i + 1}")
            );

            if (hexParseResult.IsFailure)
            {
                return hexParseResult.Error;
            }

            entries.Add(
                new IseKeyEntry(
                    KeyId: keyTypes[i].ToString(),
                    KeyValue: hexParseResult.Value,
                    Type: keyTypes[i],
                    KeyVersion: 0x00,
                    Description: $"ISE imported {keyTypes[i]} key"
                )
            );
        }

        return Result.Success<List<IseKeyEntry>, SmartCardError>(entries);
    }

    /// <summary>
    /// Parses single-line format ISE content (same key for all types).
    /// </summary>
    private static Result<List<IseKeyEntry>, SmartCardError> ParseSingleLineFormat(string line)
    {
        return Result.Try(
            () =>
            {
                string cleanedHex = line.Replace(" ", "").Replace("-", "");
                byte[] keyBytes = Convert.FromHexString(cleanedHex);

                List<IseKeyEntry> entries = [];
                KeyType[] keyTypes = [KeyType.Enc, KeyType.Mac, KeyType.Dek];

                foreach (var keyType in keyTypes)
                {
                    entries.Add(
                        new IseKeyEntry(
                            KeyId: keyType.ToString(),
                            KeyValue: (byte[])keyBytes.Clone(),
                            Type: keyType,
                            KeyVersion: 0x00,
                            Description: $"ISE imported {keyType} key (shared)"
                        )
                    );
                }

                return entries;
            },
            _ => SmartCardError.InvalidArgument("Invalid hex string")
        );
    }

    /// <summary>
    /// Generates a unique key ID for storage.
    /// </summary>
    private static string GenerateKeyId(IseKeyEntry entry)
    {
        return $"ISE_{entry.KeyId}_{entry.Type}_{entry.KeyVersion:X2}";
    }

    /// <summary>
    /// Parses a key type from a string.
    /// </summary>
    private static Result<KeyType, SmartCardError> ParseKeyType(string keyName)
    {
        return keyName.ToUpperInvariant() switch
        {
            "ENC" or "ENCKEY" or "ENC_KEY" => Result.Success<KeyType, SmartCardError>(KeyType.Enc),
            "MAC" or "MACKEY" or "MAC_KEY" => Result.Success<KeyType, SmartCardError>(KeyType.Mac),
            "DEK" or "DEKKEY" or "DEK_KEY" => Result.Success<KeyType, SmartCardError>(KeyType.Dek),
            "KEK" or "KEKKEY" or "KEK_KEY" => Result.Success<KeyType, SmartCardError>(KeyType.Kek),
            _
                => Result.Failure<KeyType, SmartCardError>(
                    SmartCardError.InvalidArgument($"Unknown key type: {keyName}")
                ),
        };
    }

    /// <summary>
    /// Checks if a string is a valid hex string.
    /// </summary>
    private static bool IsHexString(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string trimmed = value.Trim().Replace(" ", "").Replace("-", "");
        return trimmed.Length % 2 == 0 && trimmed.All(c => "0123456789ABCDEFabcdef".Contains(c));
    }
}
