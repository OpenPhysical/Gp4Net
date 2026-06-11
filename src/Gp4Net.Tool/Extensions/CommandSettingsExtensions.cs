using System;
using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Gp4Net.Domain;
using Gp4Net.Tool.Commands;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Extensions;

/// <summary>
/// Pure functional extensions for converting command settings to domain requests.
/// Eliminates imperative keyset resolution patterns in commands.
/// </summary>
[PublicAPI]
public static class CommandSettingsExtensions
{
    /// <summary>
    /// Converts SecureCommandSettings to SecureChannelRequest using pure functional transformation.
    /// </summary>
    /// <param name="settings">The secure command settings.</param>
    /// <returns>A secure channel request for pipeline processing.</returns>
    public static SecureChannelRequest ToSecureChannelRequest(this SecureCommandSettings settings)
    {
        return new SecureChannelRequest(
            KeysetName: settings.GetKeyset(),
            ExplicitKeys: ExtractExplicitKeys(settings),
            KeysetParameters: ExtractKeysetParameters(settings),
            SecurityLevel: SecurityLevel.CMac, // Default for GP operations
            ExplicitKeyVersion: ExtractKeyVersion(settings)
        );
    }

    /// <summary>
    /// Extracts explicit keys from settings using functional composition.
    /// Pure function that handles hex string conversion safely.
    /// </summary>
    private static Maybe<ExplicitKeys> ExtractExplicitKeys(SecureCommandSettings settings)
    {
        // Check if any explicit keys are provided
        bool hasExplicitKeys = HasExplicitKeyProperties(settings);
        if (!hasExplicitKeys)
        {
            return Maybe<ExplicitKeys>.None;
        }

        // Extract and convert hex keys using pure functions
        var encKey = ExtractHexKey(GetEncKeyProperty(settings));
        var macKey = ExtractHexKey(GetMacKeyProperty(settings));
        var dekKey = ExtractHexKey(GetDekKeyProperty(settings));

        // Validate that all keys are present if any are provided
        return encKey.Bind(enc =>
            macKey.Bind(mac => dekKey.Map(dek => new ExplicitKeys(enc, mac, dek)))
        );
    }

    /// <summary>
    /// Checks if settings have explicit key properties using reflection-free approach.
    /// Pure function for property detection.
    /// </summary>
    private static bool HasExplicitKeyProperties(SecureCommandSettings settings)
    {
        // Use dynamic property access with safe fallbacks
        var settingsType = settings.GetType();

        return HasPropertyWithValue(settingsType, settings, "KeyEnc")
            || HasPropertyWithValue(settingsType, settings, "KeyMac")
            || HasPropertyWithValue(settingsType, settings, "KeyDek");
    }

    /// <summary>
    /// Gets encryption key property value using safe property access.
    /// </summary>
    private static Maybe<string> GetEncKeyProperty(SecureCommandSettings settings)
    {
        return GetPropertyValue(settings.GetType(), settings, "KeyEnc");
    }

    /// <summary>
    /// Gets MAC key property value using safe property access.
    /// </summary>
    private static Maybe<string> GetMacKeyProperty(SecureCommandSettings settings)
    {
        return GetPropertyValue(settings.GetType(), settings, "KeyMac");
    }

    /// <summary>
    /// Gets DEK key property value using safe property access.
    /// </summary>
    private static Maybe<string> GetDekKeyProperty(SecureCommandSettings settings)
    {
        return GetPropertyValue(settings.GetType(), settings, "KeyDek");
    }

    /// <summary>
    /// Extracts key version from settings with functional fallback.
    /// </summary>
    private static Maybe<byte> ExtractKeyVersion(SecureCommandSettings settings)
    {
        object? value = settings.GetType().GetProperty("KeyVersion")?.GetValue(settings);
        return value switch
        {
            Maybe<byte> maybe => maybe,
            byte keyVersion => Maybe<byte>.From(keyVersion),
            string text => ParseByte(text),
            _ => Maybe<byte>.None,
        };
    }

    /// <summary>
    /// Extracts keyset parameters using safe property access.
    /// </summary>
    private static Maybe<Dictionary<string, string>> ExtractKeysetParameters(
        SecureCommandSettings settings
    )
    {
        return GetPropertyValue(settings.GetType(), settings, "KeysetParams")
            .Where(param => !string.IsNullOrEmpty(param))
            .Map(_ => new Dictionary<string, string>()); // Extend parsing logic here if needed
    }

    /// <summary>
    /// Converts hex string to byte array using pure functional error handling.
    /// </summary>
    private static Maybe<byte[]> ExtractHexKey(Maybe<string> hexString)
    {
        return hexString
            .Where(s => !string.IsNullOrEmpty(s))
            .Bind(hex =>
                Maybe<byte[]>.From(
                    Result
                        .Try(() => Convert.FromHexString(hex), _ => (byte[])null)
                        .GetValueOrDefault()
                )
            );
    }

    /// <summary>
    /// Safe property value extraction using reflection.
    /// Pure function with Maybe return type.
    /// </summary>
    private static Maybe<string> GetPropertyValue(
        Type settingsType,
        object settings,
        string propertyName
    )
    {
        object? value = settingsType.GetProperty(propertyName)?.GetValue(settings);
        return value switch
        {
            string text => Maybe<string>.From(text),
            Maybe<string> maybe => maybe,
            _ => Maybe<string>.None,
        };
    }

    private static Maybe<byte> ParseByte(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Maybe<byte>.None;
        }

        string normalized = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? value[2..]
            : value;

        return byte.TryParse(normalized, out byte decimalValue)
            ? Maybe<byte>.From(decimalValue)
            : byte.TryParse(
                normalized,
                System.Globalization.NumberStyles.HexNumber,
                provider: null,
                out byte hexValue
            )
                ? Maybe<byte>.From(hexValue)
                : Maybe<byte>.None;
    }

    /// <summary>
    /// Checks if a property exists and has a non-empty value.
    /// </summary>
    private static bool HasPropertyWithValue(
        Type settingsType,
        object settings,
        string propertyName
    )
    {
        return GetPropertyValue(settingsType, settings, propertyName)
            .Where(static value => !string.IsNullOrEmpty(value))
            .HasValue;
    }
}
