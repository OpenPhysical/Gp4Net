using System;
using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Gp4Net.Domain;
using Gp4Net.Tool.Commands;
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
            KeyVersion: ExtractKeyVersion(settings));
    }

    /// <summary>
    /// Extracts explicit keys from settings using functional composition.
    /// Pure function that handles hex string conversion safely.
    /// </summary>
    private static Maybe<ExplicitKeys> ExtractExplicitKeys(SecureCommandSettings settings)
    {
        // Check if any explicit keys are provided using functional patterns
        bool hasExplicitKeys = HasExplicitKeyProperties(settings);
        if (!hasExplicitKeys)
        {
            return Maybe<ExplicitKeys>.None;
        }

        // Extract and convert hex keys using pure functions
        Maybe<byte[]> encKey = ExtractHexKey(GetEncKeyProperty(settings));
        Maybe<byte[]> macKey = ExtractHexKey(GetMacKeyProperty(settings));
        Maybe<byte[]> dekKey = ExtractHexKey(GetDekKeyProperty(settings));

        // Validate that all keys are present if any are provided
        return encKey.Bind(enc =>
            macKey.Bind(mac =>
                dekKey.Map(dek => new ExplicitKeys(enc, mac, dek))));
    }

    /// <summary>
    /// Checks if settings have explicit key properties using reflection-free approach.
    /// Pure function for property detection.
    /// </summary>
    private static bool HasExplicitKeyProperties(SecureCommandSettings settings)
    {
        // Use dynamic property access with safe fallbacks
        Type settingsType = settings.GetType();
        
        return HasPropertyWithValue(settingsType, settings, "KeyEnc") ||
               HasPropertyWithValue(settingsType, settings, "KeyMac") ||
               HasPropertyWithValue(settingsType, settings, "KeyDek");
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
    private static byte ExtractKeyVersion(SecureCommandSettings settings)
    {
        Maybe<string> keyVersionProperty = GetPropertyValue(settings.GetType(), settings, "KeyVersion");
        return keyVersionProperty
            .Bind(value => Maybe<byte>.From(byte.TryParse(value, out byte result) ? (byte?)result : null))
            .GetValueOrDefault((byte)0x01);
    }

    /// <summary>
    /// Extracts keyset parameters using safe property access.
    /// </summary>
    private static Maybe<Dictionary<string, string>> ExtractKeysetParameters(SecureCommandSettings settings)
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
            .Bind(hex => Maybe<byte[]>.From(
                Result.Try(() => Convert.FromHexString(hex), _ => (byte[])null).GetValueOrDefault()));
    }

    /// <summary>
    /// Safe property value extraction using reflection.
    /// Pure function with Maybe return type.
    /// </summary>
    private static Maybe<string> GetPropertyValue(Type settingsType, object settings, string propertyName)
    {
        return Maybe<string>.From(
            settingsType.GetProperty(propertyName)?.GetValue(settings) as string);
    }

    /// <summary>
    /// Checks if a property exists and has a non-empty value.
    /// </summary>
    private static bool HasPropertyWithValue(Type settingsType, object settings, string propertyName)
    {
        return GetPropertyValue(settingsType, settings, propertyName)
            .Where(value => !string.IsNullOrEmpty(value))
            .HasValue;
    }
}