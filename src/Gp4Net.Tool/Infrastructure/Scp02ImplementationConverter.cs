using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using Gp4Net.Constants;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Infrastructure;

/// <summary>
/// Type converter for SCP02 implementation parameter parsing.
/// Supports both hex values (15, 35, 75) and specific aliases (CLR, MAC, ENC, RENC).
/// Based on GlobalPlatform Card Specification v2.3.1 Table E-1 bitmap structure.
/// </summary>
[PublicAPI]
public class Scp02ImplementationConverter : TypeConverter
{
    /// <summary>
    /// Dictionary mapping user input strings to ScpImplementation enum values.
    /// Includes all hex values and specific aliases for common modes.
    /// </summary>
    private static readonly Dictionary<string, ScpImplementation> _validValues = new()
    {
        // All SCP02 hex values (comprehensive support)
        { "00", ScpImplementation.Scp02I00 },
        { "02", ScpImplementation.Scp02I02 },
        { "04", ScpImplementation.Scp02I04 },
        { "05", ScpImplementation.Scp02I05 },
        { "0A", ScpImplementation.Scp02I0A },
        { "14", ScpImplementation.Scp02I14 },
        { "15", ScpImplementation.Scp02I15 },
        { "1A", ScpImplementation.Scp02I1A },
        { "24", ScpImplementation.Scp02I24 },
        { "25", ScpImplementation.Scp02I25 },
        { "2A", ScpImplementation.Scp02I2A },
        { "34", ScpImplementation.Scp02I34 },
        { "35", ScpImplementation.Scp02I35 },
        { "3A", ScpImplementation.Scp02I3A },
        { "44", ScpImplementation.Scp02I44 },
        { "45", ScpImplementation.Scp02I45 },
        { "4A", ScpImplementation.Scp02I4A },
        { "54", ScpImplementation.Scp02I54 },
        { "55", ScpImplementation.Scp02I55 },
        { "64", ScpImplementation.Scp02I64 },
        { "65", ScpImplementation.Scp02I65 },
        { "6A", ScpImplementation.Scp02I6A },
        { "74", ScpImplementation.Scp02I74 },
        { "75", ScpImplementation.Scp02I75 },
        { "7A", ScpImplementation.Scp02I7A },
        // SCP03 hex values
        { "10", ScpImplementation.Scp03I10 },
        { "11", ScpImplementation.Scp03I11 },
        { "20", ScpImplementation.Scp03I20 },
        { "30", ScpImplementation.Scp03I30 },
        { "60", ScpImplementation.Scp03I60 },
        { "70", ScpImplementation.Scp03I70 },
        // Specific aliases based on exact features (no ambiguity)
        { "CLR", ScpImplementation.Scp02I15 }, // Most common SCP02 mode (i=15)
        { "MAC", ScpImplementation.Scp02I35 }, // CLR + R-MAC support (i=35)
        { "ENC", ScpImplementation.Scp02I55 }, // CLR + well-known challenge (i=55)
        { "RENC", ScpImplementation.Scp02I75 }, // Full security: CLR + well-known + R-MAC (i=75)
        { "IMPLICIT", ScpImplementation.Scp02I1A }, // Implicit initiation mode (i=1A)
        { "BASE_KEY", ScpImplementation.Scp02I14 }, // Single base key variant of CLR (i=14)
    };

    /// <summary>
    /// Determines whether this converter can convert from the given source type.
    /// </summary>
    /// <param name="context">Type descriptor context</param>
    /// <param name="sourceType">The type to convert from</param>
    /// <returns>True if conversion is supported</returns>
    public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
    {
        return sourceType == typeof(string) || base.CanConvertFrom(context, sourceType);
    }

    /// <summary>
    /// Converts the given value to an ScpImplementation enum value.
    /// Supports hex formats (15, 35, 75) and specific aliases (CLR, MAC, ENC, RENC).
    /// </summary>
    /// <param name="context">Type descriptor context</param>
    /// <param name="culture">Culture information</param>
    /// <param name="value">The value to convert</param>
    /// <returns>The converted ScpImplementation enum value</returns>
    /// <exception cref="NotSupportedException">Thrown when the value is not supported</exception>
    public override object ConvertFrom(
        ITypeDescriptorContext context,
        CultureInfo culture,
        object value
    )
    {
        if (value is string str)
        {
            string normalizedStr = str.Trim().ToUpperInvariant();

            // Try direct lookup in dictionary
            if (_validValues.TryGetValue(normalizedStr, out ScpImplementation implementation))
                return implementation;

            // Try parsing as hex number (with or without 0x prefix)
            string hexStr = normalizedStr.StartsWith("0X") ? normalizedStr[2..] : normalizedStr;
            if (
                byte.TryParse(
                    hexStr,
                    NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture,
                    out byte byteValue
                )
            )
            {
                if (Enum.IsDefined(typeof(ScpImplementation), byteValue))
                    return (ScpImplementation)byteValue;
            }

            // Generate helpful error message
            string commonOptions = "15|CLR, 35|MAC, 55|ENC, 75|RENC, 1A|IMPLICIT";
            throw new NotSupportedException(
                $"SCP implementation '{value}' not supported. "
                    + $"Common options: {commonOptions}. "
                    + $"All valid SCP02 'i' parameter values (04-7A) are supported. "
                    + $"Use hex format (15) or specific aliases (CLR)."
            );
        }

        return base.ConvertFrom(context, culture, value);
    }

    /// <summary>
    /// Determines whether this converter can convert to the given destination type.
    /// </summary>
    /// <param name="context">Type descriptor context</param>
    /// <param name="destinationType">The type to convert to</param>
    /// <returns>True if conversion is supported</returns>
    public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType)
    {
        return destinationType == typeof(string) || base.CanConvertTo(context, destinationType);
    }

    /// <summary>
    /// Converts the given ScpImplementation value to a string representation.
    /// </summary>
    /// <param name="context">Type descriptor context</param>
    /// <param name="culture">Culture information</param>
    /// <param name="value">The value to convert</param>
    /// <param name="destinationType">The destination type</param>
    /// <returns>String representation of the implementation</returns>
    public override object ConvertTo(
        ITypeDescriptorContext context,
        CultureInfo culture,
        object value,
        Type destinationType
    )
    {
        if (destinationType == typeof(string) && value is ScpImplementation impl)
        {
            // Return alias if available, otherwise hex format
            string alias = impl.GetAlias();
            return alias.Length == 2 ? alias : $"{alias} ({(byte)impl:X2})";
        }

        return base.ConvertTo(context, culture, value, destinationType);
    }

    /// <summary>
    /// Gets all supported implementation values for help text generation.
    /// </summary>
    /// <returns>Dictionary of supported values</returns>
    public static IReadOnlyDictionary<string, ScpImplementation> GetSupportedValues()
    {
        return _validValues;
    }

    /// <summary>
    /// Gets a list of common implementation options for user guidance.
    /// </summary>
    /// <returns>List of common options with descriptions</returns>
    public static List<(string Value, string Description)> GetCommonOptions()
    {
        return
        [
            ("15", "Standard SCP02 mode (C-MAC only)"),
            ("CLR", "Alias for 15 - most compatible mode"),
            ("35", "SCP02 with response MAC verification"),
            ("MAC", "Alias for 35 - CLR + R-MAC"),
            ("55", "SCP02 with well-known challenge"),
            ("ENC", "Alias for 55 - CLR + challenge"),
            ("75", "Full security mode (R-MAC + R-ENC)"),
            ("RENC", "Alias for 75 - complete bidirectional security"),
            ("1A", "Implicit initiation mode"),
            ("IMPLICIT", "Alias for 1A - different initiation"),
        ];
    }
}
