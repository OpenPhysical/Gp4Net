using System;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Infrastructure;

/// <summary>
/// Type converter for byte values that supports hex string input.
/// </summary>
[PublicAPI]
public class ByteTypeConverter : TypeConverter
{
    /// <inheritdoc />
    public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
    {
        return sourceType == typeof(string)
            || sourceType == typeof(int)
            || sourceType == typeof(long)
            || base.CanConvertFrom(context, sourceType);
    }

    /// <inheritdoc />
    public override object ConvertFrom(
        ITypeDescriptorContext context,
        CultureInfo culture,
        object value
    )
    {
        switch (value)
        {
            case string stringValue:
                return ConvertFromString(stringValue);

            case int intValue:
                if (intValue is >= byte.MinValue and <= byte.MaxValue)
                {
                    return (byte)intValue;
                }

                throw new ArgumentOutOfRangeException(
                    nameof(value),
                    $"Value {intValue} is outside the range of byte (0-255)"
                );

            case long longValue:
                if (longValue is >= byte.MinValue and <= byte.MaxValue)
                {
                    return (byte)longValue;
                }

                throw new ArgumentOutOfRangeException(
                    nameof(value),
                    $"Value {longValue} is outside the range of byte (0-255)"
                );

            default:
                return base.ConvertFrom(context, culture, value);
        }
    }

    private static new byte ConvertFromString(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value cannot be null or empty");
        }

        value = value.Trim();

        // Handle hex strings (0x prefix or pure hex)
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            value = value.Substring(2);
            return Convert.ToByte(value, 16);
        }

        // Try hex first if it looks like hex (all hex digits)
        if (value.Length <= 2 && IsHexString(value))
        {
            try
            {
                return Convert.ToByte(value, 16);
            }
            catch
            {
                // Fall through to decimal parsing
            }
        }

        // Parse as decimal
        if (byte.TryParse(value, out byte result))
        {
            return result;
        }

        throw new ArgumentException(
            $"Cannot convert '{value}' to byte. Use decimal (0-255) or hex (0x00-0xFF) format."
        );
    }

    private static bool IsHexString(string value) => value.All(Uri.IsHexDigit);

    /// <inheritdoc />
    public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType)
    {
        return destinationType == typeof(string) || base.CanConvertTo(context, destinationType);
    }

    /// <inheritdoc />
    public override object ConvertTo(
        ITypeDescriptorContext context,
        CultureInfo culture,
        object value,
        Type destinationType
    )
    {
        if (destinationType == typeof(string) && value is byte byteValue)
        {
            return byteValue.ToString();
        }

        return base.ConvertTo(context, culture, value, destinationType);
    }
}
