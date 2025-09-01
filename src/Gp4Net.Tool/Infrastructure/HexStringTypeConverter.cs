using System;
using System.ComponentModel;
using System.Globalization;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Infrastructure;

/// <summary>
/// Type converter for hex string to byte array conversion.
/// </summary>
[PublicAPI]
public class HexStringTypeConverter : TypeConverter
{
    /// <inheritdoc />
    public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
    {
        return sourceType == typeof(string) || base.CanConvertFrom(context, sourceType);
    }

    /// <inheritdoc />
    public override object ConvertFrom(
        ITypeDescriptorContext context,
        CultureInfo culture,
        object value
    )
    {
        if (value is string hexString)
        {
            if (string.IsNullOrWhiteSpace(hexString))
            {
                return null;
            }

            try
            {
                // Remove spaces and convert to uppercase
                hexString = hexString.Replace(" ", "").ToUpperInvariant();

                // Validate hex string
                if (hexString.Length % 2 != 0)
                {
                    throw new ArgumentException(
                        "Hex string must have an even number of characters"
                    );
                }

                return Convert.FromHexString(hexString);
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"Invalid hex string: {ex.Message}", ex);
            }
        }

        return base.ConvertFrom(context, culture, value);
    }
}
