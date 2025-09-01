using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Cryptography;
using static Gp4Net.Cryptography.CryptoService;

namespace Gp4Net.Core.Functional;

public static class EnumParsingExtensions
{
    /// <summary>
    /// Parses a byte into TEnum with functional error handling.
    /// - For non-flags enums: value must match a defined named constant.
    /// - For [Flags] enums: value must contain only defined flag bits.
    /// Returns Result{TEnum} with an error message on failure.
    /// </summary>
    public static Result<TEnum> ToEnum<TEnum>(this byte value, bool allowZeroForFlags = true)
        where TEnum : struct, Enum
    {
        Type t = typeof(TEnum);

        // Enforce underlying type = byte to avoid accidental mis-casts
        if (Enum.GetUnderlyingType(t) != typeof(byte))
            return Result.Failure<TEnum>($"{t.Name} must have underlying type byte");

        TEnum candidate = (TEnum)(object)value;
        bool isFlags = Attribute.IsDefined(t, typeof(FlagsAttribute));

        if (!isFlags)
        {
            // Exact named value required
            return Enum.IsDefined(t, candidate)
                ? Result.Success(candidate)
                : Result.Failure<TEnum>($"0x{value:X2} is not a defined {t.Name}");
        }

        // Flags: ensure only defined bits are set
        ulong mask = Enum.GetValues(t)
            .Cast<object>()
            .Select(Convert.ToUInt64)
            .Aggregate(0UL, (acc, v) => acc | v);

        ulong uv = value;

        if (uv == 0 && !allowZeroForFlags)
            return Result.Failure<TEnum>($"0x00 is not allowed for flags enum {t.Name}");

        return (uv & ~mask) == 0
            ? Result.Success(candidate)
            : Result.Failure<TEnum>($"0x{value:X2} contains undefined flag bits for {t.Name}");
    }

    /// <summary>
    /// Converts a byte to ScpVersion with functional error handling.
    /// </summary>
    public static Result<ScpVersion> ToScpVersion(this byte value) => value.ToEnum<ScpVersion>();

    /// <summary>
    /// Converts an int to ScpVersion with functional error handling.
    /// </summary>
    public static Result<ScpVersion> ToScpVersion(this int value) =>
        value is >= 0 and <= 255
            ? ((byte)value).ToEnum<ScpVersion>()
            : Result.Failure<ScpVersion>($"Value {value} is outside byte range for ScpVersion");

    /// <summary>
    /// Converts ScpVersion to byte.
    /// </summary>
    public static byte ToByte(this ScpVersion version) => (byte)version;
}
