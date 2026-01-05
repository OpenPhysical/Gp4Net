using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Gp4Net.Tool.Common;

/// <summary>
/// JSON converter for byte arrays that serializes them as hexadecimal strings.
/// Follows functional programming principles with immutable conversions.
/// </summary>
public sealed class ByteArrayHexConverter : JsonConverter<byte[]>
{
    /// <summary>
    /// Reads a hexadecimal string and converts it to a byte array.
    /// </summary>
    public override byte[] Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options
    )
    {
        var hexString = reader.GetString();
        return hexString is null ? Array.Empty<byte>() : Convert.FromHexString(hexString);
    }

    /// <summary>
    /// Writes a byte array as a hexadecimal string.
    /// </summary>
    public override void Write(Utf8JsonWriter writer, byte[] value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(Convert.ToHexString(value));
    }
}
