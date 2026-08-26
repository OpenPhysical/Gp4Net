using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using CSharpFunctionalExtensions;

namespace Gp4Net.Tool.Common;

internal sealed class MaybeJsonConverterFactory : JsonConverterFactory
{
    public override bool CanConvert(Type typeToConvert) =>
        typeToConvert.IsGenericType
        && typeToConvert.GetGenericTypeDefinition() == typeof(Maybe<>);

    public override JsonConverter CreateConverter(
        Type typeToConvert,
        JsonSerializerOptions options
    ) =>
        (JsonConverter)
            Activator.CreateInstance(
                typeof(MaybeJsonConverter<>).MakeGenericType(typeToConvert.GetGenericArguments()[0])
            )!;

    private sealed class MaybeJsonConverter<T> : JsonConverter<Maybe<T>>
    {
        public override Maybe<T> Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options
        ) => throw new NotSupportedException("Maybe JSON deserialization is not supported");

        public override void Write(
            Utf8JsonWriter writer,
            Maybe<T> value,
            JsonSerializerOptions options
        )
        {
            if (!value.HasValue)
            {
                writer.WriteNullValue();
                return;
            }

            JsonSerializer.Serialize(writer, value.Value, options);
        }
    }
}
