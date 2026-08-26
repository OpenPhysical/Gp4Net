using System.Text.Json;
using CSharpFunctionalExtensions;
using Gp4Net.Tool.Common;
using NUnit.Framework;

namespace Gp4Net.Tool.Tests.Common;

public class MaybeJsonConverterFactoryTests
{
    [Test]
    public void EmptyMaybeSerializesAsNullWithoutReadingValue()
    {
        var options = new JsonSerializerOptions();
        options.Converters.Add(new MaybeJsonConverterFactory());

        string json = JsonSerializer.Serialize(Maybe<string>.None, options);

        Assert.That(json, Is.EqualTo("null"));
    }

    [Test]
    public void PopulatedMaybeSerializesItsValue()
    {
        var options = new JsonSerializerOptions();
        options.Converters.Add(new MaybeJsonConverterFactory());

        string json = JsonSerializer.Serialize(Maybe<string>.From("value"), options);

        Assert.That(json, Is.EqualTo("\"value\""));
    }
}
