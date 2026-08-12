using System;
using System.Linq;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Pipeline;
using Gp4Net.Tool;
using NUnit.Framework;

namespace Gp4Net.Tests.Architecture;

[TestFixture]
public sealed class FunctionalArchitectureTests
{
    private static readonly string[] LegacyTypeSuffixes =
    [
        "Service",
        "Factory",
        "Manager",
        "Resolver",
    ];

    [Test]
    public void Should_Not_Export_Legacy_Architecture_Type_Names()
    {
        var assemblies = new[]
        {
            typeof(CardSession).Assembly,
            typeof(IVirtualCard).Assembly,
            typeof(Program).Assembly,
        };

        string[] violations =
        [
            .. assemblies
                .SelectMany(assembly => assembly.GetExportedTypes())
                .Where(type => LegacyTypeSuffixes.Any(suffix => type.Name.EndsWith(suffix)))
                .Select(type => type.ToString()),
        ];

        Assert.That(violations, Is.Empty);
    }

    [Test]
    public void Core_Should_Expose_Only_Approved_Polymorphic_Interfaces()
    {
        string[] approved =
        [
            "IApplication",
            "IAppletRuntime",
            "IApduCommand",
            "IApduTransport",
            "ICardChannel",
            "IKeySet",
            "IPreloadedRngContext",
            "IRngContext",
            "IVirtualCard",
        ];

        string[] actual =
        [
            .. new[] { typeof(CardSession).Assembly, typeof(IVirtualCard).Assembly }
                .SelectMany(assembly => assembly.GetExportedTypes())
                .Where(type => type.IsInterface)
                .Select(type => type.Name)
                .Distinct()
                .Order(),
        ];

        Assert.That(actual, Is.EqualTo(approved.Order()));
    }
}
