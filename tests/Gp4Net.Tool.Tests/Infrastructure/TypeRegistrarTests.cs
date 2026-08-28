using System;
using Gp4Net.Tool.Infrastructure;
using NUnit.Framework;

namespace Gp4Net.Tool.Tests.Infrastructure;

public class TypeRegistrarTests
{
    [Test]
    public void Register_SameServiceAndImplementation_DoesNotRecurse()
    {
        var registrar = new TypeRegistrar();
        registrar.Register(typeof(SelfRegistered), typeof(SelfRegistered));
        var resolver = registrar.Build();

        Assert.That(resolver.Resolve(typeof(SelfRegistered)), Is.TypeOf<SelfRegistered>());
    }

    public sealed class SelfRegistered;
}
