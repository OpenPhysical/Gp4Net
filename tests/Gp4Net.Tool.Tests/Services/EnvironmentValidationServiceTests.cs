using System;
using System.Linq;
using Gp4Net.Domain.Keys;
using Gp4Net.Tool.Services;
using Gp4Net.Tool.Tests.Support;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.Tool.Tests.Services;

public class EnvironmentValidationServiceTests
{
    private static readonly byte[][] KnownTestKeys =
    [
        Convert.FromHexString(SecurityTestData.LoadGpDefaultKeys().Keys[0].Hex),
        new byte[16],
        Enumerable.Repeat((byte)0xFF, 16).ToArray(),
        Convert.FromHexString("000102030405060708090A0B0C0D0E0F"),
        Convert.FromHexString("DEADBEEFDEADBEEFDEADBEEFDEADBEEF"),
    ];

    private EnvironmentValidationService service = default!;

    [SetUp]
    public void SetUp()
    {
        service = new EnvironmentValidationService(
            NullLogger<EnvironmentValidationService>.Instance
        );
    }

    [Test]
    public void Should_Return_True_For_Known_Test_Key_Patterns()
    {
        foreach (var keyBytes in KnownTestKeys)
        {
            var keySet = CreateKeySet(keyBytes);
            Assert.That(
                service.IsTestKeySet(keySet),
                Is.True,
                "Known test pattern should be detected"
            );
        }
    }

    [Test]
    public void Should_Return_False_For_Production_Like_Keys()
    {
        var productionKey = Enumerable.Range(0, 16).Select(i => (byte)(0x80 + i)).ToArray();
        var keySet = CreateKeySet(productionKey);

        var result = service.IsTestKeySet(keySet);

        Assert.That(result, Is.False);
    }

    [Test]
    public void Should_Return_True_For_All_Zeros_Key()
    {
        var keyBytes = new byte[16];
        var keySet = CreateKeySet(keyBytes);

        var result = service.IsTestKeySet(keySet);

        Assert.That(result, Is.True);
    }

    [Test]
    public void Should_Return_True_For_All_FFs_Key()
    {
        var keyBytes = Enumerable.Repeat((byte)0xFF, 16).ToArray();
        var keySet = CreateKeySet(keyBytes);

        var result = service.IsTestKeySet(keySet);

        Assert.That(result, Is.True);
    }

    [Test]
    public void Should_Throw_When_KeySet_Is_Null()
    {
        Assert.That(() => service.IsTestKeySet(null!), Throws.TypeOf<ArgumentNullException>());
    }

    private static IKeySet CreateKeySet(byte[] key)
    {
        var result = Scp03KeySet.Create(key, key, key, 0x00);
        return result.Value;
    }
}
