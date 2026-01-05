using System;
using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using NUnit.Framework;

namespace Gp4Net.Tests.Services;

public class KeysetResolverTests
{
    private KeysetResolver _resolver = default!;

    [SetUp]
    public void Setup()
    {
        _resolver = new KeysetResolver();
    }

    [Test]
    public void Should_Resolve_Keyset_By_Name_For_Known_Keysets()
    {
        var result = _resolver.ResolveKeyset(
            "gp_test",
            new Dictionary<string, string>(),
            Maybe<byte[]>.None,
            Maybe<byte[]>.None,
            Maybe<byte[]>.None,
            0x00,
            Maybe<InitializeUpdateResponse>.None
        );

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
    }

    [Test]
    public void Should_Return_Success_For_Unknown_Keyset_Name()
    {
        var result = _resolver.ResolveKeyset(
            "unknown_keyset",
            new Dictionary<string, string>(),
            Maybe<byte[]>.None,
            Maybe<byte[]>.None,
            Maybe<byte[]>.None,
            0x00,
            Maybe<InitializeUpdateResponse>.None
        );

        Assert.That(result.IsSuccess, Is.True);
    }

    [Test]
    public void Should_Resolve_Default_Keyset()
    {
        var result = _resolver.GetTestKeys(0x02, 0x00);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
        Assert.That(result.Value.KeyVersion, Is.EqualTo(0x00));
    }

    [Test]
    public void Should_Resolve_From_Hex_Keys()
    {
        var testKeyHex = "404142434445464748494A4B4C4D4E4F";

        var result = _resolver.ResolveFromHexKeys(testKeyHex, testKeyHex, testKeyHex, 0x00);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
        Assert.That(result.Value.KeyVersion, Is.EqualTo(0x00));
    }

    [Test]
    public void Should_Fail_For_Invalid_Hex_Keys()
    {
        var invalidHex = "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG";

        var result = _resolver.ResolveFromHexKeys(invalidHex, invalidHex, invalidHex, 0x00);

        Assert.That(result.IsFailure, Is.True);
    }

    [Test]
    public void Should_Resolve_SCP02_Test_KeySet()
    {
        var result = _resolver.ResolveScp02KeySet("gp_test", 0x00);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
        Assert.That(result.Value.KeyVersion, Is.EqualTo(0x00));
    }

    [Test]
    public void Should_Resolve_SCP03_Test_KeySet()
    {
        var result = _resolver.ResolveScp03KeySet("gp_test", 0x00);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
        Assert.That(result.Value.KeyVersion, Is.EqualTo(0x00));
    }

    [Test]
    public void Should_Use_Explicit_Keys_When_Provided()
    {
        var testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");

        var result = _resolver.ResolveKeyset(
            "any_name",
            new Dictionary<string, string>(),
            Maybe<byte[]>.From(testKey),
            Maybe<byte[]>.From(testKey),
            Maybe<byte[]>.From(testKey),
            0x00,
            Maybe<InitializeUpdateResponse>.None
        );

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
    }

    [Test]
    public void Should_Fallback_To_Test_Keys_When_No_Explicit_Keys()
    {
        var result = _resolver.ResolveKeyset(
            "any_name",
            new Dictionary<string, string>(),
            Maybe<byte[]>.None,
            Maybe<byte[]>.None,
            Maybe<byte[]>.None,
            0x00,
            Maybe<InitializeUpdateResponse>.None
        );

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
    }

    [Test]
    public void Should_Handle_Different_Key_Versions()
    {
        var versions = new byte[] { 0x00, 0x01, 0x02, 0xFF };

        foreach (var version in versions)
        {
            var result = _resolver.GetTestKeys(0x03, version);

            Assert.That(result.IsSuccess, Is.True, $"Should resolve keys for version {version:X2}");
            Assert.That(result.Value.KeyVersion, Is.EqualTo(version));
        }
    }

    [Test]
    public void Should_Handle_Different_Protocol_Versions()
    {
        var protocols = new byte[] { 0x02, 0x03 };

        foreach (var protocol in protocols)
        {
            var result = _resolver.GetTestKeys(protocol, 0x00);

            Assert.That(
                result.IsSuccess,
                Is.True,
                $"Should resolve keys for protocol {protocol:X2}"
            );
        }
    }
}
