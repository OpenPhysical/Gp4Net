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
        InitializeUpdateResponse cardResponse = CreateInitializeUpdateResponse(0x02);
        var result = _resolver.ResolveKeyset(
            "gp_test",
            new Dictionary<string, string>(),
            Maybe<byte[]>.None,
            Maybe<byte[]>.None,
            Maybe<byte[]>.None,
            0x00,
            Maybe<InitializeUpdateResponse>.From(cardResponse)
        );

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
    }

    [Test]
    // GP Card Specification v2.3.1, Section 7.5.1: the off-card system must know the
    // Security Domain's key-identification scheme.
    public void Should_Fail_For_Unknown_Keyset_Name()
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

        Assert.That(result.IsFailure, Is.True);
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
    // SCP03 Amendment D v1.1.2, Section 4.1, defines the AES Secure Channel base keys.
    public void Should_Create_Scp03_Keyset_When_Card_Reports_Scp03()
    {
        var testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        InitializeUpdateResponse cardResponse = CreateInitializeUpdateResponse(0x03);

        var result = _resolver.ResolveKeyset(
            "any_name",
            new Dictionary<string, string>(),
            Maybe<byte[]>.From(testKey),
            Maybe<byte[]>.From(testKey),
            Maybe<byte[]>.From(testKey),
            0x00,
            Maybe<InitializeUpdateResponse>.From(cardResponse)
        );

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.TypeOf<Scp03KeySet>());
    }

    [Test]
    public void Should_Require_Initialize_Update_Response_When_No_Explicit_Keys()
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

        Assert.That(result.IsFailure, Is.True);
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

    [Test]
    public void Should_Fail_For_Unsupported_Protocol_Instead_Of_Assuming_Scp02()
    {
        var result = _resolver.GetTestKeys(0x04, 0x00);

        Assert.That(result.IsFailure, Is.True);
    }

    [Test]
    public void Should_Require_All_Explicit_Key_Components()
    {
        var testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");

        var result = _resolver.ResolveKeyset(
            "gp_test",
            new Dictionary<string, string>(),
            Maybe<byte[]>.From(testKey),
            Maybe<byte[]>.None,
            Maybe<byte[]>.None,
            0x00,
            Maybe<InitializeUpdateResponse>.From(CreateInitializeUpdateResponse(0x02))
        );

        Assert.That(result.IsFailure, Is.True);
    }

    private static InitializeUpdateResponse CreateInitializeUpdateResponse(byte scpId)
    {
        int sequenceCounterLength = scpId == 0x02 ? 2 : 3;
        int cardChallengeLength = scpId == 0x02 ? 6 : 8;
        return InitializeUpdateResponse
            .Create(
                new byte[10],
                0x00,
                scpId,
                new byte[sequenceCounterLength],
                new byte[cardChallengeLength],
                new byte[8]
            )
            .Value;
    }
}
