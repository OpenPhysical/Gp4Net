using System;
using System.Linq;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using NUnit.Framework;

namespace Gp4Net.Tests.Unit.Security;

[TestFixture]
[Category("Unit")]
[Category("Security")]
public class KeyDiversificationServiceTests
{
    private static readonly byte[] TestKey = Convert.FromHexString(
        "404142434445464748494A4B4C4D4E4F"
    );

    [Test]
    public void DiversifyScp03KeySet_WithKdf3_ShouldProduceExpectedKeyChecksums()
    {
        var baseKeyResult = Scp03KeySet.Create(TestKey, TestKey, TestKey, 0x01);
        Assert.That(baseKeyResult.IsSuccess, Is.True);
        var baseKeySet = baseKeyResult.Value;

        var specResult = KeyDiversificationService.CreateSpec("kdf3");
        Assert.That(specResult.IsSuccess, Is.True);
        var spec = specResult.Value;

        byte[] kdd = Enumerable.Range(0, 10).Select(i => (byte)i).ToArray();

        var diversifiedResult = KeyDiversificationService.DiversifyScp03KeySet(
            baseKeySet,
            spec,
            kdd
        );
        Assert.That(
            diversifiedResult.IsSuccess,
            Is.True,
            diversifiedResult.IsFailure ? diversifiedResult.Error.Message : string.Empty
        );

        var diversified = diversifiedResult.Value;
        AssertKcv(diversified.EncKey, "E79C05");
        AssertKcv(diversified.MacKey, "D1BD77");
        AssertKcv(diversified.DekKey, "3FDE8C");
    }

    [Test]
    public void CreateSpec_ShouldNormalizeScp03AliasesToCanonicalName()
    {
        var aliases = new[] { "kdf3", "scp03", "SCP03-Default", "key-derivation-function-3", };

        foreach (var alias in aliases)
        {
            var result = KeyDiversificationService.CreateSpec(alias);
            Assert.That(
                result.IsSuccess,
                Is.True,
                result.IsFailure ? result.Error.Message : string.Empty
            );
            Assert.That(result.Value.Scheme, Is.EqualTo("scp03"));
        }
    }

    private static void AssertKcv(byte[] key, string expectedHexKcv)
    {
        var expected = Convert.FromHexString(expectedHexKcv);
        var actual = ComputeAesKcv(key);
        Assert.That(actual, Is.EqualTo(expected));
    }

    private static byte[] ComputeAesKcv(byte[] key)
    {
        var input = Enumerable.Repeat((byte)0x01, 16).ToArray();
        var iv = new byte[16];

        var encryptResult = CryptoService.Cipher.EncryptAesCbc(key, iv, input);

        Assert.That(
            encryptResult.IsSuccess,
            Is.True,
            encryptResult.IsFailure
                ? $"KCV calculation failed: {encryptResult.Error.Message}"
                : string.Empty
        );

        return encryptResult.Value.Take(3).ToArray();
    }
}
