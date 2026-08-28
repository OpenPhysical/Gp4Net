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

        var specResult = KeyDiversification.CreateSpec("kdf3");
        Assert.That(specResult.IsSuccess, Is.True);
        var spec = specResult.Value;

        byte[] kdd = Enumerable.Range(0, 10).Select(i => (byte)i).ToArray();

        var diversifiedResult = KeyDiversification.DiversifyScp03KeySet(baseKeySet, spec, kdd);
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
    public void DiversifyScp02KeySet_WithVisa2_ShouldProduceCapturedKeys()
    {
        var baseKeyResult = Scp02KeySet.Create(TestKey, TestKey, TestKey, 0x01, 0x01);
        Assert.That(baseKeyResult.IsSuccess, Is.True);
        var specResult = KeyDiversification.CreateSpec("visa2");
        Assert.That(specResult.IsSuccess, Is.True);

        var result = KeyDiversification.DiversifyScp02KeySet(
            baseKeyResult.Value,
            specResult.Value,
            Convert.FromHexString("00112233445566778899")
        );

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value.KeyVersion, Is.EqualTo(0x01));
        Assert.That(result.Value.KeyId, Is.EqualTo(0x01));
        Assert.That(
            Convert.ToHexString(result.Value.EncKey),
            Is.EqualTo("456CEAAF837C2D932162DA9C4D68E956")
        );
        Assert.That(
            Convert.ToHexString(result.Value.MacKey),
            Is.EqualTo("6CC1D686816C069843B9DA63F58B5BA6")
        );
        Assert.That(
            Convert.ToHexString(result.Value.DekKey),
            Is.EqualTo("AA15435D35CF69D09A65DC2B6F63D76A")
        );
    }

    [Test]
    public void CreateSpec_ShouldNormalizeScp03AliasesToCanonicalName()
    {
        var aliases = new[] { "kdf3", "scp03", "SCP03-Default", "key-derivation-function-3", };

        foreach (var alias in aliases)
        {
            var result = KeyDiversification.CreateSpec(alias);
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

        var encryptResult = CryptoOperations.Cipher.EncryptAesCbc(key, iv, input);

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
