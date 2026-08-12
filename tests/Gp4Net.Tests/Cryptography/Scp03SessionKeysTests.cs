using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using NUnit.Framework;

namespace Gp4Net.Tests.Cryptography;

[TestFixture]
public class Scp03SessionKeysTests
{
    // Test data from actual trace log at tests/Gp4Net.Tests/TestData/Traces/Raw/gp_pro_p71_scp03.txt
    private static readonly byte[] MasterKey = Convert.FromHexString(
        "404142434445464748494A4B4C4D4E4F"
    );

    // From line 88-89 of trace
    private static readonly byte[] HostChallenge = Convert.FromHexString("FE0530CF61BAA9F3");
    private static readonly byte[] CardChallenge = Convert.FromHexString("83FA042C5C10F778");

    // From line 92 - Expected session keys
    private static readonly byte[] ExpectedEncKey = Convert.FromHexString(
        "7392646744DF8721131C4A995A845BAE"
    );
    private static readonly byte[] ExpectedMacKey = Convert.FromHexString(
        "CD9F750E543E0CF862B0EA73E3812113"
    );
    private static readonly byte[] ExpectedRmacKey = Convert.FromHexString(
        "D1B695D89DE01992B6CB238BDFB006D9"
    );

    [Test]
    public void Should_Derive_Scp03_Session_Keys_With_Implementation_Parameter_70()
    {
        // i=70 from trace line 90
        var keySetResult = Scp03KeySet.Create(MasterKey, MasterKey, MasterKey, 0x01);
        Assert.That(keySetResult.IsSuccess, Is.True, "Failed to create key set");
        var keySet = keySetResult.Value;

        var contextResult = KeyDerivationContext.CreateForScp03(
            keySet,
            HostChallenge,
            CardChallenge,
            Maybe<ScpImplementation>.From(ScpImplementation.Scp03I70)
        );
        Assert.That(contextResult.IsSuccess, Is.True, "Failed to create context");
        var context = contextResult.Value;

        var sessionKeysResult = CryptoService.KeyDerivation.DeriveSessionKeys(context);

        Assert.That(sessionKeysResult.IsSuccess, Is.True, "Failed to derive session keys");
        var sessionKeys = sessionKeysResult.Value;

        Assert.That(sessionKeys.SEnc, Is.EqualTo(ExpectedEncKey), "ENC key mismatch");
        Assert.That(sessionKeys.SMac, Is.EqualTo(ExpectedMacKey), "MAC key mismatch");
        Assert.That(sessionKeys.SrMac, Is.EqualTo(ExpectedRmacKey), "RMAC key mismatch");
    }

    [Test]
    public void Should_Derive_Session_Keys_From_Trace_Data()
    {
        var keySetResult = Scp03KeySet.Create(MasterKey, MasterKey, MasterKey, 0x01);
        Assert.That(keySetResult.IsSuccess, Is.True);
        var keySet = keySetResult.Value;

        var hostChallenge = Convert.FromHexString("A51709B085AF91C1");
        var cardChallenge = Convert.FromHexString("BE906A81C79CAF17");

        var context = KeyDerivationContext
            .CreateForScp03(
                keySet,
                hostChallenge,
                cardChallenge,
                Maybe<ScpImplementation>.From(ScpImplementation.Scp03I70)
            )
            .Value;

        var sessionKeys = CryptoService.KeyDerivation.DeriveSessionKeys(context).Value;

        Assert.That(
            sessionKeys.SEnc,
            Is.EqualTo(Convert.FromHexString("3B4E4997DA4232822E926D0AA69BFEBA"))
        );
        Assert.That(
            sessionKeys.SMac,
            Is.EqualTo(Convert.FromHexString("C4404EF2866673415B2125C821DD7C66"))
        );
        Assert.That(
            sessionKeys.SrMac,
            Is.EqualTo(Convert.FromHexString("F1682C3D8819D48C924010546C1E23B9"))
        );
    }

    [Test]
    public void ImplementationParameter_DoesNotAffectDerivation_WhenChallengesMatch()
    {
        var keySetResult = Scp03KeySet.Create(MasterKey, MasterKey, MasterKey, 0x01);
        Assert.That(keySetResult.IsSuccess, Is.True);
        var keySet = keySetResult.Value;

        var contextDefault = KeyDerivationContext
            .CreateForScp03(
                keySet,
                HostChallenge,
                CardChallenge,
                Maybe<ScpImplementation>.From(ScpImplementation.Scp03I10)
            )
            .Value;

        var contextPseudoRandom = KeyDerivationContext
            .CreateForScp03(
                keySet,
                HostChallenge,
                CardChallenge,
                Maybe<ScpImplementation>.From(ScpImplementation.Scp03I70)
            )
            .Value;

        var keysDefault = CryptoService.KeyDerivation.DeriveSessionKeys(contextDefault).Value;
        var keysPseudoRandom = CryptoService
            .KeyDerivation.DeriveSessionKeys(contextPseudoRandom)
            .Value;

        Assert.That(keysDefault.SEnc, Is.EqualTo(keysPseudoRandom.SEnc));
        Assert.That(keysDefault.SMac, Is.EqualTo(keysPseudoRandom.SMac));
        Assert.That(keysDefault.SrMac, Is.EqualTo(keysPseudoRandom.SrMac));
    }

    [Test]
    public void Should_Support_Different_Key_Lengths()
    {
        // Test AES-128 (16 bytes)
        var aes128Key = MasterKey; // 16 bytes
        var keySet128Result = Scp03KeySet.Create(aes128Key, aes128Key, aes128Key, 0x01);
        Assert.That(keySet128Result.IsSuccess, Is.True, "AES-128 key set creation should succeed");
        var keySet128 = keySet128Result.Value;

        // Test AES-192 (24 bytes)
        var aes192Key = Convert.FromHexString("404142434445464748494A4B4C4D4E4F5051525354555657");
        var keySet192Result = Scp03KeySet.Create(aes192Key, aes192Key, aes192Key, 0x01);
        Assert.That(keySet192Result.IsSuccess, Is.True, "AES-192 key set creation should succeed");
        var keySet192 = keySet192Result.Value;

        // Test AES-256 (32 bytes)
        var aes256Key = Convert.FromHexString(
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
        );
        var keySet256Result = Scp03KeySet.Create(aes256Key, aes256Key, aes256Key, 0x01);
        Assert.That(keySet256Result.IsSuccess, Is.True, "AES-256 key set creation should succeed");
        var keySet256 = keySet256Result.Value;

        // Derive session keys with AES-128
        var context128Result = KeyDerivationContext.CreateForScp03(
            keySet128,
            HostChallenge,
            CardChallenge,
            Maybe<ScpImplementation>.From(ScpImplementation.Scp03I70)
        );
        Assert.That(context128Result.IsSuccess, Is.True, "Failed to create context for AES-128");
        var session128Result = CryptoService.KeyDerivation.DeriveSessionKeys(
            context128Result.Value
        );
        Assert.That(
            session128Result.IsSuccess,
            Is.True,
            "Session key derivation should succeed for AES-128"
        );

        // Derive session keys with AES-192
        var context192Result = KeyDerivationContext.CreateForScp03(
            keySet192,
            HostChallenge,
            CardChallenge,
            Maybe<ScpImplementation>.From(ScpImplementation.Scp03I70)
        );
        Assert.That(context192Result.IsSuccess, Is.True, "Failed to create context for AES-192");
        var session192Result = CryptoService.KeyDerivation.DeriveSessionKeys(
            context192Result.Value
        );
        Assert.That(
            session192Result.IsSuccess,
            Is.True,
            "Session key derivation should succeed for AES-192"
        );

        // Derive session keys with AES-256
        var context256Result = KeyDerivationContext.CreateForScp03(
            keySet256,
            HostChallenge,
            CardChallenge,
            Maybe<ScpImplementation>.From(ScpImplementation.Scp03I70)
        );
        Assert.That(context256Result.IsSuccess, Is.True, "Failed to create context for AES-256");
        var session256Result = CryptoService.KeyDerivation.DeriveSessionKeys(
            context256Result.Value
        );
        Assert.That(
            session256Result.IsSuccess,
            Is.True,
            "Session key derivation should succeed for AES-256"
        );
    }

    [Test]
    public void Should_Fail_With_Invalid_Key_Lengths()
    {
        // Test with invalid key length (not 16, 24, or 32 bytes)
        var invalidKey = Convert.FromHexString("404142434445464748494A4B4C4D"); // 14 bytes
        var keySetResult = Scp03KeySet.Create(invalidKey, MasterKey, MasterKey, 0x01);

        Assert.That(keySetResult.IsFailure, Is.True, "Should reject invalid key length");
        // Error message mentions key length in "...must be 16, 24, or 32 bytes, got 14 bytes"
        Assert.That(
            keySetResult.Error.ToString(),
            Does.Contain("bytes"),
            "Error should mention key length issue"
        );
    }

    [Test]
    public void Should_Produce_Consistent_Results_For_Same_Inputs()
    {
        var keySetResult = Scp03KeySet.Create(MasterKey, MasterKey, MasterKey, 0x01);
        Assert.That(keySetResult.IsSuccess, Is.True);
        var keySet = keySetResult.Value;

        // Derive keys multiple times with same inputs
        var contextResult = KeyDerivationContext.CreateForScp03(
            keySet,
            HostChallenge,
            CardChallenge,
            Maybe<ScpImplementation>.From(ScpImplementation.Scp03I70)
        );
        Assert.That(contextResult.IsSuccess, Is.True, "Failed to create context");
        var context = contextResult.Value;

        var result1 = CryptoService.KeyDerivation.DeriveSessionKeys(context);
        Assert.That(result1.IsSuccess, Is.True, "First derivation should succeed");
        var keys1 = result1.Value;

        // SCP03 1.1.2, 6.1 and 6.2.8: key-sensitive data uses static Key-DEK;
        // SCP03 does not derive an S-DEK from the per-session challenges.
        Assert.That(keys1.Dek.HasValue, Is.True);
        Assert.That(keys1.Dek.Value, Is.EqualTo(keySet.DekKey));

        var result2 = CryptoService.KeyDerivation.DeriveSessionKeys(context);
        Assert.That(result2.IsSuccess, Is.True, "Second derivation should succeed");
        var keys2 = result2.Value;

        var result3 = CryptoService.KeyDerivation.DeriveSessionKeys(context);
        Assert.That(result3.IsSuccess, Is.True, "Third derivation should succeed");
        var keys3 = result3.Value;

        // Verify all results are identical
        Assert.That(keys2.SEnc, Is.EqualTo(keys1.SEnc), "Run 2 ENC key should match first run");
        Assert.That(keys2.SMac, Is.EqualTo(keys1.SMac), "Run 2 MAC key should match first run");
        Assert.That(keys2.SrMac, Is.EqualTo(keys1.SrMac), "Run 2 RMAC key should match first run");

        Assert.That(keys3.SEnc, Is.EqualTo(keys1.SEnc), "Run 3 ENC key should match first run");
        Assert.That(keys3.SMac, Is.EqualTo(keys1.SMac), "Run 3 MAC key should match first run");
        Assert.That(keys3.SrMac, Is.EqualTo(keys1.SrMac), "Run 3 RMAC key should match first run");
    }

    [Test]
    public void Should_Derive_The_Same_Keys_For_Random_And_Pseudo_Random_Modes()
    {
        // SCP03 Amendment D v1.1.2, Table 5-1: i=60 is random and i=70 is pseudo-random.
        var keySetResult = Scp03KeySet.Create(MasterKey, MasterKey, MasterKey, 0x01);
        Assert.That(keySetResult.IsSuccess, Is.True);
        var keySet = keySetResult.Value;

        var context60Result = KeyDerivationContext.CreateForScp03(
            keySet,
            HostChallenge,
            CardChallenge,
            Maybe<ScpImplementation>.From(ScpImplementation.Scp03I60)
        );
        Assert.That(context60Result.IsSuccess, Is.True, "Failed to create context for i=60");
        var sessionKeys60Result = CryptoService.KeyDerivation.DeriveSessionKeys(
            context60Result.Value
        );
        Assert.That(sessionKeys60Result.IsSuccess, Is.True, "i=60 should be supported");
        var sessionKeys60 = sessionKeys60Result.Value;

        var context70Result = KeyDerivationContext.CreateForScp03(
            keySet,
            HostChallenge,
            CardChallenge,
            Maybe<ScpImplementation>.From(ScpImplementation.Scp03I70)
        );
        Assert.That(context70Result.IsSuccess, Is.True, "Failed to create context for i=70");
        var sessionKeys70Result = CryptoService.KeyDerivation.DeriveSessionKeys(
            context70Result.Value
        );
        Assert.That(sessionKeys70Result.IsSuccess, Is.True, "i=70 should be supported");
        var sessionKeys70 = sessionKeys70Result.Value;

        Assert.That(sessionKeys60.SEnc, Is.EqualTo(sessionKeys70.SEnc));
        Assert.That(sessionKeys60.SMac, Is.EqualTo(sessionKeys70.SMac));
        Assert.That(sessionKeys60.SrMac, Is.EqualTo(sessionKeys70.SrMac));
    }
}
