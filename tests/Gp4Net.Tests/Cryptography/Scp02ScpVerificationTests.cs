using System;
using System.Linq;
using Gp4Net.Constants;
using Gp4Net.Cryptography;
using NUnit.Framework;

namespace Gp4Net.Tests.Cryptography;

/// <summary>
/// SCP02 tests that verify our implementation matches the ScpVerification reference implementation exactly.
/// These tests use the same test vectors and should produce identical results.
/// </summary>
[TestFixture]
public class Scp02ScpVerificationTests
{
    [Test]
    public void Test_SCP02_Key_Derivation_Matches_ScpVerification()
    {
        // Test vectors from ScpVerification/Scp02IntegrationTests.cs
        var masterKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var sequenceCounter = Convert.FromHexString("0013");

        // Derive session keys
        var encKeyResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
            masterKey,
            sequenceCounter,
            Constants.Constants.Scp.Scp02.KeyDerivationConstants.SEnc
        );
        var macKeyResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
            masterKey,
            sequenceCounter,
            Constants.Constants.Scp.Scp02.KeyDerivationConstants.SMac
        );
        var rmacKeyResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
            masterKey,
            sequenceCounter,
            Constants.Constants.Scp.Scp02.KeyDerivationConstants.SrMac
        );
        var dekKeyResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
            masterKey,
            sequenceCounter,
            Constants.Constants.Scp.Scp02.KeyDerivationConstants.SDek
        );

        // Expected keys from ScpVerification test output with sequence counter 0013
        var expectedEncKey = Convert.FromHexString("E94829A5FD577FB1512772AC2DD27024");
        var expectedMacKey = Convert.FromHexString("A4C596637EBC545276CDDFB75194B01C");
        var expectedRmacKey = Convert.FromHexString("94EAE1F3661F5D308A7FE41BB45FBE67");
        var expectedDekKey = Convert.FromHexString("0B54004FB7A503931A0B3F77EDF962C4");

        Assert.Multiple(() =>
        {
            Assert.That(encKeyResult.IsSuccess, Is.True);
            Assert.That(macKeyResult.IsSuccess, Is.True);
            Assert.That(rmacKeyResult.IsSuccess, Is.True);
            Assert.That(dekKeyResult.IsSuccess, Is.True);
        });

        Assert.Multiple(() =>
        {
            Assert.That(encKeyResult.Value, Is.EqualTo(expectedEncKey), "S-ENC key mismatch");
            Assert.That(macKeyResult.Value, Is.EqualTo(expectedMacKey), "S-MAC key mismatch");
            Assert.That(rmacKeyResult.Value, Is.EqualTo(expectedRmacKey), "S-RMAC key mismatch");
            Assert.That(dekKeyResult.Value, Is.EqualTo(expectedDekKey), "S-DEK key mismatch");
        });
    }

    [Test]
    public void Test_SCP02_Cryptogram_Matches_ScpVerification()
    {
        // Test data from actual trace: response 0000234555808320483901020013884AB6A84A1819A72830637708FB
        var sEncKey = Convert.FromHexString("E94829A5FD577FB1512772AC2DD27024");
        var hostChallenge = Convert.FromHexString("CE410ED7FACD71A1");
        var sequenceCounter = Convert.FromHexString("0013");
        var cardChallenge = Convert.FromHexString("884AB6A84A18");
        var expectedCardCryptogram = Convert.FromHexString("19A72830637708FB");

        // Build the card cryptogram data: hostChallenge || sequenceCounter || cardChallenge
        var cryptogramData = hostChallenge.Concat(sequenceCounter).Concat(cardChallenge).ToArray();

        // Calculate cryptogram - padding is handled internally
        var result = CryptoService.Cryptogram.CalculateScp02Cryptogram(sEncKey, cryptogramData);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.EqualTo(expectedCardCryptogram), "Card cryptogram mismatch");
    }

    [Test]
    public void Test_SCP02_MAC_Calculation_Matches_ScpVerification()
    {
        // Test data from actual trace with corrected S-MAC key
        var sMacKey = Convert.FromHexString("A4C596637EBC545276CDDFB75194B01C");
        var hostCryptogram = Convert.FromHexString("E214362A48999E2A");
        var externalAuthCommand = new byte[] { 0x84, 0x82, 0x03, 0x00, 0x10 };
        var macInput = externalAuthCommand.Concat(hostCryptogram).ToArray();
        var icv = new byte[8]; // Zero ICV for first command
        var expectedMac = Convert.FromHexString("D0C159C17E6D3F9A");

        // Calculate MAC
        var result = CryptoService.Mac.CalculateScp02CommandMac(sMacKey, macInput, icv);

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.EqualTo(expectedMac), "MAC mismatch");
    }

    [Test]
    public void Test_SCP02_ICV_Chaining_Matches_ScpVerification()
    {
        // Test ICV encryption for chaining
        var sMacKey = Convert.FromHexString("A4C596637EBC545276CDDFB75194B01C");
        var previousMac = Convert.FromHexString("D0C159C17E6D3F9A");

        // Encrypt the previous MAC to get the next ICV
        var encryptedIcvResult = CryptoService.Mac.EncryptScp02Icv(previousMac, sMacKey);
        Assert.That(encryptedIcvResult.IsSuccess, Is.True);

        // Expected encrypted ICV from ScpVerification
        var expectedEncryptedIcv = Convert.FromHexString("13A84162D6CF3D3E");
        Assert.That(encryptedIcvResult.Value, Is.EqualTo(expectedEncryptedIcv), "Encrypted ICV mismatch");

        // Test next command MAC with chained ICV
        var nextCommand = new byte[] { 0x84, 0xF2, 0x80, 0x02, 0x0A, 0x4F, 0x00 };
        var nextMacResult = CryptoService.Mac.CalculateScp02CommandMac(
            sMacKey,
            nextCommand,
            encryptedIcvResult.Value
        );

        Assert.That(nextMacResult.IsSuccess, Is.True);
        var expectedNextMac = Convert.FromHexString("B2037DBFF3A4A091");
        Assert.That(nextMacResult.Value, Is.EqualTo(expectedNextMac), "Chained MAC mismatch");
    }
}