using System;
using System.Linq;
using Gp4Net.Cryptography;
using NUnit.Framework;

namespace Gp4Net.Tests.Cryptography;

/// <summary>
/// SCP02 integration tests based on proven implementation from ScpVerification.
/// Tests the complete SCP02 flow including key derivation, cryptogram calculation, and MAC generation.
/// </summary>
[TestFixture]
public class Scp02IntegrationTests
{
    [Flags]
    enum SecurityLevel : byte
    {
        NoSecurityLevel = 0x00,
        CMac = 0x01,
        CDecryption = 0x02,
        RMac = 0x10,
        Authenticated = 0x80,
    }

    [Test]
    public void Test_Complete_SCP02_Flow_With_Real_Trace_Data()
    {
        // Test data from actual SCP02 trace (gp_pro_scp02_enc.log)
        const byte globalPlatformCommand = 0x80;
        const byte secureMessagingGlobalPlatformPropreitary = 0x04;
        const byte insExternalAuthenticate = 0x82;
        const byte channelNumberMask = 0xFC;

        // Initial ICVs are 8 bytes of zeros
        var macIcv = new byte[8];
        var encIcv = new byte[8];

        // GP Test Keys
        var masterKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");

        // Host challenge from trace
        var hostChallengeHex = "CE410ED7FACD71A1";
        var hostChallengeBytes = Convert.FromHexString(hostChallengeHex);

        // INITIALIZE UPDATE command APDU
        var hostChallengeApduHex = ("80 50 0000 08 " + hostChallengeHex + "00").Replace(" ", "");
        var hostChallengeApdu = Convert.FromHexString(hostChallengeApduHex);
        Assert.That(
            hostChallengeApdu,
            Is.EqualTo(Convert.FromHexString("8050000008CE410ED7FACD71A100"))
        );

        // Card response from trace (line 24 of gp_pro_scp02_enc.log)
        var cardResponseHex = (
            "0000234555808320483901020013884AB6A84A1819A72830637708FB 9000"
        ).Replace(" ", "");
        var cardResponseBytes = Convert.FromHexString(cardResponseHex);
        Assert.That(cardResponseBytes.Length, Is.EqualTo(30));

        // Parse card response per GP Card Specification
        var diversificationData = cardResponseBytes[..10];
        var keyVersionNumber = cardResponseBytes[10..11];
        var scpVersion = cardResponseBytes[11..12];
        var sequenceCounter = cardResponseBytes[12..14];
        var cardChallengeOnly = cardResponseBytes[14..20]; // 6 bytes card challenge
        var cardCryptogram = cardResponseBytes[20..28];

        TestContext.Out.WriteLine(
            "Diversification Data: " + Convert.ToHexString(diversificationData)
        );
        TestContext.Out.WriteLine("Key Version: " + Convert.ToHexString(keyVersionNumber));
        TestContext.Out.WriteLine("SCP Version: " + Convert.ToHexString(scpVersion));
        TestContext.Out.WriteLine("Sequence Counter: " + Convert.ToHexString(sequenceCounter));
        TestContext.Out.WriteLine("Card Challenge: " + Convert.ToHexString(cardChallengeOnly));
        TestContext.Out.WriteLine("Card Cryptogram: " + Convert.ToHexString(cardCryptogram));

        // Test SCP02 key derivation using Gp4Net implementation
        var encKeyResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
            masterKey,
            sequenceCounter,
            Constants.Constants.Scp.Scp02.KeyDerivationConstants.SEnc
        );
        Assert.That(encKeyResult.IsSuccess, Is.True, "ENC key derivation failed");
        var encKey = encKeyResult.Value;

        var cmacKeyResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
            masterKey,
            sequenceCounter,
            Constants.Constants.Scp.Scp02.KeyDerivationConstants.SMac
        );
        Assert.That(cmacKeyResult.IsSuccess, Is.True, "MAC key derivation failed");
        var cmacKey = cmacKeyResult.Value;

        var rmacKeyResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
            masterKey,
            sequenceCounter,
            Constants.Constants.Scp.Scp02.KeyDerivationConstants.SrMac
        );
        Assert.That(rmacKeyResult.IsSuccess, Is.True, "RMAC key derivation failed");
        var rmacKey = rmacKeyResult.Value;

        var dekKeyResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
            masterKey,
            sequenceCounter,
            Constants.Constants.Scp.Scp02.KeyDerivationConstants.SDek
        );
        Assert.That(dekKeyResult.IsSuccess, Is.True, "DEK key derivation failed");
        var dekKey = dekKeyResult.Value;

        // Expected derived keys using correct SCP02 derivation (matching ScpVerification)
        var expectedEncKey = Convert.FromHexString("E94829A5FD577FB1512772AC2DD27024");
        var expectedCmacKey = Convert.FromHexString("A4C596637EBC545276CDDFB75194B01C");
        var expectedRmacKey = Convert.FromHexString("94EAE1F3661F5D308A7FE41BB45FBE67");
        var expectedDekKey = Convert.FromHexString("0B54004FB7A503931A0B3F77EDF962C4");

        TestContext.Out.WriteLine("S-ENC Key: " + Convert.ToHexString(encKey));
        TestContext.Out.WriteLine("S-CMAC Key: " + Convert.ToHexString(cmacKey));
        TestContext.Out.WriteLine("S-RMAC Key: " + Convert.ToHexString(rmacKey));
        TestContext.Out.WriteLine("S-DEK Key: " + Convert.ToHexString(dekKey));

        Assert.Multiple(() =>
        {
            Assert.That(encKey, Is.EqualTo(expectedEncKey), "S-ENC key mismatch");
            Assert.That(cmacKey, Is.EqualTo(expectedCmacKey), "S-CMAC key mismatch");
            Assert.That(rmacKey, Is.EqualTo(expectedRmacKey), "S-RMAC key mismatch");
            Assert.That(dekKey, Is.EqualTo(expectedDekKey), "S-DEK key mismatch");
        });

        // Test card cryptogram calculation
        // Per GP specification: host challenge || sequence counter || card challenge
        var cardCryptogramData = hostChallengeBytes
            .Concat(sequenceCounter)
            .Concat(cardChallengeOnly)
            .ToArray();

        // The CalculateScp02Cryptogram method uses PaddedBufferedBlockCipher which handles padding
        // So we pass the unpadded data directly (matching ScpVerification approach)
        var cardCryptogramResult = CryptoService.Cryptogram.CalculateScp02Cryptogram(
            encKey, // Use S-ENC session key for cryptogram
            cardCryptogramData // Pass unpadded data - cipher will handle padding
        );
        Assert.That(cardCryptogramResult.IsSuccess, Is.True, "Card cryptogram calculation failed");
        var calculatedCardCryptogram = cardCryptogramResult.Value;

        TestContext.Out.WriteLine(
            "Calculated Card Cryptogram: " + Convert.ToHexString(calculatedCardCryptogram)
        );
        TestContext.Out.WriteLine(
            "Expected Card Cryptogram: " + Convert.ToHexString(cardCryptogram)
        );
        // Verify the card cryptogram matches
        Assert.That(
            calculatedCardCryptogram,
            Is.EqualTo(cardCryptogram),
            "Card cryptogram mismatch"
        );

        // Test host cryptogram calculation
        // Per GP specification: sequence counter || card challenge || host challenge
        var hostCryptogramData = sequenceCounter
            .Concat(cardChallengeOnly)
            .Concat(hostChallengeBytes)
            .ToArray();

        // The CalculateScp02Cryptogram method uses PaddedBufferedBlockCipher which handles padding
        // So we pass the unpadded data directly (matching ScpVerification approach)
        var hostCryptogramResult = CryptoService.Cryptogram.CalculateScp02Cryptogram(
            encKey, // Use S-ENC session key for cryptogram
            hostCryptogramData // Pass unpadded data - cipher will handle padding
        );
        Assert.That(hostCryptogramResult.IsSuccess, Is.True, "Host cryptogram calculation failed");
        var hostCryptogram = hostCryptogramResult.Value;

        // Expected host cryptogram from trace (line 33)
        var expectedHostCryptogram = Convert.FromHexString("E214362A48999E2A");
        TestContext.Out.WriteLine(
            "Calculated Host Cryptogram: " + Convert.ToHexString(hostCryptogram)
        );
        TestContext.Out.WriteLine(
            "Expected Host Cryptogram: " + Convert.ToHexString(expectedHostCryptogram)
        );
        Assert.That(hostCryptogram, Is.EqualTo(expectedHostCryptogram), "Host cryptogram mismatch");

        // EXTERNAL AUTHENTICATE command from trace (line 35)
        var hostResponseHex = "84820300 10 E214362A48999E2AD0C159C17E6D3F9A 00".Replace(" ", "");
        var hostResponseBytes = Convert.FromHexString(hostResponseHex);

        var hostResponseCla = hostResponseBytes[0];
        var hostResponseIns = hostResponseBytes[1];
        var hostResponseP1 = hostResponseBytes[2];
        var hostResponseP2 = hostResponseBytes[3];
        var hostResponseLc = hostResponseBytes[4];
        var hostResponseCryptogram = hostResponseBytes[5..13];
        var hostResponseMac = hostResponseBytes[13..21];

        TestContext.Out.WriteLine(
            "Host Response Cryptogram: " + Convert.ToHexString(hostResponseCryptogram)
        );
        TestContext.Out.WriteLine("Host Response MAC: " + Convert.ToHexString(hostResponseMac));

        Assert.Multiple(() =>
        {
            Assert.That(
                hostResponseCla & channelNumberMask,
                Is.EqualTo(globalPlatformCommand | secureMessagingGlobalPlatformPropreitary)
            );
            Assert.That(hostResponseIns, Is.EqualTo(insExternalAuthenticate));
            Assert.That(hostResponseP2, Is.EqualTo(0x00));
            Assert.That(hostResponseLc, Is.EqualTo(0x10));
            Assert.That(
                hostResponseCryptogram,
                Is.EqualTo(expectedHostCryptogram),
                "Host cryptogram in command mismatch"
            );
        });

        // Test MAC calculation for EXTERNAL AUTHENTICATE
        var takeBytes = 5 + hostResponseLc - hostResponseMac.Length;
        var macInput = hostResponseBytes[..takeBytes];
        TestContext.Out.WriteLine("MAC Input: " + Convert.ToHexString(macInput));

        var calculatedMacResult = CryptoService.Mac.CalculateScp02CommandMac(
            cmacKey,
            macInput,
            macIcv
        );
        Assert.That(calculatedMacResult.IsSuccess, Is.True, "MAC calculation failed");
        TestContext.Out.WriteLine(
            "Calculated MAC: " + Convert.ToHexString(calculatedMacResult.Value)
        );
        Assert.That(
            calculatedMacResult.Value,
            Is.EqualTo(hostResponseMac),
            "EXTERNAL AUTHENTICATE MAC mismatch"
        );

        // Update ICV for next command
        macIcv = calculatedMacResult.Value;

        // Test subsequent command with ICV chaining
        var nextCommandHex = "84F28002 10 13A84162D6CF3D3EB2037DBFF3A4A091 00".Replace(" ", "");
        var nextCommandBytes = Convert.FromHexString(nextCommandHex);

        var preEncryptionData = new byte[] { 0x4F, 0x00 };
        byte[] preEncryptionCommand =
        [
            0x84,
            0xF2,
            0x80,
            0x02,
            (byte)preEncryptionData.Length,
            .. preEncryptionData
        ];

        TestContext.Out.Write("\n\nTesting ICV Chaining:\n");

        // Test ICV encryption for chaining
        var encryptedIcvResult = CryptoService.Mac.EncryptScp02Icv(macIcv, cmacKey);
        Assert.That(encryptedIcvResult.IsSuccess, Is.True, "ICV encryption failed");
        TestContext.Out.WriteLine(
            "Encrypted ICV: " + Convert.ToHexString(encryptedIcvResult.Value)
        );

        // Calculate MAC with encrypted ICV
        var nextMacInput = preEncryptionCommand.ToArray();
        nextMacInput[4] = (byte)(nextMacInput[4] + 8); // Add MAC length to Lc

        TestContext.Out.WriteLine("MAC Input: " + Convert.ToHexString(nextMacInput));
        Assert.That(Convert.ToHexString(nextMacInput), Is.EqualTo("84F280020A4F00"));

        var nextMacResult = CryptoService.Mac.CalculateScp02CommandMac(
            cmacKey,
            nextMacInput,
            encryptedIcvResult.Value
        );
        Assert.That(nextMacResult.IsSuccess, Is.True, "Next MAC calculation failed");
        TestContext.Out.WriteLine(
            "Calculated Chained MAC: " + Convert.ToHexString(nextMacResult.Value)
        );
        Assert.That(
            Convert.ToHexString(nextMacResult.Value),
            Is.EqualTo("B2037DBFF3A4A091"),
            "Chained MAC mismatch"
        );
    }

    [Test]
    public void Test_SCP02_Key_Derivation_With_Test_Vectors()
    {
        // Test vectors from GP specification
        var masterKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var sequenceCounter = Convert.FromHexString("0001");

        // Derive all session keys
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
        var dekKeyResult = CryptoService.KeyDerivation.DeriveScp02SessionKey(
            masterKey,
            sequenceCounter,
            Constants.Constants.Scp.Scp02.KeyDerivationConstants.SDek
        );

        Assert.Multiple(() =>
        {
            Assert.That(encKeyResult.IsSuccess, Is.True);
            Assert.That(macKeyResult.IsSuccess, Is.True);
            Assert.That(dekKeyResult.IsSuccess, Is.True);
        });

        // Verify keys are different
        Assert.Multiple(() =>
        {
            Assert.That(encKeyResult.Value, Is.Not.EqualTo(macKeyResult.Value));
            Assert.That(encKeyResult.Value, Is.Not.EqualTo(dekKeyResult.Value));
            Assert.That(macKeyResult.Value, Is.Not.EqualTo(dekKeyResult.Value));
        });

        // Verify key lengths
        Assert.Multiple(() =>
        {
            Assert.That(encKeyResult.Value.Length, Is.EqualTo(16));
            Assert.That(macKeyResult.Value.Length, Is.EqualTo(16));
            Assert.That(dekKeyResult.Value.Length, Is.EqualTo(16));
        });
    }

    [Test]
    public void Test_SCP02_Cryptogram_Padding()
    {
        var sEncKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var hostChallenge = Convert.FromHexString("0102030405060708");
        var sequenceCounter = Convert.FromHexString("0001");
        var cardChallenge = Convert.FromHexString("090A0B0C0D0E");

        // Build cryptogram data
        var data = hostChallenge.Concat(sequenceCounter).Concat(cardChallenge).ToArray();
        Assert.That(data.Length, Is.EqualTo(16));

        // Calculate cryptogram - padding is handled internally
        var result = CryptoService.Cryptogram.CalculateScp02Cryptogram(sEncKey, data);
        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value.Length, Is.EqualTo(8));
    }

    [Test]
    public void Test_SCP02_ICV_Encryption()
    {
        var sMacKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var icv = Convert.FromHexString("0102030405060708");

        var result = CryptoService.Mac.EncryptScp02Icv(icv, sMacKey);
        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value.Length, Is.EqualTo(8));

        // Verify encryption is deterministic
        var result2 = CryptoService.Mac.EncryptScp02Icv(icv, sMacKey);
        Assert.That(result2.IsSuccess, Is.True);
        Assert.That(result2.Value, Is.EqualTo(result.Value));

        // Verify different input produces different output
        var differentIcv = Convert.FromHexString("0807060504030201");
        var result3 = CryptoService.Mac.EncryptScp02Icv(differentIcv, sMacKey);
        Assert.That(result3.IsSuccess, Is.True);
        Assert.That(result3.Value, Is.Not.EqualTo(result.Value));
    }
}
