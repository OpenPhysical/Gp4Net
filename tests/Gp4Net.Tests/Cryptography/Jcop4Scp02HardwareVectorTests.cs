using System;
using System.Linq;
using AwesomeAssertions;
using Gp4Net.Cryptography;
using NUnit.Framework;

namespace Gp4Net.Tests.Cryptography;

[TestFixture]
[Category("HardwareVector")]
public sealed class Jcop4Scp02HardwareVectorTests
{
    [Test]
    public void StaticTestKeys_ReproduceCapturedJcop4SessionAndExternalAuthenticate()
    {
        // NXP P71D321/JCOP4 capture, GlobalPlatformPro, 2026-08-26.
        byte[] key = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        byte[] sequenceCounter = Convert.FromHexString("0017");
        byte[] hostChallenge = Convert.FromHexString("E3E36E6FBBC98F00");
        byte[] cardChallenge = Convert.FromHexString("CE12B6373F90");

        byte[] sEnc = CryptoOperations.KeyDerivation.DeriveScp02SessionKey(
            key,
            sequenceCounter,
            Constants.Constants.Scp.Scp02.KeyDerivationConstants.SEnc
        ).Value;
        byte[] sMac = CryptoOperations.KeyDerivation.DeriveScp02SessionKey(
            key,
            sequenceCounter,
            Constants.Constants.Scp.Scp02.KeyDerivationConstants.SMac
        ).Value;
        byte[] sRmac = CryptoOperations.KeyDerivation.DeriveScp02SessionKey(
            key,
            sequenceCounter,
            Constants.Constants.Scp.Scp02.KeyDerivationConstants.SrMac
        ).Value;

        sEnc.Should().Equal(Convert.FromHexString("56A1DC0A4B4165C9ED464FAB97380ABD"));
        sMac.Should().Equal(Convert.FromHexString("6DDCB69848E88F941CDD5978B46B6A3E"));
        sRmac.Should().Equal(Convert.FromHexString("04F08E7AA9F735905DB96CFF6DF02A30"));

        byte[] cardCryptogram = CryptoOperations.Cryptogram.CalculateScp02Cryptogram(
            sEnc,
            hostChallenge.Concat(sequenceCounter).Concat(cardChallenge).ToArray()
        ).Value;
        byte[] hostCryptogram = CryptoOperations.Cryptogram.CalculateScp02Cryptogram(
            sEnc,
            sequenceCounter.Concat(cardChallenge).Concat(hostChallenge).ToArray()
        ).Value;

        cardCryptogram.Should().Equal(Convert.FromHexString("2AA03BDA981D015E"));
        hostCryptogram.Should().Equal(Convert.FromHexString("DF4B2AC87842B118"));

        byte[] externalAuthenticateWithoutMac =
        [
            0x84, 0x82, 0x01, 0x00, 0x10,
            .. hostCryptogram,
        ];
        byte[] commandMac = CryptoOperations.Mac.CalculateScp02CommandMac(
            sMac,
            externalAuthenticateWithoutMac,
            new byte[8]
        ).Value;

        commandMac.Should().Equal(Convert.FromHexString("AD3410261EB6603F"));
    }
}
