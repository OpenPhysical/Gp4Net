// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using AwesomeAssertions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using NUnit.Framework;

namespace Gp4Net.Tests.Cryptography;

[TestFixture]
[Category("Unit")]
public class KeyDerivationTests
{
    [Test]
    public void DeriveScp03SessionKeys_ValidInput_ReturnsSessionKeys()
    {
        // Arrange
        var keySet = new Scp03KeySet(
            encKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
            macKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
            dekKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F")
        );

        var hostChallenge = Convert.FromHexString("0102030405060708");
        var cardChallenge = Convert.FromHexString("0807060504030201");

        // Act
        var result = KeyDerivation.DeriveScp03SessionKeys(
            keySet,
            hostChallenge,
            cardChallenge,
            128
        );

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var sessionKeys = result.Value;

        _ = sessionKeys.SEnc.Length.Should().Be(16);
        _ = sessionKeys.SMac.Length.Should().Be(16);
        _ = sessionKeys.SrMac.Length.Should().Be(16);
        // Verify keys are different from master keys
        _ = sessionKeys.SEnc.Should().NotEqual(keySet.EncKey);
        _ = sessionKeys.SMac.Should().NotEqual(keySet.MacKey);
        _ = sessionKeys.SrMac.Should().NotEqual(keySet.MacKey);
        // Verify keys are not all zeros
        _ = sessionKeys.SEnc.Should().NotEqual(new byte[16]);
        _ = sessionKeys.SMac.Should().NotEqual(new byte[16]);
        _ = sessionKeys.SrMac.Should().NotEqual(new byte[16]);
    }

    [Test]
    public void DeriveScp03SessionKeys_DifferentChallenges_ProducesDifferentKeys()
    {
        // Arrange
        var keySet = new Scp03KeySet(
            encKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
            macKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
            dekKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F")
        );

        var hostChallenge1 = Convert.FromHexString("0102030405060708");
        var cardChallenge1 = Convert.FromHexString("0807060504030201");

        var hostChallenge2 = Convert.FromHexString("1112131415161718");
        var cardChallenge2 = Convert.FromHexString("1817161514131211");

        // Act
        var result1 = KeyDerivation.DeriveScp03SessionKeys(
            keySet,
            hostChallenge1,
            cardChallenge1,
            128
        );
        var result2 = KeyDerivation.DeriveScp03SessionKeys(
            keySet,
            hostChallenge2,
            cardChallenge2,
            128
        );

        // Assert
        _ = result1.IsSuccess.Should().BeTrue();
        _ = result2.IsSuccess.Should().BeTrue();
            
        var sessionKeys1 = result1.Value;
        var sessionKeys2 = result2.Value;

        _ = sessionKeys1.SEnc.Should().NotEqual(sessionKeys2.SEnc);
        _ = sessionKeys1.SMac.Should().NotEqual(sessionKeys2.SMac);
        _ = sessionKeys1.SrMac.Should().NotEqual(sessionKeys2.SrMac);
    }

    [Test]
    public void CalculateCryptogram_Scp03_ReturnsEightBytes()
    {
        // Arrange
        var key = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var data = Convert.FromHexString("0102030405060708090A0B0C0D0E0F10");

        // Act
        var result = KeyDerivation.CalculateCryptogram(key, data, true);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        var cryptogram = result.Value;

        _ = cryptogram.Length.Should().Be(8);
        // Verify cryptogram is not all zeros (would indicate a calculation error)
        _ = cryptogram.Should().NotEqual(new byte[8]);
        // Verify cryptogram is deterministic - same inputs should produce same output
        var result2 = KeyDerivation.CalculateCryptogram(key, data, true);
        _ = result2.IsSuccess.Should().BeTrue();
        _ = cryptogram.Should().BeEquivalentTo(result2.Value);
    }

    [Test]
    public void DeriveScp03SessionKeys_InvalidHostChallenge_ReturnsFailure()
    {
        // Arrange
        var keySet = new Scp03KeySet(
            encKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
            macKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
            dekKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F")
        );

        var invalidHostChallenge = Convert.FromHexString("0102030405"); // Too short
        var cardChallenge = Convert.FromHexString("0807060504030201");

        // Act
        var result = KeyDerivation.DeriveScp03SessionKeys(
            keySet,
            invalidHostChallenge,
            cardChallenge,
            128
        );

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<InvalidLengthError>();
        var lengthError = (InvalidLengthError)result.Error;
        _ = lengthError.Field.Should().Be("hostChallenge");
        _ = lengthError.Expected.Should().Be(8);
        _ = lengthError.Actual.Should().Be(5);
    }
}