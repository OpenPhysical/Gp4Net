// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using NUnit.Framework;

namespace Gp4Net.Tests.Cryptography
{
    [TestFixture]
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
            var sessionKeys = KeyDerivation.DeriveScp03SessionKeys(
                keySet,
                hostChallenge,
                cardChallenge,
                128
            );

            // Assert
            Assert.That(sessionKeys.SEnc.Length, Is.EqualTo(16));
            Assert.That(sessionKeys.SMac.Length, Is.EqualTo(16));
            Assert.That(sessionKeys.SRMac.Length, Is.EqualTo(16));
            // Verify keys are different from master keys
            Assert.That(sessionKeys.SEnc, Is.Not.EqualTo(keySet.EncKey));
            Assert.That(sessionKeys.SMac, Is.Not.EqualTo(keySet.MacKey));
            Assert.That(sessionKeys.SRMac, Is.Not.EqualTo(keySet.MacKey));
            // Verify keys are not all zeros
            Assert.That(sessionKeys.SEnc, Is.Not.EqualTo(new byte[16]));
            Assert.That(sessionKeys.SMac, Is.Not.EqualTo(new byte[16]));
            Assert.That(sessionKeys.SRMac, Is.Not.EqualTo(new byte[16]));
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
            var sessionKeys1 = KeyDerivation.DeriveScp03SessionKeys(
                keySet,
                hostChallenge1,
                cardChallenge1,
                128
            );
            var sessionKeys2 = KeyDerivation.DeriveScp03SessionKeys(
                keySet,
                hostChallenge2,
                cardChallenge2,
                128
            );

            // Assert
            Assert.That(sessionKeys1.SEnc, Is.Not.EqualTo(sessionKeys2.SEnc));
            Assert.That(sessionKeys1.SMac, Is.Not.EqualTo(sessionKeys2.SMac));
            Assert.That(sessionKeys1.SRMac, Is.Not.EqualTo(sessionKeys2.SRMac));
        }

        [Test]
        public void CalculateCryptogram_Scp03_ReturnsEightBytes()
        {
            // Arrange
            var key = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
            var data = Convert.FromHexString("0102030405060708090A0B0C0D0E0F10");

            // Act
            var cryptogram = KeyDerivation.CalculateCryptogram(key, data, true);

            // Assert
            Assert.That(cryptogram.Length, Is.EqualTo(8));
            // Verify cryptogram is not all zeros (would indicate a calculation error)
            Assert.That(cryptogram, Is.Not.EqualTo(new byte[8]));
            // Verify cryptogram is deterministic - same inputs should produce same output
            var cryptogram2 = KeyDerivation.CalculateCryptogram(key, data, true);
            Assert.That(cryptogram, Is.EqualTo(cryptogram2));
        }

        [Test]
        public void DeriveScp03SessionKeys_InvalidHostChallenge_ThrowsException()
        {
            // Arrange
            var keySet = new Scp03KeySet(
                encKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
                macKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
                dekKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F")
            );

            var invalidHostChallenge = Convert.FromHexString("0102030405"); // Too short
            var cardChallenge = Convert.FromHexString("0807060504030201");

            // Act & Assert
            _ = Assert.Throws<ArgumentException>(
                () =>
                    KeyDerivation.DeriveScp03SessionKeys(
                        keySet,
                        invalidHostChallenge,
                        cardChallenge,
                        128
                    )
            );
        }
    }
}
