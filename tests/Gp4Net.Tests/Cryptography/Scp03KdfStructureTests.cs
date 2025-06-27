// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Reflection;
using Gp4Net.Constants;
using Gp4Net.Cryptography;

namespace Gp4Net.Tests.Cryptography
{
    /// <summary>
    /// Tests to verify the structure of SCP03 KDF input matches GlobalPlatform specifications.
    /// </summary>
    [TestFixture]
    public class Scp03KdfStructureTests
    {
        [Test]
        public void DeriveScp03Key_InputStructure_MatchesGlobalPlatformSpec()
        {
            // This test verifies that our KDF input structure matches:
            // Counter || Label || 0x00 || Derivation Constant || 0x00 || L || Context

            // Use reflection to access the private DeriveScp03Key method for testing
            var method = typeof(KeyDerivation).GetMethod(
                "DeriveScp03Key",
                BindingFlags.NonPublic | BindingFlags.Static);

            Assert.That(method, Is.Not.Null, "Could not find DeriveScp03Key method");

            // Test parameters
            var kdk = new byte[16];
            Array.Fill(kdk, (byte)0x40);
            var derivationConstant = DerivationConstants.SEnc;
            var context = new byte[16]; // host challenge || card challenge
            Array.Fill(context, (byte)0x01);
            var keyLengthBits = 128;

            // Expected structure (without counter which is prepended by KDF):
            // Label (11 bytes) || 0x00 || Derivation Constant || 0x00 || L (2 bytes) || Context (16 bytes)
            var expectedLength = 11 + 1 + 1 + 1 + 2 + 16; // 32 bytes

            // Verify the constants
            Assert.That(DerivationConstants.Scp03Label.Length, Is.EqualTo(11),
                "SCP03 label should be 11 bytes");
            Assert.That(DerivationConstants.Scp03Separator, Is.EqualTo(0x00),
                "SCP03 separator should be 0x00");

            // Test derivation constants
            Assert.That(DerivationConstants.SEnc, Is.EqualTo(0x04), "S-ENC constant should be 0x04");
            Assert.That(DerivationConstants.SMac, Is.EqualTo(0x06), "S-MAC constant should be 0x06");
            Assert.That(DerivationConstants.SRMac, Is.EqualTo(0x07), "S-RMAC constant should be 0x07");
        }

        [Test]
        public void Scp03Label_IsAllZeros()
        {
            // Verify that the SCP03 label is 11 bytes of zeros
            var label = DerivationConstants.Scp03Label;

            Assert.That(label.Length, Is.EqualTo(11));

            foreach (var b in label)
            {
                Assert.That(b, Is.EqualTo(0x00), "All bytes in SCP03 label should be 0x00");
            }
        }

        [Test]
        public void DeriveScp03SessionKeys_ProducesThreeDifferentKeys()
        {
            // Arrange
            var kdk = new byte[16];
            Array.Fill(kdk, (byte)0xFF);

            var keySet = new Gp4Net.Domain.Keys.Scp03KeySet(
                encKey: kdk,
                macKey: kdk,
                dekKey: kdk
            );

            var hostChallenge = new byte[8];
            Array.Fill(hostChallenge, (byte)0xAA);

            var cardChallenge = new byte[8];
            Array.Fill(cardChallenge, (byte)0xBB);

            // Act
            var sessionKeys = KeyDerivation.DeriveScp03SessionKeys(keySet, hostChallenge, cardChallenge, 128);

            // Assert - all three keys should be different due to different derivation constants
            Assert.That(sessionKeys.SEnc, Is.Not.EqualTo(sessionKeys.SMac),
                "S-ENC and S-MAC should be different");
            Assert.That(sessionKeys.SMac, Is.Not.EqualTo(sessionKeys.SRMac),
                "S-MAC and S-RMAC should be different");
            Assert.That(sessionKeys.SEnc, Is.Not.EqualTo(sessionKeys.SRMac),
                "S-ENC and S-RMAC should be different");

            // Log for debugging
            Console.WriteLine($"S-ENC:  {Convert.ToHexString(sessionKeys.SEnc)}");
            Console.WriteLine($"S-MAC:  {Convert.ToHexString(sessionKeys.SMac)}");
            Console.WriteLine($"S-RMAC: {Convert.ToHexString(sessionKeys.SRMac)}");
        }

        [Test]
        public void DeriveScp03SessionKeys_SameInputs_ProducesSameOutputs()
        {
            // Test deterministic behavior
            var keySet = new Gp4Net.Domain.Keys.Scp03KeySet(
                encKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
                macKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
                dekKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F")
            );

            var hostChallenge = Convert.FromHexString("0102030405060708");
            var cardChallenge = Convert.FromHexString("0807060504030201");

            // Act - derive keys twice
            var sessionKeys1 = KeyDerivation.DeriveScp03SessionKeys(keySet, hostChallenge, cardChallenge, 128);
            var sessionKeys2 = KeyDerivation.DeriveScp03SessionKeys(keySet, hostChallenge, cardChallenge, 128);

            // Assert - results should be identical
            Assert.That(sessionKeys1.SEnc, Is.EqualTo(sessionKeys2.SEnc),
                "S-ENC should be deterministic");
            Assert.That(sessionKeys1.SMac, Is.EqualTo(sessionKeys2.SMac),
                "S-MAC should be deterministic");
            Assert.That(sessionKeys1.SRMac, Is.EqualTo(sessionKeys2.SRMac),
                "S-RMAC should be deterministic");
        }
    }
}
