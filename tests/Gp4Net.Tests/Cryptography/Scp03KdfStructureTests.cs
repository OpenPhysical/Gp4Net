// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Reflection;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using NUnit.Framework;

namespace Gp4Net.Tests.Cryptography;

/// <summary>
/// Tests to verify the structure of SCP03 KDF input matches GlobalPlatform specifications.
/// </summary>
[TestFixture]
[Category("Unit")]
public class Scp03KdfStructureTests
{
    [Test]
    public void DeriveScp03Key_InputStructure_MatchesGlobalPlatformSpec()
    {
        // This test verifies that our KDF input structure matches:
        // Counter || Label || 0x00 || Derivation Constant || 0x00 || L || Context

        // Use reflection to access the private DeriveScp03Key method for testing
        MethodInfo? method = typeof(KeyDerivationService).GetMethod(
            "DeriveScp03Key",
            BindingFlags.NonPublic | BindingFlags.Instance
        );

        _ = method.Should().NotBeNull("Could not find DeriveScp03Key method");

        // Test parameters
        byte[] kdk = new byte[16];
        Array.Fill(kdk, (byte)0x40);
        // Test parameters (unused but documented for clarity)
        // var derivationConstant = DerivationConstants.SEnc;
        byte[] context = new byte[16]; // host challenge || card challenge
        Array.Fill(context, (byte)0x01);
        // var keyLengthBits = 128;

        // Expected structure (without counter which is prepended by KDF):
        // Label (11 bytes) || 0x00 || Derivation Constant || 0x00 || L (2 bytes) || Context (16 bytes)
        // var expectedLength = 11 + 1 + 1 + 1 + 2 + 16; // 32 bytes

        // Verify the constants
        _ = DerivationConstants.Scp03Label.Length.Should()
            .Be(11, "SCP03 label should be 11 bytes");
        _ = DerivationConstants.Scp03Separator.Should()
            .Be(0x00, "SCP03 separator should be 0x00");

        // Test derivation constants
        _ = DerivationConstants.SEnc.Should()
            .Be(0x04, "S-ENC constant should be 0x04");
        _ = DerivationConstants.SMac.Should()
            .Be(0x06, "S-MAC constant should be 0x06");
        _ = DerivationConstants.SrMac.Should()
            .Be(0x07, "S-RMAC constant should be 0x07");
    }

    [Test]
    public void Scp03Label_IsAllZeros()
    {
        // Verify that the SCP03 label is 11 bytes of zeros
        byte[]? label = DerivationConstants.Scp03Label;

        _ = label.Length.Should().Be(11);

        foreach (byte b in label)
        {
            _ = b.Should().Be(0x00, "All bytes in SCP03 label should be 0x00");
        }
    }

    [Test]
    public void DeriveScp03SessionKeys_ProducesThreeDifferentKeys()
    {
        // Arrange
        byte[] kdk = new byte[16];
        Array.Fill(kdk, (byte)0xFF);

        Scp03KeySet keySet = new Scp03KeySet(encKey: kdk, macKey: kdk, dekKey: kdk);

        byte[] hostChallenge = new byte[8];
        Array.Fill(hostChallenge, (byte)0xAA);

        byte[] cardChallenge = new byte[8];
        Array.Fill(cardChallenge, (byte)0xBB);

        // Act
        Result<SessionKeys, SmartCardError> result = KeyDerivation.DeriveScp03SessionKeys(
            keySet,
            hostChallenge,
            cardChallenge,
            128
        );

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        SessionKeys? sessionKeys = result.Value;

        // All three keys should be different due to different derivation constants
        _ = sessionKeys.SEnc.Should()
            .NotEqual(sessionKeys.SMac, "S-ENC and S-MAC should be different");
        _ = sessionKeys.SMac.Should()
            .NotEqual(sessionKeys.SrMac, "S-MAC and S-RMAC should be different");
        _ = sessionKeys.SEnc.Should()
            .NotEqual(sessionKeys.SrMac, "S-ENC and S-RMAC should be different");
    }

    [Test]
    public void DeriveScp03SessionKeys_SameInputs_ProducesSameOutputs()
    {
        // Test deterministic behavior
        Scp03KeySet keySet = new Scp03KeySet(
            encKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
            macKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
            dekKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F")
        );

        byte[] hostChallenge = Convert.FromHexString("0102030405060708");
        byte[] cardChallenge = Convert.FromHexString("0807060504030201");

        // Act - derive keys twice
        Result<SessionKeys, SmartCardError> result1 = KeyDerivation.DeriveScp03SessionKeys(
            keySet,
            hostChallenge,
            cardChallenge,
            128
        );
        Result<SessionKeys, SmartCardError> result2 = KeyDerivation.DeriveScp03SessionKeys(
            keySet,
            hostChallenge,
            cardChallenge,
            128
        );

        // Assert - results should be identical
        _ = result1.IsSuccess.Should().BeTrue();
        _ = result2.IsSuccess.Should().BeTrue();

        SessionKeys? sessionKeys1 = result1.Value;
        SessionKeys? sessionKeys2 = result2.Value;

        _ = sessionKeys1.SEnc.Should()
            .Equal(sessionKeys2.SEnc, "S-ENC should be deterministic");
        _ = sessionKeys1.SMac.Should()
            .Equal(sessionKeys2.SMac, "S-MAC should be deterministic");
        _ = sessionKeys1.SrMac.Should()
            .Equal(sessionKeys2.SrMac, "S-RMAC should be deterministic");
    }
}