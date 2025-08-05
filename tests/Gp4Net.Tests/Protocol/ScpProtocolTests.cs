// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Tests.TestVectors;
using NUnit.Framework;

namespace Gp4Net.Tests.Protocol;

/// <summary>
/// Comprehensive SCP protocol tests using JSON test vectors from verified Python reference implementations.
/// Replaces redundant individual conformance tests with parameterized tests covering all scenarios.
/// Source: scripts/scp02_test_vectors.json and scripts/scp03_test_vectors.json
/// </summary>
[TestFixture]
[Category("Protocol")]
public class ScpProtocolTests
{
    [Test]
    [TestCaseSource(nameof(GetScp02TestVectors))]
    public void Scp02_KeyDerivation_WithJsonTestVector_ProducesExpectedSessionKeys(Scp02TestVector vector)
    {
        // Arrange
        var keySet = Scp02KeySet.Create(
            vector.StaticEncKey,
            vector.StaticMacKey,
            vector.StaticDekKey,
            0x01
        );
        keySet.IsSuccess.Should().BeTrue($"Failed to create key set: {vector.Name}");

        var implementationOption = Convert.ToByte(vector.ImplementationOption, 16);

        // Act
        var result = Scp02ProtocolImpl.DeriveSessionKeys(
            keySet.Value,
            vector.HostChallenge,
            vector.CardChallenge,
            vector.SequenceCounter,
            implementationOption
        );

        // Assert
        result.IsSuccess.Should().BeTrue($"Key derivation failed for {vector.Name}: {(result.IsFailure ? result.Error.Message : "N/A")}");
        
        var sessionKeys = result.Value;
        sessionKeys.SEnc.Should().BeEquivalentTo(vector.ExpectedSEncKey, $"S-ENC mismatch for {vector.Name}");
        sessionKeys.SMac.Should().BeEquivalentTo(vector.ExpectedSMacKey, $"S-MAC mismatch for {vector.Name}");
        sessionKeys.Dek.Should().BeEquivalentTo(vector.ExpectedSDekKey, $"S-DEK mismatch for {vector.Name}");
    }

    [Test]
    [TestCaseSource(nameof(GetScp03TestVectors))]
    public void Scp03_KeyDerivation_WithJsonTestVector_ProducesExpectedSessionKeys(Scp03TestVector vector)
    {
        // Arrange
        var keySet = new Scp03KeySet(
            vector.StaticEncKey,
            vector.StaticMacKey,
            vector.StaticDekKey,
            0x01
        );

        // Act
        var result = Scp03ProtocolImpl.DeriveSessionKeys(
            keySet,
            vector.HostChallenge,
            vector.CardChallenge,
            null, // SCP03 doesn't use sequence counter for key derivation
            0x00  // Implementation parameter not used for SCP03
        );

        // Assert
        result.IsSuccess.Should().BeTrue($"Key derivation failed for {vector.Name}: {(result.IsFailure ? result.Error.Message : "N/A")}");
        
        var sessionKeys = result.Value;
        sessionKeys.SEnc.Should().BeEquivalentTo(vector.ExpectedSEncKey, $"S-ENC mismatch for {vector.Name}");
        sessionKeys.SMac.Should().BeEquivalentTo(vector.ExpectedSMacKey, $"S-MAC mismatch for {vector.Name}");
        // Note: SessionKeys.SRMac is not directly accessible from SessionKeys structure
        // The SRMac key is derived and stored separately within the protocol implementation
    }

    [Test]
    [TestCaseSource(nameof(GetScp02TestVectors))]
    public void Scp02_CryptogramCalculation_WithJsonTestVector_ProducesExpectedCryptograms(Scp02TestVector vector)
    {
        // Arrange
        var sessionEncKey = vector.ExpectedSEncKey;

        // Act - Calculate card cryptogram
        var cardCryptogramResult = Scp02ProtocolImpl.CalculateCryptogramMac(sessionEncKey, vector.CardCryptogramData);
        
        // Act - Calculate host cryptogram  
        var hostCryptogramResult = Scp02ProtocolImpl.CalculateCryptogramMac(sessionEncKey, vector.HostCryptogramData);

        // Assert
        cardCryptogramResult.IsSuccess.Should().BeTrue($"Card cryptogram calculation failed for {vector.Name}");
        hostCryptogramResult.IsSuccess.Should().BeTrue($"Host cryptogram calculation failed for {vector.Name}");
        
        cardCryptogramResult.Value.Should().BeEquivalentTo(vector.ExpectedCardCryptogram, $"Card cryptogram mismatch for {vector.Name}");
        hostCryptogramResult.Value.Should().BeEquivalentTo(vector.ExpectedHostCryptogram, $"Host cryptogram mismatch for {vector.Name}");
    }

    [Test]
    [TestCaseSource(nameof(GetScp03TestVectors))]
    public void Scp03_CryptogramCalculation_WithJsonTestVector_ProducesExpectedCryptograms(Scp03TestVector vector)
    {
        // Arrange
        var sessionMacKey = vector.ExpectedSMacKey;
        var context = vector.HostChallenge.Concat(vector.CardChallenge).ToArray();
        
        // For SCP03, cryptograms are calculated using KDF on the session MAC key
        // Card cryptogram: KDF(S-MAC, derivation constant 0x00, context, 64 bits)
        // Host cryptogram: KDF(S-MAC, derivation constant 0x01, context, 64 bits)
        var cryptogramService = new Gp4Net.Domain.Security.CryptogramService();

        // Act - Calculate card cryptogram
        var cardCryptogramResult = cryptogramService.CalculateCardCryptogram(
            sessionMacKey, 
            vector.HostChallenge, 
            vector.CardChallenge, 
            Maybe<byte[]>.None, 
            ScpVersion.Scp03);
        
        // Act - Calculate host cryptogram
        var hostCryptogramResult = cryptogramService.CalculateHostCryptogram(
            sessionMacKey, 
            vector.HostChallenge, 
            vector.CardChallenge, 
            Maybe<byte[]>.None, 
            ScpVersion.Scp03);

        // Assert
        cardCryptogramResult.IsSuccess.Should().BeTrue($"Card cryptogram calculation failed for {vector.Name}: {(cardCryptogramResult.IsFailure ? cardCryptogramResult.Error.Message : "N/A")}");
        hostCryptogramResult.IsSuccess.Should().BeTrue($"Host cryptogram calculation failed for {vector.Name}: {(hostCryptogramResult.IsFailure ? hostCryptogramResult.Error.Message : "N/A")}");
        
        cardCryptogramResult.Value.Should().BeEquivalentTo(vector.ExpectedCardCryptogram, $"Card cryptogram mismatch for {vector.Name}");
        hostCryptogramResult.Value.Should().BeEquivalentTo(vector.ExpectedHostCryptogram, $"Host cryptogram mismatch for {vector.Name}");
    }

    [Test]
    [TestCaseSource(nameof(GetScp02CMacTestVectors))]
    public void Scp02_CMacCalculation_WithJsonTestVector_ProducesExpectedMac(Scp02CMacTestVector vector)
    {
        // Act
        var macResult = Scp02ProtocolImpl.CalculateMac(vector.MacKey, vector.CommandData);

        // Assert
        macResult.IsSuccess.Should().BeTrue($"C-MAC calculation failed for {vector.Name}: {(macResult.IsFailure ? macResult.Error.Message : "N/A")}");
        macResult.Value.Should().BeEquivalentTo(vector.ExpectedCMac, $"C-MAC mismatch for {vector.Name}");
    }

    [Test]
    public void Scp02_ProtocolConstants_MatchSpecification()
    {
        Scp02ProtocolImpl.ProtocolVersion.Should().Be(0x02);
        Scp02ProtocolImpl.BlockSize.Should().Be(8); // 3DES block size
        Scp02ProtocolImpl.MacSize.Should().Be(8);
        Scp02ProtocolImpl.ChainingValueSize.Should().Be(8);
        Scp02ProtocolImpl.CardChallengeLength.Should().Be(6); // SCP02 uses 6-byte card challenge
    }

    [Test]
    public void Scp03_ProtocolConstants_MatchSpecification()
    {
        Scp03ProtocolImpl.ProtocolVersion.Should().Be(0x03);
        Scp03ProtocolImpl.BlockSize.Should().Be(16); // AES block size
        Scp03ProtocolImpl.MacSize.Should().Be(8); // Truncated for commands/responses
        Scp03ProtocolImpl.ChainingValueSize.Should().Be(16); // Full AES-CMAC for chaining
        Scp03ProtocolImpl.CardChallengeLength.Should().Be(8); // SCP03 uses 8-byte card challenge
    }

    [Test]
    public void Scp02_KeySetCreation_WithValidKeys_Succeeds()
    {
        // Arrange
        var encKey = new byte[16];
        var macKey = new byte[16];
        var dekKey = new byte[16];
        
        // Act
        var result = Scp02KeySet.Create(encKey, macKey, dekKey, 0x01);
        
        // Assert
        result.IsSuccess.Should().BeTrue("Valid keys should create successful key set");
    }

    [Test]
    public void Scp03_KeySetCreation_WithValidKeys_Succeeds()
    {
        // Arrange
        var encKey = new byte[16];
        var macKey = new byte[16];
        var dekKey = new byte[16];
        
        // Act
        var keySet = new Scp03KeySet(encKey, macKey, dekKey, 0x01);
        
        // Assert
        keySet.Should().NotBeNull("Valid keys should create successful key set");
        keySet.EncKey.Should().BeEquivalentTo(encKey);
        keySet.MacKey.Should().BeEquivalentTo(macKey);
        keySet.DekKey.Should().BeEquivalentTo(dekKey);
    }

    // Test vector sources for parameterized tests
    private static Scp02TestVector[] GetScp02TestVectors() => ScpTestVectors.Scp02Vectors.ToArray();
    private static Scp03TestVector[] GetScp03TestVectors() => ScpTestVectors.Scp03Vectors.ToArray();
    private static Scp02CMacTestVector[] GetScp02CMacTestVectors() => ScpTestVectors.Scp02CMacVectors.ToArray();
}