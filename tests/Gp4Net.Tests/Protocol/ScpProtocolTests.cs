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
using Gp4Net.Domain.Security;
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
        _ = keySet.IsSuccess.Should().BeTrue($"Failed to create key set: {vector.Name}");

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
        _ = result.IsSuccess.Should().BeTrue($"Key derivation failed for {vector.Name}: {(result.IsFailure ? result.Error.Message : "N/A")}");
        
        var sessionKeys = result.Value;
        _ = sessionKeys.SEnc.Should().BeEquivalentTo(vector.ExpectedSEncKey, $"S-ENC mismatch for {vector.Name}");
        _ = sessionKeys.SMac.Should().BeEquivalentTo(vector.ExpectedSMacKey, $"S-MAC mismatch for {vector.Name}");
        _ = sessionKeys.Dek.Should().BeEquivalentTo(vector.ExpectedSDekKey, $"S-DEK mismatch for {vector.Name}");
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
        _ = result.IsSuccess.Should().BeTrue($"Key derivation failed for {vector.Name}: {(result.IsFailure ? result.Error.Message : "N/A")}");
        
        var sessionKeys = result.Value;
        _ = sessionKeys.SEnc.Should().BeEquivalentTo(vector.ExpectedSEncKey, $"S-ENC mismatch for {vector.Name}");
        _ = sessionKeys.SMac.Should().BeEquivalentTo(vector.ExpectedSMacKey, $"S-MAC mismatch for {vector.Name}");
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
        _ = cardCryptogramResult.IsSuccess.Should().BeTrue($"Card cryptogram calculation failed for {vector.Name}");
        _ = hostCryptogramResult.IsSuccess.Should().BeTrue($"Host cryptogram calculation failed for {vector.Name}");

        _ = cardCryptogramResult.Value.Should().BeEquivalentTo(vector.ExpectedCardCryptogram, $"Card cryptogram mismatch for {vector.Name}");
        _ = hostCryptogramResult.Value.Should().BeEquivalentTo(vector.ExpectedHostCryptogram, $"Host cryptogram mismatch for {vector.Name}");
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

        // Act - Create type-safe SCP03 parameters and calculate cryptograms
        var keySet = new Scp03KeySet(sessionMacKey, sessionMacKey, sessionMacKey) { SMac = sessionMacKey };
        
        var cardCryptogramResult = CryptogramParameters.ForScp03(
                vector.HostChallenge,
                vector.CardChallenge,
                keySet)
            .Bind(parameters => cryptogramService.CalculateCardCryptogram(parameters));
        
        var hostCryptogramResult = CryptogramParameters.ForScp03(
                vector.HostChallenge,
                vector.CardChallenge,
                keySet)
            .Bind(parameters => cryptogramService.CalculateHostCryptogram(parameters));

        // Assert
        _ = cardCryptogramResult.IsSuccess.Should().BeTrue($"Card cryptogram calculation failed for {vector.Name}: {(cardCryptogramResult.IsFailure ? cardCryptogramResult.Error.Message : "N/A")}");
        _ = hostCryptogramResult.IsSuccess.Should().BeTrue($"Host cryptogram calculation failed for {vector.Name}: {(hostCryptogramResult.IsFailure ? hostCryptogramResult.Error.Message : "N/A")}");

        _ = cardCryptogramResult.Value.Should().BeEquivalentTo(vector.ExpectedCardCryptogram, $"Card cryptogram mismatch for {vector.Name}");
        _ = hostCryptogramResult.Value.Should().BeEquivalentTo(vector.ExpectedHostCryptogram, $"Host cryptogram mismatch for {vector.Name}");
    }

    [Test]
    [TestCaseSource(nameof(GetScp02CMacTestVectors))]
    public void Scp02_CMacCalculation_WithJsonTestVector_ProducesExpectedMac(Scp02CMacTestVector vector)
    {
        // Act
        var macResult = Scp02ProtocolImpl.CalculateMac(vector.MacKey, vector.CommandData);

        // Assert
        _ = macResult.IsSuccess.Should().BeTrue($"C-MAC calculation failed for {vector.Name}: {(macResult.IsFailure ? macResult.Error.Message : "N/A")}");
        _ = macResult.Value.Should().BeEquivalentTo(vector.ExpectedCMac, $"C-MAC mismatch for {vector.Name}");
    }

    [Test]
    public void Scp02_ProtocolConstants_MatchSpecification()
    {
        _ = Scp02ProtocolImpl.ProtocolVersion.Should().Be(0x02);
        _ = Scp02ProtocolImpl.BlockSize.Should().Be(8); // 3DES block size
        _ = Scp02ProtocolImpl.MacSize.Should().Be(8);
        _ = Scp02ProtocolImpl.ChainingValueSize.Should().Be(8);
        _ = Scp02ProtocolImpl.CardChallengeLength.Should().Be(6); // SCP02 uses 6-byte card challenge
    }

    [Test]
    public void Scp03_ProtocolConstants_MatchSpecification()
    {
        _ = Scp03ProtocolImpl.ProtocolVersion.Should().Be(0x03);
        _ = Scp03ProtocolImpl.BlockSize.Should().Be(16); // AES block size
        _ = Scp03ProtocolImpl.MacSize.Should().Be(8); // Truncated for commands/responses
        _ = Scp03ProtocolImpl.ChainingValueSize.Should().Be(16); // Full AES-CMAC for chaining
        _ = Scp03ProtocolImpl.CardChallengeLength.Should().Be(8); // SCP03 uses 8-byte card challenge
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
        _ = result.IsSuccess.Should().BeTrue("Valid keys should create successful key set");
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
        _ = keySet.Should().NotBeNull("Valid keys should create successful key set");
        _ = keySet.EncKey.Should().BeEquivalentTo(encKey);
        _ = keySet.MacKey.Should().BeEquivalentTo(macKey);
        _ = keySet.DekKey.Should().BeEquivalentTo(dekKey);
    }

    // Test vector sources for parameterized tests
    private static Scp02TestVector[] GetScp02TestVectors() => ScpTestVectors.Scp02Vectors.ToArray();
    private static Scp03TestVector[] GetScp03TestVectors() => ScpTestVectors.Scp03Vectors.ToArray();
    private static Scp02CMacTestVector[] GetScp02CMacTestVectors() => ScpTestVectors.Scp02CMacVectors.ToArray();
}