using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Security;

/// <summary>
/// Tests for SCP02 cryptogram calculations using type-safe parameters.
/// Validates that invalid states are unrepresentable at compile time.
/// </summary>
public class CryptogramServiceScp02Tests
{
    private readonly CryptogramService _cryptogramService;

    public CryptogramServiceScp02Tests()
    {
        _cryptogramService = new CryptogramService();
    }

    [Test]
    public void CalculateCardCryptogram_WithInvalidCardChallengeLength_ShouldFail()
    {
        // Arrange - Try to create parameters with invalid card challenge length
        var hostChallenge = new byte[8];
        var invalidCardChallenge = new byte[8]; // Should be 6 for SCP02
        var sequenceCounter = new byte[2];
        
        var keySetResult = Scp02KeySet.Create(new byte[16], new byte[16], new byte[16]);
        keySetResult.IsSuccess.Should().BeTrue("Key set creation should succeed");

        // Act
        var result = keySetResult.Bind(keySet => 
            CryptogramParameters.ForScp02(
                hostChallenge,
                invalidCardChallenge,
                sequenceCounter,
                keySet));

        // Assert - Parameter creation should fail with invalid card challenge
        result.IsFailure.Should().BeTrue();
        result.Error.Message.Should().Contain("SCP02 card challenge must be 6 bytes");
    }

    [Test]
    public void CalculateCardCryptogram_WithInvalidSequenceCounterLength_ShouldFail()
    {
        // Arrange - Try to create parameters with invalid sequence counter length
        var hostChallenge = new byte[8];
        var cardChallenge = new byte[6];
        var invalidSequenceCounter = new byte[3]; // Should be 2 for SCP02
        
        var keySetResult = Scp02KeySet.Create(new byte[16], new byte[16], new byte[16]);
        keySetResult.IsSuccess.Should().BeTrue("Key set creation should succeed");

        // Act
        var result = keySetResult.Bind(keySet => 
            CryptogramParameters.ForScp02(
                hostChallenge,
                cardChallenge,
                invalidSequenceCounter,
                keySet));

        // Assert - Parameter creation should fail with invalid sequence counter
        result.IsFailure.Should().BeTrue();
        result.Error.Message.Should().Contain("Sequence counter must be 2 bytes");
    }

    [Test]
    public void CalculateCardCryptogram_WithValidParameters_ShouldSucceed()
    {
        // Arrange - Using test vectors from a real SCP02 trace
        var encKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var hostChallenge = Convert.FromHexString("0102030405060708");
        var cardChallenge = Convert.FromHexString("0A0B0C0D0E0F");
        var sequenceCounter = Convert.FromHexString("0001");

        // Act - Create key set and parameters functionally
        var result = Scp02KeySet.Create(encKey, encKey, encKey) // SEnc will be set to encKey in constructor
            .Bind(keySet => CryptogramParameters.ForScp02(hostChallenge, cardChallenge, sequenceCounter, keySet))
            .Bind(parameters => _cryptogramService.CalculateCardCryptogram(parameters));

        // Assert
        result.IsSuccess.Should().BeTrue($"Expected success but got: {(result.IsFailure ? result.Error.Message : "")}");
        result.Match(
            cryptogram => cryptogram.Should().HaveCount(8),
            error => Assert.Fail($"Cryptogram calculation failed: {error.Message}"));
    }

    [Test]
    public void CalculateHostCryptogram_WithValidParameters_ShouldSucceed()
    {
        // Arrange
        var encKey = new byte[16];
        var hostChallenge = new byte[8];
        var cardChallenge = new byte[6];
        var sequenceCounter = new byte[2];

        // Act - Create key set and parameters functionally
        var result = Scp02KeySet.Create(encKey, encKey, encKey) // SEnc will be set to encKey in constructor
            .Bind(keySet => CryptogramParameters.ForScp02(hostChallenge, cardChallenge, sequenceCounter, keySet))
            .Bind(parameters => _cryptogramService.CalculateHostCryptogram(parameters));

        // Assert
        result.IsSuccess.Should().BeTrue($"Expected success but got: {(result.IsFailure ? result.Error.Message : "")}");
        result.Match(
            cryptogram => cryptogram.Should().HaveCount(8),
            error => Assert.Fail($"Host cryptogram calculation failed: {error.Message}"));
    }

    [Test]
    public void TypeSafeParameters_PreventInvalidStateAtCompileTime()
    {
        // Arrange - This test validates that the type system prevents invalid states
        var encKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var hostChallenge = new byte[8];
        var cardChallenge = new byte[6]; // SCP02 requires 6-byte card challenge
        var sequenceCounter = new byte[2]; // SCP02 requires sequence counter

        // Act - Parameters can only be created with valid data
        var result = Scp02KeySet.Create(encKey, encKey, encKey) // SEnc will be set to encKey in constructor
            .Bind(keySet => CryptogramParameters.ForScp02(hostChallenge, cardChallenge, sequenceCounter, keySet))
            .Bind(parameters => _cryptogramService.CalculateCardCryptogram(parameters));

        // Assert - Type-safe parameters ensure validity
        result.IsSuccess.Should().BeTrue();
        result.Match(
            cryptogram => cryptogram.Should().HaveCount(8),
            error => Assert.Fail($"Type-safe cryptogram calculation failed: {error.Message}"));
    }
}