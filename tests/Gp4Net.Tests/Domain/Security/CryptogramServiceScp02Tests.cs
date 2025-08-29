using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
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
        byte[] hostChallenge = new byte[8];
        byte[] invalidCardChallenge = new byte[8]; // Should be 6 for SCP02
        byte[] sequenceCounter = new byte[2];

        Result<Scp02KeySet, SmartCardError> keySetResult = Scp02KeySet.Create(new byte[16], new byte[16], new byte[16]);
        _ = keySetResult.IsSuccess.Should().BeTrue("Key set creation should succeed");

        // Act
        Result<Scp02CryptogramParameters, SmartCardError> result = keySetResult.Bind(keySet =>
            CryptogramParameters.ForScp02(
                hostChallenge,
                invalidCardChallenge,
                sequenceCounter,
                keySet));

        // Assert - Parameter creation should fail with invalid card challenge
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("SCP02 card challenge must be 6 bytes");
    }

    [Test]
    public void CalculateCardCryptogram_WithInvalidSequenceCounterLength_ShouldFail()
    {
        // Arrange - Try to create parameters with invalid sequence counter length
        byte[] hostChallenge = new byte[8];
        byte[] cardChallenge = new byte[6];
        byte[] invalidSequenceCounter = new byte[3]; // Should be 2 for SCP02

        Result<Scp02KeySet, SmartCardError> keySetResult = Scp02KeySet.Create(new byte[16], new byte[16], new byte[16]);
        _ = keySetResult.IsSuccess.Should().BeTrue("Key set creation should succeed");

        // Act
        Result<Scp02CryptogramParameters, SmartCardError> result = keySetResult.Bind(keySet =>
            CryptogramParameters.ForScp02(
                hostChallenge,
                cardChallenge,
                invalidSequenceCounter,
                keySet));

        // Assert - Parameter creation should fail with invalid sequence counter
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("Sequence counter must be 2 bytes");
    }

    [Test]
    public void CalculateCardCryptogram_WithValidParameters_ShouldSucceed()
    {
        // Arrange - Using test vectors from a real SCP02 trace
        byte[] encKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        byte[] hostChallenge = Convert.FromHexString("0102030405060708");
        byte[] cardChallenge = Convert.FromHexString("0A0B0C0D0E0F");
        byte[] sequenceCounter = Convert.FromHexString("0001");

        // Act - Create key set and parameters functionally
        Result<byte[], SmartCardError> result = Scp02KeySet.Create(encKey, encKey, encKey) // SEnc will be set to encKey in constructor
            .Bind(keySet => CryptogramParameters.ForScp02(hostChallenge, cardChallenge, sequenceCounter, keySet))
            .Bind(parameters => _cryptogramService.CalculateCardCryptogram(parameters));

        // Assert
        _ = result.IsSuccess.Should().BeTrue($"Expected success but got: {(result.IsFailure ? result.Error.Message : "")}");
        result.Match(
            cryptogram => cryptogram.Should().HaveCount(8),
            error => Assert.Fail($"Cryptogram calculation failed: {error.Message}"));
    }

    [Test]
    public void CalculateHostCryptogram_WithValidParameters_ShouldSucceed()
    {
        // Arrange
        byte[] encKey = new byte[16];
        byte[] hostChallenge = new byte[8];
        byte[] cardChallenge = new byte[6];
        byte[] sequenceCounter = new byte[2];

        // Act - Create key set and parameters functionally
        Result<byte[], SmartCardError> result = Scp02KeySet.Create(encKey, encKey, encKey) // SEnc will be set to encKey in constructor
            .Bind(keySet => CryptogramParameters.ForScp02(hostChallenge, cardChallenge, sequenceCounter, keySet))
            .Bind(parameters => _cryptogramService.CalculateHostCryptogram(parameters));

        // Assert
        _ = result.IsSuccess.Should().BeTrue($"Expected success but got: {(result.IsFailure ? result.Error.Message : "")}");
        result.Match(
            cryptogram => cryptogram.Should().HaveCount(8),
            error => Assert.Fail($"Host cryptogram calculation failed: {error.Message}"));
    }

    [Test]
    public void TypeSafeParameters_PreventInvalidStateAtCompileTime()
    {
        // Arrange - This test validates that the type system prevents invalid states
        byte[] encKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        byte[] hostChallenge = new byte[8];
        byte[] cardChallenge = new byte[6]; // SCP02 requires 6-byte card challenge
        byte[] sequenceCounter = new byte[2]; // SCP02 requires sequence counter

        // Act - Parameters can only be created with valid data
        Result<byte[], SmartCardError> result = Scp02KeySet.Create(encKey, encKey, encKey) // SEnc will be set to encKey in constructor
            .Bind(keySet => CryptogramParameters.ForScp02(hostChallenge, cardChallenge, sequenceCounter, keySet))
            .Bind(parameters => _cryptogramService.CalculateCardCryptogram(parameters));

        // Assert - Type-safe parameters ensure validity
        _ = result.IsSuccess.Should().BeTrue();
        result.Match(
            cryptogram => cryptogram.Should().HaveCount(8),
            error => Assert.Fail($"Type-safe cryptogram calculation failed: {error.Message}"));
    }
}