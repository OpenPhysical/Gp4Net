using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Security;

/// <summary>
/// Tests for SCP02 cryptogram calculations to ensure sequence counter is properly handled.
/// These tests will detect if SCP02 support is missing or broken.
/// </summary>
public class CryptogramServiceScp02Tests
{
    private readonly CryptogramService _cryptogramService;

    public CryptogramServiceScp02Tests()
    {
        _cryptogramService = new CryptogramService();
    }

    [Test]
    public void CalculateCardCryptogram_WithoutSequenceCounter_ShouldFail()
    {
        // Arrange
        var key = new byte[16];
        var hostChallenge = new byte[8];
        var cardChallenge = new byte[6]; // SCP02 uses 6-byte card challenge
        var sequenceCounter = Maybe<byte[]>.None; // Missing sequence counter

        // Act
        var result = _cryptogramService.CalculateCardCryptogram(
            key,
            hostChallenge,
            cardChallenge,
            sequenceCounter,
            ScpVersion.Scp02);

        // Assert - This test MUST fail if SCP02 is not properly supported
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("SCP02 card cryptogram requires sequence counter");
    }

    [Test]
    public void CalculateCardCryptogram_WithInvalidSequenceCounterLength_ShouldFail()
    {
        // Arrange
        var key = new byte[16];
        var hostChallenge = new byte[8];
        var cardChallenge = new byte[6];
        var sequenceCounter = Maybe<byte[]>.From(new byte[3]); // Wrong length (should be 2)

        // Act
        var result = _cryptogramService.CalculateCardCryptogram(
            key,
            hostChallenge,
            cardChallenge,
            sequenceCounter,
            ScpVersion.Scp02);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("SCP02 sequence counter must be 2 bytes");
    }

    [Test]
    public void CalculateCardCryptogram_WithValidSequenceCounter_ShouldSucceed()
    {
        // Arrange - Using test vectors from a real SCP02 trace
        var key = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var hostChallenge = Convert.FromHexString("0102030405060708");
        var cardChallenge = Convert.FromHexString("0A0B0C0D0E0F");
        var sequenceCounter = Maybe<byte[]>.From(Convert.FromHexString("0001"));

        // Act
        var result = _cryptogramService.CalculateCardCryptogram(
            key,
            hostChallenge,
            cardChallenge,
            sequenceCounter,
            ScpVersion.Scp02);

        // Assert
        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Should().HaveCount(8); // Cryptogram should be 8 bytes
    }

    [Test]
    public void CalculateHostCryptogram_WithoutSequenceCounter_ShouldFail()
    {
        // Arrange
        var key = new byte[16];
        var hostChallenge = new byte[8];
        var cardChallenge = new byte[6];
        var sequenceCounter = Maybe<byte[]>.None;

        // Act
        var result = _cryptogramService.CalculateHostCryptogram(
            key,
            hostChallenge,
            cardChallenge,
            sequenceCounter,
            ScpVersion.Scp02);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("SCP02 host cryptogram requires sequence counter");
    }

    [Test]
    public void CalculateCardCryptogram_WithWrongCardChallengeLength_ShouldFail()
    {
        // Arrange
        var key = new byte[16];
        var hostChallenge = new byte[8];
        var cardChallenge = new byte[8]; // Wrong! SCP02 uses 6-byte card challenge
        var sequenceCounter = Maybe<byte[]>.From(new byte[2]);

        // Act
        var result = _cryptogramService.CalculateCardCryptogram(
            key,
            hostChallenge,
            cardChallenge,
            sequenceCounter,
            ScpVersion.Scp02);

        // Assert
        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Message.Should().Contain("SCP02 card challenge must be 6 bytes");
    }

    [Test]
    public void CalculateCryptogram_GenericMethod_DoesNotRequireSequenceCounter()
    {
        // Arrange - Generic cryptogram method should still work for C-MAC/R-MAC
        // Use GP test key instead of all zeros
        var key = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var data = new byte[16]; // 16-byte data (can be zeros for test)
        
        // Act
        var result = _cryptogramService.CalculateCryptogram(
            key,
            data,
            ScpVersion.Scp02);

        // Assert - Generic method should work without sequence counter
        _ = result.IsSuccess.Should().BeTrue($"Expected success but got error: {(result.IsFailure ? result.Error.Message : "unknown")}");
        if (result.IsSuccess)
        {
            _ = result.Value.Should().HaveCount(8);
        }
    }
}