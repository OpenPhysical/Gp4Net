using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Keys;

/// <summary>
/// Tests for SCP02 base key mode (b1=0) to ensure correct key derivation behavior.
/// </summary>
[TestFixture]
[Category("Unit")]
[Category("FailHard")]
public class Scp02BaseKeyModeTests
{
    [Test]
    public void Scp02_BaseKeyMode_Should_Use_Respective_Keys_Not_Just_Enc()
    {
        // Arrange - Use different keys to expose the bug if it exists
        byte[] encKey = Convert.FromHexString("0123456789ABCDEF1234567890ABCDEF");
        byte[] macKey = Convert.FromHexString("FEDCBA9876543210ABCDEF0987654321");
        byte[] dekKey = Convert.FromHexString("1122334455667788AABBCCDDEEFF1122");

        Result<Scp02KeySet, SmartCardError> keySetResult = Scp02KeySet.Create(
            encKey,
            macKey,
            dekKey,
            0x01
        );
        _ = keySetResult.IsSuccess.Should().BeTrue();

        byte[] sequenceCounter = Convert.FromHexString("00A5");
        byte[] hostChallenge = Convert.FromHexString("FEDCBA9876543210");
        byte[] cardChallenge = Convert.FromHexString("123456789ABC");
        byte implementationParameter = 0x04; // i=04 (b1=0, base key mode)

        // Act - Derive keys using protocol implementation
        var deriveResult = Scp02ProtocolImpl.DeriveSessionKeys(
            keySetResult.Value,
            hostChallenge,
            cardChallenge,
            sequenceCounter,
            implementationParameter
        );

        // Assert
        _ = deriveResult.IsSuccess.Should().BeTrue();
        var sessionKeys = deriveResult.Value;

        // The fix ensures MAC session key is derived from MAC base key, not ENC key
        byte[] expectedSMac = Convert.FromHexString("82D6C3CC4FE50FC6C4DF470744514496");
        _ = sessionKeys
            .SMac.Should()
            .BeEquivalentTo(
                expectedSMac,
                "MAC session key should be derived from MAC base key, not ENC key"
            );

        // Verify ENC key derivation
        byte[] expectedSEnc = Convert.FromHexString("B1B1E3A7B4FBD9F6BDA5FDDB703C5D47");
        _ = sessionKeys
            .SEnc.Should()
            .BeEquivalentTo(expectedSEnc, "ENC session key should be derived from ENC base key");

        // Verify DEK key derivation
        byte[] expectedSDek = Convert.FromHexString("CAF3D972A7E964D2BCBF868561574637");
        _ = sessionKeys
            .Dek.Should()
            .BeEquivalentTo(expectedSDek, "DEK session key should be derived from DEK base key");
    }

    [Test]
    public void Scp02_BaseKeyMode_With_Same_Keys_Should_Still_Work()
    {
        // Arrange - Use same key for all slots (common scenario)
        byte[] sameKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");

        Result<Scp02KeySet, SmartCardError> keySetResult = Scp02KeySet.Create(
            sameKey,
            sameKey,
            sameKey,
            0x01
        );
        _ = keySetResult.IsSuccess.Should().BeTrue();

        byte[] sequenceCounter = Convert.FromHexString("0001");
        byte[] hostChallenge = Convert.FromHexString("1122334455667788");
        byte[] cardChallenge = Convert.FromHexString("AABBCCDDEE11");
        byte implementationParameter = 0x04; // i=04 (b1=0, base key mode)

        // Act - Derive keys using protocol implementation
        var deriveResult = Scp02ProtocolImpl.DeriveSessionKeys(
            keySetResult.Value,
            hostChallenge,
            cardChallenge,
            sequenceCounter,
            implementationParameter
        );

        // Assert
        _ = deriveResult.IsSuccess.Should().BeTrue();
        var sessionKeys = deriveResult.Value;

        // When all base keys are the same, the result should be consistent
        // regardless of which base key is used
        _ = sessionKeys.SMac.Should().NotBeNull();
        _ = sessionKeys.SEnc.Should().NotBeNull();
        _ = sessionKeys.Dek.Should().NotBeNull();
    }

    [Test]
    public void Scp02_ThreeKeysMode_Should_Use_Derived_Mac_Keys()
    {
        // Arrange - i=05 has b1=1 (3 keys mode)
        byte[] encKey = Convert.FromHexString("9192939495969798999A9B9C9D9E9FA0");
        byte[] macKey = Convert.FromHexString("A1A2A3A4A5A6A7A8A9AAABACADAEAFB0");
        byte[] dekKey = Convert.FromHexString("B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0");

        Result<Scp02KeySet, SmartCardError> keySetResult = Scp02KeySet.Create(
            encKey,
            macKey,
            dekKey,
            0x01
        );
        _ = keySetResult.IsSuccess.Should().BeTrue();

        byte[] sequenceCounter = Convert.FromHexString("0042");
        byte[] hostChallenge = Convert.FromHexString("0011223344556677");
        byte[] cardChallenge = Convert.FromHexString("8899AABBCCDD");
        byte implementationParameter = 0x05; // i=05 (b1=1, 3 keys mode)

        // Act - Derive keys using protocol implementation
        var deriveResult = Scp02ProtocolImpl.DeriveSessionKeys(
            keySetResult.Value,
            hostChallenge,
            cardChallenge,
            sequenceCounter,
            implementationParameter
        );

        // Assert
        _ = deriveResult.IsSuccess.Should().BeTrue();
        var sessionKeys = deriveResult.Value;

        // For i=05, MAC key should be derived (not static)
        byte[] expectedSMac = Convert.FromHexString("8520B9AF247712F7E72BC07D8D920EB3");
        _ = sessionKeys
            .SMac.Should()
            .BeEquivalentTo(expectedSMac, "For i=05 (b1=1), MAC key should be derived");
    }

    // Removed: Scp02ProtocolImpl_DeriveSessionKeys_WithNullKeySet_ShouldFailHard
    // NO NULLS rule - nulls should be converted to Result<T> at boundaries, not checked in domain

    // Removed: Scp02ProtocolImpl_DeriveSessionKeys_WithNullHostChallenge_ShouldFailHard
    // NO NULLS rule - nulls should be converted to Result<T> at boundaries, not checked in domain

    // Removed: Scp02ProtocolImpl_DeriveSessionKeys_WithNullCardChallenge_ShouldFailHard
    // NO NULLS rule - nulls should be converted to Result<T> at boundaries, not checked in domain

    // Removed: Scp02ProtocolImpl_DeriveSessionKeys_WithNullSequenceCounter_ShouldFailHard
    // NO NULLS rule - nulls should be converted to Result<T> at boundaries, not checked in domain

    [Test]
    public void Scp02ProtocolImpl_DeriveSessionKeys_WithInvalidChallengeLength_ShouldFailHard()
    {
        // Arrange
        Scp02KeySet? keySet = Scp02KeySet
            .Create(
                Convert.FromHexString("0123456789ABCDEF1234567890ABCDEF"),
                Convert.FromHexString("FEDCBA9876543210ABCDEF0987654321"),
                Convert.FromHexString("1122334455667788AABBCCDDEEFF1122")
            )
            .Value;
        byte[] sequenceCounter = Convert.FromHexString("0001");
        byte[] cardChallenge = Convert.FromHexString("AABBCCDDEE11");
        byte implementationParameter = 0x05;

        // Test invalid host challenge lengths
        (byte[], string)[] invalidHostChallenges =
        [
            ([], "Empty host challenge"),
            (new byte[4], "4-byte host challenge"),
            (new byte[12], "12-byte host challenge"),
            (new byte[16], "16-byte host challenge"),
        ];

        foreach ((byte[] invalidChallenge, string description) in invalidHostChallenges)
        {
            // Act
            var result = Scp02ProtocolImpl.DeriveSessionKeys(
                keySet,
                invalidChallenge,
                cardChallenge,
                sequenceCounter,
                implementationParameter
            );

            // Assert
            _ = result.IsFailure.Should().BeTrue($"{description} should be rejected");
            _ = result.Error.Should().BeOfType<InvalidLengthError>();
            InvalidLengthError? lengthError = (InvalidLengthError)result.Error;
            _ = lengthError.Expected.Should().Be(8);

            TestContext.Out.WriteLine(
                $"✓ {description} correctly rejected: {result.Error.Message}"
            );
        }

        // Test invalid card challenge lengths
        byte[] hostChallenge = Convert.FromHexString("1122334455667788");
        (byte[], string)[] invalidCardChallenges =
        [
            ([], "Empty card challenge"),
            (new byte[4], "4-byte card challenge"),
            (new byte[8], "8-byte card challenge"),
            (new byte[12], "12-byte card challenge"),
        ];

        foreach ((byte[] invalidChallenge, string description) in invalidCardChallenges)
        {
            // Act
            var result = Scp02ProtocolImpl.DeriveSessionKeys(
                keySet,
                hostChallenge,
                invalidChallenge,
                sequenceCounter,
                implementationParameter
            );

            // Assert
            _ = result.IsFailure.Should().BeTrue($"{description} should be rejected");
            _ = result.Error.Should().BeOfType<InvalidLengthError>();
            InvalidLengthError? lengthError = (InvalidLengthError)result.Error;
            _ = lengthError.Expected.Should().Be(6);

            TestContext.Out.WriteLine(
                $"✓ {description} correctly rejected: {result.Error.Message}"
            );
        }
    }

    [Test]
    public void Scp02ProtocolImpl_DeriveSessionKeys_WithInvalidSequenceCounterLength_ShouldFailHard()
    {
        // Arrange
        Scp02KeySet? keySet = Scp02KeySet
            .Create(
                Convert.FromHexString("0123456789ABCDEF1234567890ABCDEF"),
                Convert.FromHexString("FEDCBA9876543210ABCDEF0987654321"),
                Convert.FromHexString("1122334455667788AABBCCDDEEFF1122")
            )
            .Value;
        byte[] hostChallenge = Convert.FromHexString("1122334455667788");
        byte[] cardChallenge = Convert.FromHexString("AABBCCDDEE11");
        byte implementationParameter = 0x05;

        (byte[], string)[] invalidSequenceCounters =
        [
            ([], "Empty sequence counter"),
            (new byte[1], "1-byte sequence counter"),
            (new byte[3], "3-byte sequence counter"),
            (new byte[4], "4-byte sequence counter"),
        ];

        foreach ((byte[] invalidCounter, string description) in invalidSequenceCounters)
        {
            // Act
            var result = Scp02ProtocolImpl.DeriveSessionKeys(
                keySet,
                hostChallenge,
                cardChallenge,
                invalidCounter,
                implementationParameter
            );

            // Assert
            _ = result.IsFailure.Should().BeTrue($"{description} should be rejected");
            _ = result.Error.Should().BeOfType<InvalidLengthError>();
            InvalidLengthError? lengthError = (InvalidLengthError)result.Error;
            _ = lengthError.Expected.Should().Be(2);

            TestContext.Out.WriteLine(
                $"✓ {description} correctly rejected: {result.Error.Message}"
            );
        }
    }

    [Test]
    public void Scp02ProtocolImpl_DeriveSessionKeys_WithInvalidImplementationParameter_ShouldFailHard()
    {
        // Arrange
        Scp02KeySet? keySet = Scp02KeySet
            .Create(
                Convert.FromHexString("0123456789ABCDEF1234567890ABCDEF"),
                Convert.FromHexString("FEDCBA9876543210ABCDEF0987654321"),
                Convert.FromHexString("1122334455667788AABBCCDDEEFF1122")
            )
            .Value;
        byte[] hostChallenge = Convert.FromHexString("1122334455667788");
        byte[] cardChallenge = Convert.FromHexString("AABBCCDDEE11");
        byte[] sequenceCounter = Convert.FromHexString("0001");

        // Test invalid implementation parameters that should fail hard
        byte[] invalidImplementations = [0x01, 0x03, 0x06, 0x08, 0x99, 0xFF];

        foreach (byte invalidImpl in invalidImplementations)
        {
            // Act
            var result = Scp02ProtocolImpl.DeriveSessionKeys(
                keySet,
                hostChallenge,
                cardChallenge,
                sequenceCounter,
                invalidImpl
            );

            // Assert
            _ = result
                .IsFailure.Should()
                .BeTrue($"Invalid implementation i={invalidImpl:X2} should be rejected");
            _ = result.Error.Should().BeOfType<UnsupportedImplementationError>();
            _ = result
                .Error.Message.Should()
                .Contain(
                    $"i={invalidImpl:X2}",
                    $"Error should identify invalid implementation i={invalidImpl:X2}"
                );

            TestContext.Out.WriteLine(
                $"✓ Invalid implementation i={invalidImpl:X2} correctly rejected: {result.Error.Message}"
            );
        }
    }
}
