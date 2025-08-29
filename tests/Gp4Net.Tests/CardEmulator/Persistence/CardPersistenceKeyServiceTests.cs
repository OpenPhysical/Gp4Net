using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Persistence;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using NUnit.Framework;

namespace Gp4Net.Tests.CardEmulator.Persistence;

/// <summary>
/// Tests for CardPersistenceKeyService functionality.
/// Verifies KDF108-based key derivation, UUID generation, and key fingerprinting.
/// </summary>
[TestFixture]
public class CardPersistenceKeyServiceTests
{
    private CardPersistenceKeyService _service;

    [SetUp]
    public void SetUp()
    {
        _service = new CardPersistenceKeyService();
    }

    [Test]
    public void GenerateCardUuid_ReturnsSuccessResult()
    {
        Result<CardUuid, SmartCardError> result = _service.GenerateCardUuid();

        result.Should().BeSuccess();
        result.Match(
            uuid => uuid.IsEmpty.Should().BeFalse(),
            error => Assert.Fail($"Expected success but got error: {error.Message}")
        );
    }

    [Test]
    public void GenerateCardUuid_ProducesUniqueUuids()
    {
        Result<CardUuid, SmartCardError> result1 = _service.GenerateCardUuid();
        Result<CardUuid, SmartCardError> result2 = _service.GenerateCardUuid();

        result1.Should().BeSuccess();
        result2.Should().BeSuccess();

        result1.Match(
            uuid1 => result2.Match(
                uuid2 => uuid1.Should().NotBe(uuid2),
                error => Assert.Fail($"Failed to generate second UUID: {error.Message}")
            ),
            error => Assert.Fail($"Failed to generate first UUID: {error.Message}")
        );
    }

    [Test]
    public void DeriveStorageKey_WithScp02SingleKey_ReturnsValidKey()
    {
        // Arrange
        byte[] encKey = new byte[16] { 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43 };
        Scp02KeySet keySet = new Scp02KeySet(encKey, encKey, encKey); // Single key scenario
        Result<CardUuid, SmartCardError> uuidResult = CardUuid.Generate();

        uuidResult.Should().BeSuccess();

        uuidResult.Match(
            uuid =>
            {
                // Act
                Result<byte[], SmartCardError> result = _service.DeriveStorageKey(keySet, uuid);

                // Assert
                result.Should().BeSuccess();
                result.Match(
                    derivedKey =>
                    {
                        _ = derivedKey.Length.Should().Be(32); // 256-bit key
                        _ = derivedKey.Should().NotBeEquivalentTo(new byte[32]); // Should not be all zeros
                    },
                    error => Assert.Fail($"Key derivation failed: {error.Message}")
                );
            },
            error => Assert.Fail($"UUID generation failed: {error.Message}")
        );
    }

    [Test]
    public void DeriveStorageKey_WithScp02TripleKey_ReturnsValidKey()
    {
        // Arrange
        byte[] encKey = new byte[16] { 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43 };
        byte[] macKey = new byte[16] { 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53 };
        byte[] dekKey = new byte[16] { 0x60, 0x61, 0x62, 0x63, 0x60, 0x61, 0x62, 0x63, 0x60, 0x61, 0x62, 0x63, 0x60, 0x61, 0x62, 0x63 };
        Scp02KeySet keySet = new Scp02KeySet(encKey, macKey, dekKey);
        Result<CardUuid, SmartCardError> uuidResult = CardUuid.Generate();

        uuidResult.Should().BeSuccess();

        uuidResult.Match(
            uuid =>
            {
                // Act
                Result<byte[], SmartCardError> result = _service.DeriveStorageKey(keySet, uuid);

                // Assert
                result.Should().BeSuccess();
                result.Match(
                    derivedKey =>
                    {
                        _ = derivedKey.Length.Should().Be(32);
                        _ = derivedKey.Should().NotBeEquivalentTo(new byte[32]);
                    },
                    error => Assert.Fail($"Key derivation failed: {error.Message}")
                );
            },
            error => Assert.Fail($"UUID generation failed: {error.Message}")
        );
    }

    [Test]
    public void DeriveStorageKey_WithScp02NoDek_ReturnsValidKey()
    {
        // Arrange - SCP02 without DEK key
        byte[] encKey = new byte[16] { 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43 };
        byte[] macKey = new byte[16] { 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53 };
        Scp02KeySet keySet = new Scp02KeySet(encKey, macKey, null); // No DEK
        Result<CardUuid, SmartCardError> uuidResult = CardUuid.Generate();

        uuidResult.Should().BeSuccess();

        uuidResult.Match(
            uuid =>
            {
                // Act
                Result<byte[], SmartCardError> result = _service.DeriveStorageKey(keySet, uuid);

                // Assert
                result.Should().BeSuccess();
                result.Match(
                    derivedKey =>
                    {
                        _ = derivedKey.Length.Should().Be(32);
                        _ = derivedKey.Should().NotBeEquivalentTo(new byte[32]);
                    },
                    error => Assert.Fail($"Key derivation failed: {error.Message}")
                );
            },
            error => Assert.Fail($"UUID generation failed: {error.Message}")
        );
    }

    [Test]
    public void DeriveStorageKey_WithScp03Aes128_ReturnsValidKey()
    {
        // Arrange
        byte[] encKey = new byte[16] { 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43 };
        byte[] macKey = new byte[16] { 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53 };
        byte[] dekKey = new byte[16] { 0x60, 0x61, 0x62, 0x63, 0x60, 0x61, 0x62, 0x63, 0x60, 0x61, 0x62, 0x63, 0x60, 0x61, 0x62, 0x63 };
        Scp03KeySet keySet = new Scp03KeySet(encKey, macKey, dekKey);
        Result<CardUuid, SmartCardError> uuidResult = CardUuid.Generate();

        uuidResult.Should().BeSuccess();

        uuidResult.Match(
            uuid =>
            {
                // Act
                Result<byte[], SmartCardError> result = _service.DeriveStorageKey(keySet, uuid);

                // Assert
                result.Should().BeSuccess();
                result.Match(
                    derivedKey =>
                    {
                        _ = derivedKey.Length.Should().Be(32);
                        _ = derivedKey.Should().NotBeEquivalentTo(new byte[32]);
                    },
                    error => Assert.Fail($"Key derivation failed: {error.Message}")
                );
            },
            error => Assert.Fail($"UUID generation failed: {error.Message}")
        );
    }

    [Test]
    public void DeriveStorageKey_WithScp03Aes256_ReturnsValidKey()
    {
        // Arrange - Use functional approach to create test keys
        byte[] encKey = Enumerable.Range(0, 32).Select(i => (byte)(0x40 + (i % 16))).ToArray();
        byte[] macKey = Enumerable.Range(0, 32).Select(i => (byte)(0x50 + (i % 16))).ToArray();
        byte[] dekKey = Enumerable.Range(0, 32).Select(i => (byte)(0x60 + (i % 16))).ToArray();
        
        Scp03KeySet keySet = new Scp03KeySet(encKey, macKey, dekKey);
        Result<CardUuid, SmartCardError> uuidResult = CardUuid.Generate();

        uuidResult.Should().BeSuccess();

        uuidResult.Match(
            uuid =>
            {
                // Act
                Result<byte[], SmartCardError> result = _service.DeriveStorageKey(keySet, uuid);

                // Assert
                result.Should().BeSuccess();
                result.Match(
                    derivedKey =>
                    {
                        _ = derivedKey.Length.Should().Be(32);
                        _ = derivedKey.Should().NotBeEquivalentTo(new byte[32]);
                    },
                    error => Assert.Fail($"Key derivation failed: {error.Message}")
                );
            },
            error => Assert.Fail($"UUID generation failed: {error.Message}")
        );
    }

    [Test]
    public void DeriveStorageKey_WithScp03NoDek_ReturnsValidKey()
    {
        // Arrange - SCP03 without DEK key
        byte[] encKey = new byte[16] { 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43 };
        byte[] macKey = new byte[16] { 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53 };
        Scp03KeySet keySet = new Scp03KeySet(encKey, macKey, null); // No DEK
        Result<CardUuid, SmartCardError> uuidResult = CardUuid.Generate();

        uuidResult.Should().BeSuccess();

        uuidResult.Match(
            uuid =>
            {
                // Act
                Result<byte[], SmartCardError> result = _service.DeriveStorageKey(keySet, uuid);

                // Assert
                result.Should().BeSuccess();
                result.Match(
                    derivedKey =>
                    {
                        _ = derivedKey.Length.Should().Be(32);
                        _ = derivedKey.Should().NotBeEquivalentTo(new byte[32]);
                    },
                    error => Assert.Fail($"Key derivation failed: {error.Message}")
                );
            },
            error => Assert.Fail($"UUID generation failed: {error.Message}")
        );
    }

    [Test]
    public void DeriveStorageKey_SameInputs_ProducesSameKey()
    {
        // Arrange
        byte[] encKey = new byte[16] { 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43 };
        Scp02KeySet keySet = new Scp02KeySet(encKey, encKey, encKey);
        Result<CardUuid, SmartCardError> uuidResult = CardUuid.Generate();

        uuidResult.Should().BeSuccess();

        uuidResult.Match(
            uuid =>
            {
                // Act - derive same key twice
                Result<byte[], SmartCardError> result1 = _service.DeriveStorageKey(keySet, uuid);
                Result<byte[], SmartCardError> result2 = _service.DeriveStorageKey(keySet, uuid);

                // Assert
                result1.Should().BeSuccess();
                result2.Should().BeSuccess();

                result1.Match(
                    key1 => result2.Match(
                        key2 => key1.Should().BeEquivalentTo(key2),
                        error => Assert.Fail($"Second key derivation failed: {error.Message}")
                    ),
                    error => Assert.Fail($"First key derivation failed: {error.Message}")
                );
            },
            error => Assert.Fail($"UUID generation failed: {error.Message}")
        );
    }

    [Test]
    public void DeriveStorageKey_DifferentUuids_ProduceDifferentKeys()
    {
        // Arrange
        byte[] encKey = new byte[16] { 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43 };
        Scp02KeySet keySet = new Scp02KeySet(encKey, encKey, encKey);
        Result<CardUuid, SmartCardError> uuid1Result = CardUuid.Generate();
        Result<CardUuid, SmartCardError> uuid2Result = CardUuid.Generate();

        uuid1Result.Should().BeSuccess();
        uuid2Result.Should().BeSuccess();

        uuid1Result.Match(
            uuid1 => uuid2Result.Match(
                uuid2 =>
                {
                    // Act
                    Result<byte[], SmartCardError> result1 = _service.DeriveStorageKey(keySet, uuid1);
                    Result<byte[], SmartCardError> result2 = _service.DeriveStorageKey(keySet, uuid2);

                    // Assert
                    result1.Should().BeSuccess();
                    result2.Should().BeSuccess();

                    result1.Match(
                        key1 => result2.Match(
                            key2 => key1.Should().NotBeEquivalentTo(key2),
                            error => Assert.Fail($"Second key derivation failed: {error.Message}")
                        ),
                        error => Assert.Fail($"First key derivation failed: {error.Message}")
                    );
                },
                error => Assert.Fail($"Second UUID generation failed: {error.Message}")
            ),
            error => Assert.Fail($"First UUID generation failed: {error.Message}")
        );
    }

    [Test]
    public void DeriveStorageKey_DifferentKeySets_ProduceDifferentKeys()
    {
        // Arrange
        byte[] encKey1 = new byte[16] { 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43 };
        byte[] encKey2 = new byte[16] { 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53 };
        Scp02KeySet keySet1 = new Scp02KeySet(encKey1, encKey1, encKey1);
        Scp02KeySet keySet2 = new Scp02KeySet(encKey2, encKey2, encKey2);
        Result<CardUuid, SmartCardError> uuidResult = CardUuid.Generate();

        uuidResult.Should().BeSuccess();

        uuidResult.Match(
            uuid =>
            {
                // Act
                Result<byte[], SmartCardError> result1 = _service.DeriveStorageKey(keySet1, uuid);
                Result<byte[], SmartCardError> result2 = _service.DeriveStorageKey(keySet2, uuid);

                // Assert
                result1.Should().BeSuccess();
                result2.Should().BeSuccess();

                result1.Match(
                    key1 => result2.Match(
                        key2 => key1.Should().NotBeEquivalentTo(key2),
                        error => Assert.Fail($"Second key derivation failed: {error.Message}")
                    ),
                    error => Assert.Fail($"First key derivation failed: {error.Message}")
                );
            },
            error => Assert.Fail($"UUID generation failed: {error.Message}")
        );
    }

    [Test]
    public void ComputeKeyFingerprint_WithScp02KeySet_ReturnsValidFingerprint()
    {
        // Arrange
        byte[] encKey = new byte[16] { 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43 };
        byte[] macKey = new byte[16] { 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53 };
        byte[] dekKey = new byte[16] { 0x60, 0x61, 0x62, 0x63, 0x60, 0x61, 0x62, 0x63, 0x60, 0x61, 0x62, 0x63, 0x60, 0x61, 0x62, 0x63 };
        Scp02KeySet keySet = new Scp02KeySet(encKey, macKey, dekKey);

        // Act
        Result<byte[], SmartCardError> result = _service.ComputeKeyFingerprint(keySet);

        // Assert
        result.Should().BeSuccess();
        result.Match(
            fingerprint =>
            {
                _ = fingerprint.Length.Should().Be(32); // SHA-256 hash
                _ = fingerprint.Should().NotBeEquivalentTo(new byte[32]);
            },
            error => Assert.Fail($"Fingerprint computation failed: {error.Message}")
        );
    }

    [Test]
    public void ComputeKeyFingerprint_WithScp03KeySet_ReturnsValidFingerprint()
    {
        // Arrange
        byte[] encKey = new byte[16] { 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43 };
        byte[] macKey = new byte[16] { 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53, 0x50, 0x51, 0x52, 0x53 };
        byte[] dekKey = new byte[16] { 0x60, 0x61, 0x62, 0x63, 0x60, 0x61, 0x62, 0x63, 0x60, 0x61, 0x62, 0x63, 0x60, 0x61, 0x62, 0x63 };
        Scp03KeySet keySet = new Scp03KeySet(encKey, macKey, dekKey);

        // Act
        Result<byte[], SmartCardError> result = _service.ComputeKeyFingerprint(keySet);

        // Assert
        result.Should().BeSuccess();
        result.Match(
            fingerprint =>
            {
                _ = fingerprint.Length.Should().Be(32); // SHA-256 hash
                _ = fingerprint.Should().NotBeEquivalentTo(new byte[32]);
            },
            error => Assert.Fail($"Fingerprint computation failed: {error.Message}")
        );
    }

    [Test]
    public void ComputeKeyFingerprint_SameKeySet_ProducesSameFingerprint()
    {
        // Arrange
        byte[] encKey = new byte[16] { 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43 };
        Scp02KeySet keySet = new Scp02KeySet(encKey, encKey, encKey);

        // Act
        Result<byte[], SmartCardError> result1 = _service.ComputeKeyFingerprint(keySet);
        Result<byte[], SmartCardError> result2 = _service.ComputeKeyFingerprint(keySet);

        // Assert
        result1.Should().BeSuccess();
        result2.Should().BeSuccess();

        result1.Match(
            fingerprint1 => result2.Match(
                fingerprint2 => fingerprint1.Should().BeEquivalentTo(fingerprint2),
                error => Assert.Fail($"Second fingerprint computation failed: {error.Message}")
            ),
            error => Assert.Fail($"First fingerprint computation failed: {error.Message}")
        );
    }

    [Test]
    public void ValidateKeyFingerprint_WithCorrectFingerprint_ReturnsTrue()
    {
        // Arrange
        byte[] encKey = new byte[16] { 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43 };
        Scp02KeySet keySet = new Scp02KeySet(encKey, encKey, encKey);
        Result<byte[], SmartCardError> computeResult = _service.ComputeKeyFingerprint(keySet);

        computeResult.Should().BeSuccess();

        computeResult.Match(
            expectedFingerprint =>
            {
                // Act
                Result<bool, SmartCardError> result = _service.ValidateKeyFingerprint(keySet, expectedFingerprint);

                // Assert
                result.Should().BeSuccess();
                result.Match(
                    isValid => isValid.Should().BeTrue(),
                    error => Assert.Fail($"Fingerprint validation failed: {error.Message}")
                );
            },
            error => Assert.Fail($"Fingerprint computation failed: {error.Message}")
        );
    }

    [Test]
    public void ValidateKeyFingerprint_WithIncorrectFingerprint_ReturnsFalse()
    {
        // Arrange
        byte[] encKey = new byte[16] { 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43 };
        Scp02KeySet keySet = new Scp02KeySet(encKey, encKey, encKey);
        byte[] wrongFingerprint = new byte[32]; // All zeros

        // Act
        Result<bool, SmartCardError> result = _service.ValidateKeyFingerprint(keySet, wrongFingerprint);

        // Assert
        result.Should().BeSuccess();
        result.Match(
            isValid => isValid.Should().BeFalse(),
            error => Assert.Fail($"Fingerprint validation failed: {error.Message}")
        );
    }

    [Test]
    public void DeriveStorageKey_WithNullKeySet_ReturnsFailure()
    {
        // Arrange
        Result<CardUuid, SmartCardError> uuidResult = CardUuid.Generate();

        uuidResult.Should().BeSuccess();

        uuidResult.Match(
            uuid =>
            {
                // Act
                Result<byte[], SmartCardError> result = _service.DeriveStorageKey(null, uuid);

                // Assert
                result.Should().BeFailure();
                _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
            },
            error => Assert.Fail($"UUID generation failed: {error.Message}")
        );
    }

    [Test]
    public void DeriveStorageKey_WithEmptyUuid_ReturnsFailure()
    {
        // Arrange
        byte[] encKey = new byte[16] { 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43, 0x40, 0x41, 0x42, 0x43 };
        Scp02KeySet keySet = new Scp02KeySet(encKey, encKey, encKey);
        CardUuid emptyUuid = CardUuid.Empty;

        // Act
        Result<byte[], SmartCardError> result = _service.DeriveStorageKey(keySet, emptyUuid);

        // Assert
        result.Should().BeFailure();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
    }

    [Test]
    public void ComputeKeyFingerprint_WithNullKeySet_ReturnsFailure()
    {
        // Act
        Result<byte[], SmartCardError> result = _service.ComputeKeyFingerprint(null);

        // Assert
        result.Should().BeFailure();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
    }

}