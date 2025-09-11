using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Persistence;
using Gp4Net.Domain.Keys;
using NUnit.Framework;

namespace Gp4Net.CardEmulator.Tests.Persistence;

/// <summary>
/// Tests for CardPersistenceKeyService functionality.
/// Verifies KDF108-based key derivation, UUID generation, and key fingerprinting.
/// </summary>
[TestFixture]
public class CardPersistenceKeyServiceTests
{
    // @TODO THIS NEEDS TO BE IMMUTABLE
    private CardPersistenceKeyService _service;

    [SetUp]
    public void SetUp()
    {
        _service = new CardPersistenceKeyService();
    }

    [Test]
    public void GenerateCardUuid_ReturnsSuccessResult()
    {
        var result = _service.GenerateCardUuid();

        result.IsSuccess.Should().BeTrue();
        result.Match(
            uuid => uuid.IsEmpty.Should().BeFalse(),
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public void GenerateCardUuid_ProducesUniqueUuids()
    {
        var result1 = _service.GenerateCardUuid();
        var result2 = _service.GenerateCardUuid();

        result1.IsSuccess.Should().BeTrue();
        result2.IsSuccess.Should().BeTrue();

        result1.Match(
            uuid1 =>
                result2.Match(
                    uuid2 => uuid1.Should().NotBe(uuid2),
                    error => Assert.Fail($"Failed to generate second UUID: {error}")
                ),
            error => Assert.Fail($"Failed to generate first UUID: {error}")
        );
    }

    [Test]
    public void DeriveStorageKey_WithScp02SingleKey_ReturnsValidKey()
    {
        // Arrange
        byte[] encKey = new byte[16]
        {
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
        };
        var keySet = Scp02KeySet.Create(encKey, encKey, encKey).Value; // Single key scenario
        var uuidResult = CardUuid.Generate();

        uuidResult.IsSuccess.Should().BeTrue();

        uuidResult.Match(
            uuid =>
            {
                // Act
                var result = _service.DeriveStorageKey(keySet, uuid);

                // Assert
                result.IsSuccess.Should().BeTrue();
                result.Match(
                    derivedKey =>
                    {
                        _ = derivedKey.Length.Should().Be(32); // 256-bit key
                        _ = derivedKey.Should().NotBeEquivalentTo(new byte[32]); // Should not be all zeros
                    },
                    error => Assert.Fail($"Key derivation failed: {error}")
                );
            },
            error => Assert.Fail($"UUID generation failed: {error}")
        );
    }

    [Test]
    public void DeriveStorageKey_WithScp02TripleKey_ReturnsValidKey()
    {
        // Arrange
        byte[] encKey = new byte[16]
        {
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
        };
        byte[] macKey = new byte[16]
        {
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
        };
        byte[] dekKey = new byte[16]
        {
            0x60,
            0x61,
            0x62,
            0x63,
            0x60,
            0x61,
            0x62,
            0x63,
            0x60,
            0x61,
            0x62,
            0x63,
            0x60,
            0x61,
            0x62,
            0x63,
        };
        var keySet = Scp02KeySet.Create(encKey, macKey, dekKey).Value;
        var uuidResult = CardUuid.Generate();

        uuidResult.IsSuccess.Should().BeTrue();

        uuidResult.Match(
            uuid =>
            {
                // Act
                var result = _service.DeriveStorageKey(keySet, uuid);

                // Assert
                result.IsSuccess.Should().BeTrue();
                result.Match(
                    derivedKey =>
                    {
                        _ = derivedKey.Length.Should().Be(32);
                        _ = derivedKey.Should().NotBeEquivalentTo(new byte[32]);
                    },
                    error => Assert.Fail($"Key derivation failed: {error}")
                );
            },
            error => Assert.Fail($"UUID generation failed: {error}")
        );
    }

    [Test]
    public void DeriveStorageKey_WithScp02NoDek_ReturnsValidKey()
    {
        // Arrange - SCP02 without DEK key
        byte[] encKey = new byte[16]
        {
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
        };
        byte[] macKey = new byte[16]
        {
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
        };
        var keySet = Scp02KeySet.Create(encKey, macKey, new byte[16]).Value; // No DEK
        var uuidResult = CardUuid.Generate();

        uuidResult.IsSuccess.Should().BeTrue();

        uuidResult.Match(
            uuid =>
            {
                // Act
                var result = _service.DeriveStorageKey(keySet, uuid);

                // Assert
                result.IsSuccess.Should().BeTrue();
                result.Match(
                    derivedKey =>
                    {
                        _ = derivedKey.Length.Should().Be(32);
                        _ = derivedKey.Should().NotBeEquivalentTo(new byte[32]);
                    },
                    error => Assert.Fail($"Key derivation failed: {error}")
                );
            },
            error => Assert.Fail($"UUID generation failed: {error}")
        );
    }

    [Test]
    public void DeriveStorageKey_WithScp03Aes128_ReturnsValidKey()
    {
        // Arrange
        byte[] encKey = new byte[16]
        {
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
        };
        byte[] macKey = new byte[16]
        {
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
        };
        byte[] dekKey = new byte[16]
        {
            0x60,
            0x61,
            0x62,
            0x63,
            0x60,
            0x61,
            0x62,
            0x63,
            0x60,
            0x61,
            0x62,
            0x63,
            0x60,
            0x61,
            0x62,
            0x63,
        };
        var keySet = new Scp03KeySet(encKey, macKey, dekKey);
        var uuidResult = CardUuid.Generate();

        uuidResult.IsSuccess.Should().BeTrue();

        uuidResult.Match(
            uuid =>
            {
                // Act
                var result = _service.DeriveStorageKey(keySet, uuid);

                // Assert
                result.IsSuccess.Should().BeTrue();
                result.Match(
                    derivedKey =>
                    {
                        _ = derivedKey.Length.Should().Be(32);
                        _ = derivedKey.Should().NotBeEquivalentTo(new byte[32]);
                    },
                    error => Assert.Fail($"Key derivation failed: {error}")
                );
            },
            error => Assert.Fail($"UUID generation failed: {error}")
        );
    }

    [Test]
    public void DeriveStorageKey_WithScp03Aes256_ReturnsValidKey()
    {
        // Arrange - Use functional approach to create test keys
        byte[] encKey = [.. Enumerable.Range(0, 32).Select(i => (byte)(0x40 + i % 16))];
        byte[] macKey = [.. Enumerable.Range(0, 32).Select(i => (byte)(0x50 + i % 16))];
        byte[] dekKey = [.. Enumerable.Range(0, 32).Select(i => (byte)(0x60 + i % 16))];

        var keySet = new Scp03KeySet(encKey, macKey, dekKey);
        var uuidResult = CardUuid.Generate();

        uuidResult.IsSuccess.Should().BeTrue();

        uuidResult.Match(
            uuid =>
            {
                // Act
                var result = _service.DeriveStorageKey(keySet, uuid);

                // Assert
                result.IsSuccess.Should().BeTrue();
                result.Match(
                    derivedKey =>
                    {
                        _ = derivedKey.Length.Should().Be(32);
                        _ = derivedKey.Should().NotBeEquivalentTo(new byte[32]);
                    },
                    error => Assert.Fail($"Key derivation failed: {error}")
                );
            },
            error => Assert.Fail($"UUID generation failed: {error}")
        );
    }

    [Test]
    public void DeriveStorageKey_WithScp03NoDek_ReturnsValidKey()
    {
        // Arrange - SCP03 without DEK key
        byte[] encKey = new byte[16]
        {
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
        };
        byte[] macKey = new byte[16]
        {
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
        };
        var keySet = new Scp03KeySet(encKey, macKey, null!); // No DEK
        var uuidResult = CardUuid.Generate();

        uuidResult.IsSuccess.Should().BeTrue();

        uuidResult.Match(
            uuid =>
            {
                // Act
                var result = _service.DeriveStorageKey(keySet, uuid);

                // Assert
                result.IsSuccess.Should().BeTrue();
                result.Match(
                    derivedKey =>
                    {
                        _ = derivedKey.Length.Should().Be(32);
                        _ = derivedKey.Should().NotBeEquivalentTo(new byte[32]);
                    },
                    error => Assert.Fail($"Key derivation failed: {error}")
                );
            },
            error => Assert.Fail($"UUID generation failed: {error}")
        );
    }

    [Test]
    public void DeriveStorageKey_SameInputs_ProducesSameKey()
    {
        // Arrange
        byte[] encKey = new byte[16]
        {
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
        };
        var keySet = Scp02KeySet.Create(encKey, encKey, encKey).Value;
        var uuidResult = CardUuid.Generate();

        uuidResult.IsSuccess.Should().BeTrue();

        uuidResult.Match(
            uuid =>
            {
                // Act - derive same key twice
                var result1 = _service.DeriveStorageKey(keySet, uuid);
                var result2 = _service.DeriveStorageKey(keySet, uuid);

                // Assert
                result1.IsSuccess.Should().BeTrue();
                result2.IsSuccess.Should().BeTrue();

                result1.Match(
                    key1 =>
                        result2.Match(
                            key2 => key1.Should().BeEquivalentTo(key2),
                            error => Assert.Fail($"Second key derivation failed: {error}")
                        ),
                    error => Assert.Fail($"First key derivation failed: {error}")
                );
            },
            error => Assert.Fail($"UUID generation failed: {error}")
        );
    }

    [Test]
    public void DeriveStorageKey_DifferentUuids_ProduceDifferentKeys()
    {
        // Arrange
        byte[] encKey = new byte[16]
        {
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
        };
        var keySet = Scp02KeySet.Create(encKey, encKey, encKey).Value;
        var uuid1Result = CardUuid.Generate();
        var uuid2Result = CardUuid.Generate();

        uuid1Result.IsSuccess.Should().BeTrue();
        uuid2Result.IsSuccess.Should().BeTrue();

        uuid1Result.Match(
            uuid1 =>
                uuid2Result.Match(
                    uuid2 =>
                    {
                        // Act
                        var result1 = _service.DeriveStorageKey(
                            keySet,
                            uuid1
                        );
                        var result2 = _service.DeriveStorageKey(
                            keySet,
                            uuid2
                        );

                        // Assert
                        result1.IsSuccess.Should().BeTrue();
                        result2.IsSuccess.Should().BeTrue();

                        result1.Match(
                            key1 =>
                                result2.Match(
                                    key2 => key1.Should().NotBeEquivalentTo(key2),
                                    error => Assert.Fail($"Second key derivation failed: {error}")
                                ),
                            error => Assert.Fail($"First key derivation failed: {error}")
                        );
                    },
                    error => Assert.Fail($"Second UUID generation failed: {error}")
                ),
            error => Assert.Fail($"First UUID generation failed: {error}")
        );
    }

    [Test]
    public void DeriveStorageKey_DifferentKeySets_ProduceDifferentKeys()
    {
        // Arrange
        byte[] encKey1 = new byte[16]
        {
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
        };
        byte[] encKey2 = new byte[16]
        {
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
        };
        var keySet1 = Scp02KeySet.Create(encKey1, encKey1, encKey1).Value;
        var keySet2 = Scp02KeySet.Create(encKey2, encKey2, encKey2).Value;
        var uuidResult = CardUuid.Generate();

        uuidResult.IsSuccess.Should().BeTrue();

        uuidResult.Match(
            uuid =>
            {
                // Act
                var result1 = _service.DeriveStorageKey(keySet1, uuid);
                var result2 = _service.DeriveStorageKey(keySet2, uuid);

                // Assert
                result1.IsSuccess.Should().BeTrue();
                result2.IsSuccess.Should().BeTrue();

                result1.Match(
                    key1 =>
                        result2.Match(
                            key2 => key1.Should().NotBeEquivalentTo(key2),
                            error => Assert.Fail($"Second key derivation failed: {error}")
                        ),
                    error => Assert.Fail($"First key derivation failed: {error}")
                );
            },
            error => Assert.Fail($"UUID generation failed: {error}")
        );
    }

    [Test]
    public void ComputeKeyFingerprint_WithScp02KeySet_ReturnsValidFingerprint()
    {
        // Arrange
        byte[] encKey = new byte[16]
        {
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
        };
        byte[] macKey = new byte[16]
        {
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
        };
        byte[] dekKey = new byte[16]
        {
            0x60,
            0x61,
            0x62,
            0x63,
            0x60,
            0x61,
            0x62,
            0x63,
            0x60,
            0x61,
            0x62,
            0x63,
            0x60,
            0x61,
            0x62,
            0x63,
        };
        var keySet = Scp02KeySet.Create(encKey, macKey, dekKey).Value;

        // Act
        var result = _service.ComputeKeyFingerprint(keySet);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Match(
            fingerprint =>
            {
                _ = fingerprint.Length.Should().Be(32); // SHA-256 hash
                _ = fingerprint.Should().NotBeEquivalentTo(new byte[32]);
            },
            error => Assert.Fail($"Fingerprint computation failed: {error}")
        );
    }

    [Test]
    public void ComputeKeyFingerprint_WithScp03KeySet_ReturnsValidFingerprint()
    {
        // Arrange
        byte[] encKey = new byte[16]
        {
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
        };
        byte[] macKey = new byte[16]
        {
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
            0x50,
            0x51,
            0x52,
            0x53,
        };
        byte[] dekKey = new byte[16]
        {
            0x60,
            0x61,
            0x62,
            0x63,
            0x60,
            0x61,
            0x62,
            0x63,
            0x60,
            0x61,
            0x62,
            0x63,
            0x60,
            0x61,
            0x62,
            0x63,
        };
        var keySet = new Scp03KeySet(encKey, macKey, dekKey);

        // Act
        var result = _service.ComputeKeyFingerprint(keySet);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Match(
            fingerprint =>
            {
                _ = fingerprint.Length.Should().Be(32); // SHA-256 hash
                _ = fingerprint.Should().NotBeEquivalentTo(new byte[32]);
            },
            error => Assert.Fail($"Fingerprint computation failed: {error}")
        );
    }

    [Test]
    public void ComputeKeyFingerprint_SameKeySet_ProducesSameFingerprint()
    {
        // Arrange
        byte[] encKey = new byte[16]
        {
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
        };
        var keySet = Scp02KeySet.Create(encKey, encKey, encKey).Value;

        // Act
        var result1 = _service.ComputeKeyFingerprint(keySet);
        var result2 = _service.ComputeKeyFingerprint(keySet);

        // Assert
        result1.IsSuccess.Should().BeTrue();
        result2.IsSuccess.Should().BeTrue();

        result1.Match(
            fingerprint1 =>
                result2.Match(
                    fingerprint2 => fingerprint1.Should().BeEquivalentTo(fingerprint2),
                    error => Assert.Fail($"Second fingerprint computation failed: {error}")
                ),
            error => Assert.Fail($"First fingerprint computation failed: {error}")
        );
    }

    [Test]
    public void ValidateKeyFingerprint_WithCorrectFingerprint_ReturnsTrue()
    {
        // Arrange
        byte[] encKey = new byte[16]
        {
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
        };
        var keySet = Scp02KeySet.Create(encKey, encKey, encKey).Value;
        var computeResult = _service.ComputeKeyFingerprint(keySet);

        computeResult.IsSuccess.Should().BeTrue();

        computeResult.Match(
            expectedFingerprint =>
            {
                // Act
                var result = _service.ValidateKeyFingerprint(
                    keySet,
                    expectedFingerprint
                );

                // Assert
                result.IsSuccess.Should().BeTrue();
                result.Match(
                    isValid => isValid.Should().BeTrue(),
                    error => Assert.Fail($"Fingerprint validation failed: {error}")
                );
            },
            error => Assert.Fail($"Fingerprint computation failed: {error}")
        );
    }

    [Test]
    public void ValidateKeyFingerprint_WithIncorrectFingerprint_ReturnsFalse()
    {
        // Arrange
        byte[] encKey = new byte[16]
        {
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
        };
        var keySet = Scp02KeySet.Create(encKey, encKey, encKey).Value;
        byte[] wrongFingerprint = new byte[32]; // All zeros

        // Act
        var result = _service.ValidateKeyFingerprint(
            keySet,
            wrongFingerprint
        );

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Match(
            isValid => isValid.Should().BeFalse(),
            error => Assert.Fail($"Fingerprint validation failed: {error}")
        );
    }

    [Test]
    public void DeriveStorageKey_WithNullKeySet_ReturnsFailure()
    {
        // Arrange
        var uuidResult = CardUuid.Generate();

        uuidResult.IsSuccess.Should().BeTrue();

        uuidResult.Match(
            uuid =>
            {
                // Act
                var result = _service.DeriveStorageKey(null!, uuid);

                // Assert
                result.IsFailure.Should().BeTrue();
                _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
            },
            error => Assert.Fail($"UUID generation failed: {error}")
        );
    }

    [Test]
    public void DeriveStorageKey_WithEmptyUuid_ReturnsFailure()
    {
        // Arrange
        byte[] encKey = new byte[16]
        {
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
            0x40,
            0x41,
            0x42,
            0x43,
        };
        var keySet = Scp02KeySet.Create(encKey, encKey, encKey).Value;
        var emptyUuid = CardUuid.Empty;

        // Act
        var result = _service.DeriveStorageKey(keySet, emptyUuid);

        // Assert
        result.IsFailure.Should().BeTrue();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
    }

    [Test]
    public void ComputeKeyFingerprint_WithNullKeySet_ReturnsFailure()
    {
        // Act
        var result = _service.ComputeKeyFingerprint(null!);

        // Assert
        result.IsFailure.Should().BeTrue();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
    }
}
