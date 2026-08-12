using System.Linq;
using System.Text;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Persistence;
using NUnit.Framework;

namespace Gp4Net.CardEmulator.Tests.Persistence;

/// <summary>
/// Tests for CardStateEncryption functionality.
/// Verifies AES-256-GCM encryption/decryption with UUID binding and security properties.
/// </summary>
[TestFixture]
public class AeadEncryptionServiceTests
{
    // @TODO THESE NEED TO ALL BE IMMUTABLE, PREFERABLY RECORD.

    /// <summary>
    /// A private instance of the <see cref="CardStateEncryption"/> class used for testing encryption and decryption processes
    /// with AEAD (Authenticated Encryption with Associated Data).
    /// </summary>
    private CardStateEncryption _service;

    /// <summary>
    /// Represents a valid 32-byte AES-256 encryption key used for testing purposes
    /// within the encryption and decryption functionality of the
    /// <see cref="AeadEncryptionServiceTests"/> class.
    /// </summary>
    /// <remarks>
    /// This key is dynamically generated during the setup phase of the test using
    /// a functional approach to ensure a consistent and deterministic value for
    /// encryption operations. It is primarily utilized for validating the encryption
    /// and decryption functionality within test scenarios.
    /// </remarks>
    private byte[] _validKey;

    /// <summary>
    /// Represents the plaintext data used for testing encryption and decryption in the
    /// AEAD encryption service unit tests. Acts as input data for verifying encryption
    /// methods, payload integrity, and round-trip encryption/decryption scenarios.
    /// </summary>
    private byte[] _testPlaintext;

    /// <summary>
    /// Represents a valid unique identifier (UUID) associated with a card.
    /// Used in encryption and decryption operations as part of the CardStateEncryption test suite.
    /// </summary>
    private CardUuid _validUuid;

    [SetUp]
    public void SetUp()
    {
        _service = new CardStateEncryption();

        // Generate valid 32-byte AES-256 key
        _validKey = [.. Enumerable.Range(0, 32).Select(i => (byte)(0x42 + i % 16))];

        // Create test plaintext (CBOR-like data)
        _testPlaintext = Encoding.UTF8.GetBytes("Test CBOR card state data for encryption");

        // Generate valid UUID with explicit success check
        var uuidResult = CardUuid.Generate();
        if (uuidResult.IsSuccess)
        {
            _validUuid = uuidResult.Value;
        }
        else
        {
            Assert.Fail($"Test setup failed to generate UUID: {uuidResult.Error}");
        }
    }

    [TearDown]
    public void TearDown()
    {
        _service?.Dispose();
    }

    [Test]
    public void Encrypt_WithValidInputs_ReturnsSuccessResult()
    {
        // Act
        var result = _service.Encrypt(_validKey, _testPlaintext, _validUuid);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Match(
            payload =>
            {
                _ = payload.Algorithm.Should().Be("aes-256-gcm");
                _ = payload.Iv.Length.Should().Be(12);
                _ = payload.AuthTag.Length.Should().Be(16);
                _ = payload.Ciphertext.Length.Should().Be(_testPlaintext.Length);
                _ = payload.IsValid.Should().BeTrue();
            },
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public void Encrypt_ProducesValidEncryptedPayload()
    {
        // Act
        var result = _service.Encrypt(_validKey, _testPlaintext, _validUuid);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Match(
            payload =>
            {
                // Verify payload structure
                _ = payload
                    .TotalSize.Should()
                    .Be(payload.Iv.Length + payload.Ciphertext.Length + payload.AuthTag.Length);
                _ = payload.Ciphertext.Should().NotBeEquivalentTo(_testPlaintext); // Should be encrypted
                _ = payload.Iv.Should().NotBeEquivalentTo(new byte[12]); // Should not be all zeros
                _ = payload.AuthTag.Should().NotBeEquivalentTo(new byte[16]); // Should not be all zeros
            },
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public void Encrypt_MultipleTimes_ProducesDifferentCiphertexts()
    {
        // Act - encrypt same plaintext twice
        var result1 = _service.Encrypt(_validKey, _testPlaintext, _validUuid);
        var result2 = _service.Encrypt(_validKey, _testPlaintext, _validUuid);

        // Assert
        result1.IsSuccess.Should().BeTrue();
        result2.IsSuccess.Should().BeTrue();

        result1.Match(
            payload1 =>
                result2.Match(
                    payload2 =>
                    {
                        // Different IVs should produce different ciphertexts
                        _ = payload1.Iv.Should().NotBeEquivalentTo(payload2.Iv);
                        _ = payload1.Ciphertext.Should().NotBeEquivalentTo(payload2.Ciphertext);
                        _ = payload1.AuthTag.Should().NotBeEquivalentTo(payload2.AuthTag);
                    },
                    error => Assert.Fail($"Second encryption failed: {error}")
                ),
            error => Assert.Fail($"First encryption failed: {error}")
        );
    }

    [Test]
    public void Encrypt_WithEmptyPlaintext_ReturnsSuccess()
    {
        // Arrange
        byte[] emptyPlaintext = [];

        // Act
        var result = _service.Encrypt(_validKey, emptyPlaintext, _validUuid);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Match(
            payload =>
            {
                _ = payload.Ciphertext.Length.Should().Be(0);
                _ = payload.IsValid.Should().BeFalse(); // Empty ciphertext makes payload invalid
            },
            error => Assert.Fail($"Expected success but got error: {error}")
        );
    }

    [Test]
    public void Decrypt_WithValidEncryptedPayload_ReturnsOriginalPlaintext()
    {
        // Arrange - first encrypt some data
        var encryptResult = _service.Encrypt(_validKey, _testPlaintext, _validUuid);
        encryptResult.IsSuccess.Should().BeTrue();

        encryptResult.Match(
            encryptedPayload =>
            {
                // Act - decrypt the payload
                var decryptResult = _service.Decrypt(_validKey, encryptedPayload, _validUuid);

                // Assert
                decryptResult.IsSuccess.Should().BeTrue();
                decryptResult.Match(
                    decryptedData => decryptedData.Should().BeEquivalentTo(_testPlaintext),
                    error => Assert.Fail($"Decryption failed: {error}")
                );
            },
            error => Assert.Fail($"Encryption failed: {error}")
        );
    }

    [Test]
    public void Decrypt_WithWrongKey_ReturnsFailure()
    {
        // Arrange - encrypt with one key
        var encryptResult = _service.Encrypt(_validKey, _testPlaintext, _validUuid);
        encryptResult.IsSuccess.Should().BeTrue();

        // Create wrong key
        byte[] wrongKey = [.. Enumerable.Range(0, 32).Select(i => (byte)0x99)];

        encryptResult.Match(
            encryptedPayload =>
            {
                // Act - try to decrypt with wrong key
                var decryptResult = _service.Decrypt(wrongKey, encryptedPayload, _validUuid);

                // Assert
                decryptResult.IsFailure.Should().BeTrue();
                _ = decryptResult.Error.Code.Should().Be("INTEGRITY_ERROR");
            },
            error => Assert.Fail($"Encryption failed: {error}")
        );
    }

    [Test]
    public void Decrypt_WithWrongUuid_ReturnsFailure()
    {
        // Arrange - encrypt with one UUID
        var encryptResult = _service.Encrypt(_validKey, _testPlaintext, _validUuid);
        encryptResult.IsSuccess.Should().BeTrue();

        // Create different UUID
        var wrongUuidResult = CardUuid.Generate();
        wrongUuidResult.IsSuccess.Should().BeTrue();

        encryptResult.Match(
            encryptedPayload =>
                wrongUuidResult.Match(
                    wrongUuid =>
                    {
                        // Act - try to decrypt with wrong UUID
                        var decryptResult = _service.Decrypt(
                            _validKey,
                            encryptedPayload,
                            wrongUuid
                        );

                        // Assert
                        decryptResult.IsFailure.Should().BeTrue();
                        _ = decryptResult.Error.Code.Should().Be("INTEGRITY_ERROR");
                    },
                    error => Assert.Fail($"Wrong UUID generation failed: {error}")
                ),
            error => Assert.Fail($"Encryption failed: {error}")
        );
    }

    [Test]
    public void Decrypt_WithTamperedCiphertext_ReturnsFailure()
    {
        // Arrange - encrypt some data
        var encryptResult = _service.Encrypt(_validKey, _testPlaintext, _validUuid);
        encryptResult.IsSuccess.Should().BeTrue();

        encryptResult.Match(
            originalPayload =>
            {
                // Tamper with ciphertext
                byte[] tamperedCiphertext = [.. originalPayload.Ciphertext];
                tamperedCiphertext[0] ^= 0xFF; // Flip all bits in first byte

                var tamperedPayload = originalPayload with { Ciphertext = tamperedCiphertext };

                // Act - try to decrypt tampered data
                var decryptResult = _service.Decrypt(_validKey, tamperedPayload, _validUuid);

                // Assert
                decryptResult.IsFailure.Should().BeTrue();
                _ = decryptResult.Error.Code.Should().Be("INTEGRITY_ERROR");
            },
            error => Assert.Fail($"Encryption failed: {error}")
        );
    }

    [Test]
    public void Decrypt_WithTamperedAuthTag_ReturnsFailure()
    {
        // Arrange - encrypt some data
        var encryptResult = _service.Encrypt(_validKey, _testPlaintext, _validUuid);
        encryptResult.IsSuccess.Should().BeTrue();

        encryptResult.Match(
            originalPayload =>
            {
                // Tamper with auth tag
                byte[] tamperedAuthTag = [.. originalPayload.AuthTag];
                tamperedAuthTag[0] ^= 0xFF; // Flip all bits in first byte

                var tamperedPayload = originalPayload with { AuthTag = tamperedAuthTag };

                // Act - try to decrypt tampered data
                var decryptResult = _service.Decrypt(_validKey, tamperedPayload, _validUuid);

                // Assert
                decryptResult.IsFailure.Should().BeTrue();
                _ = decryptResult.Error.Code.Should().Be("INTEGRITY_ERROR");
            },
            error => Assert.Fail($"Encryption failed: {error}")
        );
    }

    [Test]
    public void Decrypt_WithTamperedIV_ReturnsFailure()
    {
        // Arrange - encrypt some data
        var encryptResult = _service.Encrypt(_validKey, _testPlaintext, _validUuid);
        encryptResult.IsSuccess.Should().BeTrue();

        encryptResult.Match(
            originalPayload =>
            {
                // Tamper with IV
                byte[] tamperedIv = [.. originalPayload.Iv];
                tamperedIv[0] ^= 0xFF; // Flip all bits in first byte

                var tamperedPayload = originalPayload with { Iv = tamperedIv };

                // Act - try to decrypt tampered data
                var decryptResult = _service.Decrypt(_validKey, tamperedPayload, _validUuid);

                // Assert
                decryptResult.IsFailure.Should().BeTrue();
                _ = decryptResult.Error.Code.Should().Be("INTEGRITY_ERROR");
            },
            error => Assert.Fail($"Encryption failed: {error}")
        );
    }

    [Test]
    public void EncryptDecrypt_RoundTrip_PreservesData()
    {
        // Arrange
        byte[] originalData = Encoding.UTF8.GetBytes(
            "Complex CBOR data with special chars: αβγδε 🔐"
        );

        // Act - encrypt then decrypt
        var encryptResult = _service.Encrypt(_validKey, originalData, _validUuid);
        encryptResult.IsSuccess.Should().BeTrue();

        encryptResult.Match(
            encryptedPayload =>
            {
                var decryptResult = _service.Decrypt(_validKey, encryptedPayload, _validUuid);
                decryptResult.IsSuccess.Should().BeTrue();

                decryptResult.Match(
                    decryptedData => decryptedData.Should().BeEquivalentTo(originalData),
                    error => Assert.Fail($"Decryption failed: {error}")
                );
            },
            error => Assert.Fail($"Encryption failed: {error}")
        );
    }

    [Test]
    public void EncryptDecrypt_LargeData_WorksCorrectly()
    {
        // Arrange - create large test data
        byte[] largeData = [.. Enumerable.Range(0, 10000).Select(i => (byte)(i % 256))];

        // Act - encrypt then decrypt
        var encryptResult = _service.Encrypt(_validKey, largeData, _validUuid);
        encryptResult.IsSuccess.Should().BeTrue();

        encryptResult.Match(
            encryptedPayload =>
            {
                var decryptResult = _service.Decrypt(_validKey, encryptedPayload, _validUuid);
                decryptResult.IsSuccess.Should().BeTrue();

                decryptResult.Match(
                    decryptedData => decryptedData.Should().BeEquivalentTo(largeData),
                    error => Assert.Fail($"Decryption failed: {error}")
                );
            },
            error => Assert.Fail($"Encryption failed: {error}")
        );
    }

    [Test]
    public void Encrypt_WithNullKey_ReturnsFailure()
    {
        // Act
        var result = _service.Encrypt(null!, _testPlaintext, _validUuid);

        // Assert
        result.IsFailure.Should().BeTrue();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Message.Should().StartWith("Encryption key must be 32 bytes");
    }

    [Test]
    public void Encrypt_WithWrongKeySize_ReturnsFailure()
    {
        // Arrange
        byte[] wrongSizeKey = new byte[16]; // AES-128, not AES-256

        // Act
        var result = _service.Encrypt(wrongSizeKey, _testPlaintext, _validUuid);

        // Assert
        result.IsFailure.Should().BeTrue();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Message.Should().StartWith("Encryption key must be 32 bytes");
    }

    [Test]
    public void Encrypt_WithNullPlaintext_ReturnsFailure()
    {
        // Act
        var result = _service.Encrypt(_validKey, null!, _validUuid);

        // Assert
        result.IsFailure.Should().BeTrue();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Message.Should().StartWith("Plaintext cannot be null");
    }

    [Test]
    public void Encrypt_WithEmptyUuid_ReturnsFailure()
    {
        // Arrange
        var emptyUuid = CardUuid.Empty;

        // Act
        var result = _service.Encrypt(_validKey, _testPlaintext, emptyUuid);

        // Assert
        result.IsFailure.Should().BeTrue();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Message.Should().StartWith("Card UUID cannot be empty");
    }

    [Test]
    public void Decrypt_WithNullKey_ReturnsFailure()
    {
        // Arrange
        var validPayload = new EncryptedPayload(
            Algorithm: "aes-256-gcm",
            Iv: new byte[12],
            Ciphertext: new byte[10],
            AuthTag: new byte[16]
        );

        // Act
        var result = _service.Decrypt(null!, validPayload, _validUuid);

        // Assert
        result.IsFailure.Should().BeTrue();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Message.Should().StartWith("Encryption key must be 32 bytes");
    }

    [Test]
    public void Decrypt_WithInvalidPayload_ReturnsFailure()
    {
        // Arrange - create invalid payload
        var invalidPayload = new EncryptedPayload(
            Algorithm: "invalid-algorithm",
            Iv: new byte[10], // Wrong IV size
            Ciphertext: new byte[10],
            AuthTag: new byte[10] // Wrong auth tag size
        );

        // Act
        var result = _service.Decrypt(_validKey, invalidPayload, _validUuid);

        // Assert
        result.IsFailure.Should().BeTrue();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Message.Should().StartWith("Invalid encrypted payload structure");
    }

    [Test]
    public void Decrypt_WithNullPayload_ReturnsFailure()
    {
        // Act
        var result = _service.Decrypt(_validKey, null!, _validUuid);

        // Assert
        result.IsFailure.Should().BeTrue();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Message.Should().StartWith("Invalid encrypted payload structure");
    }

    [Test]
    public void Encrypt_AfterDispose_ReturnsFailure()
    {
        // Arrange
        _service.Dispose();

        // Act
        var result = _service.Encrypt(_validKey, _testPlaintext, _validUuid);

        // Assert
        result.IsFailure.Should().BeTrue();
        _ = result.Error.Code.Should().Be("COMMUNICATION_ERROR");
        _ = result.Error.Code.Should().Be("COMMUNICATION_ERROR");
        _ = result.Error.Message.Should().StartWith("AEAD service has been disposed");
    }

    [Test]
    public void Decrypt_AfterDispose_ReturnsFailure()
    {
        // Arrange
        var validPayload = new EncryptedPayload(
            Algorithm: "aes-256-gcm",
            Iv: new byte[12],
            Ciphertext: new byte[10],
            AuthTag: new byte[16]
        );
        _service.Dispose();

        // Act
        var result = _service.Decrypt(_validKey, validPayload, _validUuid);

        // Assert
        result.IsFailure.Should().BeTrue();
        _ = result.Error.Code.Should().Be("COMMUNICATION_ERROR");
        _ = result.Error.Code.Should().Be("COMMUNICATION_ERROR");
        _ = result.Error.Message.Should().StartWith("AEAD service has been disposed");
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Act & Assert - should not throw
        _service.Dispose();
        _service.Dispose(); // Second dispose should be safe
    }

    [Test]
    public void EncryptedPayload_IsValid_ReturnsTrueForValidPayload()
    {
        // Arrange
        var validPayload = new EncryptedPayload(
            Algorithm: "aes-256-gcm",
            Iv: new byte[12],
            Ciphertext: new byte[10],
            AuthTag: new byte[16]
        );

        // Assert
        _ = validPayload.IsValid.Should().BeTrue();
    }

    [Test]
    public void EncryptedPayload_IsValid_ReturnsFalseForInvalidAlgorithm()
    {
        // Arrange
        var invalidPayload = new EncryptedPayload(
            Algorithm: "invalid",
            Iv: new byte[12],
            Ciphertext: new byte[10],
            AuthTag: new byte[16]
        );

        // Assert
        _ = invalidPayload.IsValid.Should().BeFalse();
    }

    [Test]
    public void EncryptedPayload_IsValid_ReturnsFalseForWrongIVSize()
    {
        // Arrange
        var invalidPayload = new EncryptedPayload(
            Algorithm: "aes-256-gcm",
            Iv: new byte[16], // Should be 12
            Ciphertext: new byte[10],
            AuthTag: new byte[16]
        );

        // Assert
        _ = invalidPayload.IsValid.Should().BeFalse();
    }

    [Test]
    public void EncryptedPayload_IsValid_ReturnsFalseForWrongAuthTagSize()
    {
        // Arrange
        var invalidPayload = new EncryptedPayload(
            Algorithm: "aes-256-gcm",
            Iv: new byte[12],
            Ciphertext: new byte[10],
            AuthTag: new byte[8] // Should be 16
        );

        // Assert
        _ = invalidPayload.IsValid.Should().BeFalse();
    }

    [Test]
    public void EncryptedPayload_IsValid_ReturnsFalseForEmptyCiphertext()
    {
        // Arrange
        var invalidPayload = new EncryptedPayload(
            Algorithm: "aes-256-gcm",
            Iv: new byte[12],
            Ciphertext: [], // Empty ciphertext
            AuthTag: new byte[16]
        );

        // Assert
        _ = invalidPayload.IsValid.Should().BeFalse();
    }

    [Test]
    public void EncryptedPayload_TotalSize_CalculatesCorrectly()
    {
        // Arrange
        var payload = new EncryptedPayload(
            Algorithm: "aes-256-gcm",
            Iv: new byte[12],
            Ciphertext: new byte[100],
            AuthTag: new byte[16]
        );

        // Assert
        _ = payload.TotalSize.Should().Be(12 + 100 + 16);
    }

    [Test]
    public void UuidBinding_DifferentUuids_ProduceDifferentCiphertexts()
    {
        // Arrange
        var uuid1Result = CardUuid.Generate();
        var uuid2Result = CardUuid.Generate();
        uuid1Result.IsSuccess.Should().BeTrue();
        uuid2Result.IsSuccess.Should().BeTrue();

        uuid1Result.Match(
            uuid1 =>
                uuid2Result.Match(
                    uuid2 =>
                    {
                        // Act - encrypt same data with different UUIDs
                        var result1 = _service.Encrypt(_validKey, _testPlaintext, uuid1);
                        var result2 = _service.Encrypt(_validKey, _testPlaintext, uuid2);

                        // Assert
                        result1.IsSuccess.Should().BeTrue();
                        result2.IsSuccess.Should().BeTrue();

                        result1.Match(
                            payload1 =>
                                result2.Match(
                                    payload2 =>
                                    {
                                        // Different UUIDs should produce different auth tags (due to AAD)
                                        _ = payload1
                                            .AuthTag.Should()
                                            .NotBeEquivalentTo(payload2.AuthTag);
                                        // Note: Ciphertexts might be different due to different IVs, but auth tags will definitely be different
                                    },
                                    error => Assert.Fail($"Second encryption failed: {error}")
                                ),
                            error => Assert.Fail($"First encryption failed: {error}")
                        );
                    },
                    error => Assert.Fail($"Second UUID generation failed: {error}")
                ),
            error => Assert.Fail($"First UUID generation failed: {error}")
        );
    }

    [Test]
    public void UuidBinding_CrossDecryption_ShouldFail()
    {
        // Arrange - create two different UUIDs
        var uuid1Result = CardUuid.Generate();
        var uuid2Result = CardUuid.Generate();
        uuid1Result.IsSuccess.Should().BeTrue();
        uuid2Result.IsSuccess.Should().BeTrue();

        uuid1Result.Match(
            uuid1 =>
                uuid2Result.Match(
                    uuid2 =>
                    {
                        // Encrypt with uuid1
                        var encryptResult = _service.Encrypt(_validKey, _testPlaintext, uuid1);
                        encryptResult.IsSuccess.Should().BeTrue();

                        encryptResult.Match(
                            encryptedPayload =>
                            {
                                // Try to decrypt with uuid2
                                var decryptResult = _service.Decrypt(
                                    _validKey,
                                    encryptedPayload,
                                    uuid2
                                );

                                // Should fail due to UUID mismatch in AAD
                                decryptResult.IsFailure.Should().BeTrue();
                                _ = decryptResult.Error.Code.Should().Be("INTEGRITY_ERROR");
                            },
                            error => Assert.Fail($"Encryption failed: {error}")
                        );
                    },
                    error => Assert.Fail($"Second UUID generation failed: {error}")
                ),
            error => Assert.Fail($"First UUID generation failed: {error}")
        );
    }
}
