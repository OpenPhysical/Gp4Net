using System;
using System.Linq;
using System.Text;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Persistence;
using Gp4Net.Core;
using NUnit.Framework;

namespace Gp4Net.Tests.CardEmulator.Persistence;

/// <summary>
/// Tests for AeadEncryptionService functionality.
/// Verifies AES-256-GCM encryption/decryption with UUID binding and security properties.
/// </summary>
[TestFixture]
public class AeadEncryptionServiceTests
{
    private AeadEncryptionService _service;
    private byte[] _validKey;
    private byte[] _testPlaintext;
    private CardUuid _validUuid;

    [SetUp]
    public void SetUp()
    {
        _service = new AeadEncryptionService();
        
        // Generate valid 32-byte AES-256 key using functional approach
        _validKey = Enumerable.Range(0, 32).Select(i => (byte)(0x42 + (i % 16))).ToArray();
        
        // Create test plaintext (CBOR-like data)
        _testPlaintext = Encoding.UTF8.GetBytes("Test CBOR card state data for encryption");
        
        // Generate valid UUID using functional approach with explicit success check
        Result<CardUuid, SmartCardError> uuidResult = CardUuid.Generate();
        if (uuidResult.IsSuccess)
        {
            _validUuid = uuidResult.Value;
        }
        else
        {
            Assert.Fail($"Test setup failed to generate UUID: {uuidResult.Error.Message}");
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
        Result<EncryptedPayload, SmartCardError> result = _service.Encrypt(_validKey, _testPlaintext, _validUuid);

        // Assert
        result.Should().BeSuccess();
        result.Match(
            payload =>
            {
                _ = payload.Algorithm.Should().Be("aes-256-gcm");
                _ = payload.IV.Length.Should().Be(12);
                _ = payload.AuthTag.Length.Should().Be(16);
                _ = payload.Ciphertext.Length.Should().Be(_testPlaintext.Length);
                _ = payload.IsValid.Should().BeTrue();
            },
            error => Assert.Fail($"Expected success but got error: {error.Message}")
        );
    }

    [Test]
    public void Encrypt_ProducesValidEncryptedPayload()
    {
        // Act
        Result<EncryptedPayload, SmartCardError> result = _service.Encrypt(_validKey, _testPlaintext, _validUuid);

        // Assert
        result.Should().BeSuccess();
        result.Match(
            payload =>
            {
                // Verify payload structure
                _ = payload.TotalSize.Should().Be(payload.IV.Length + payload.Ciphertext.Length + payload.AuthTag.Length);
                _ = payload.Ciphertext.Should().NotBeEquivalentTo(_testPlaintext); // Should be encrypted
                _ = payload.IV.Should().NotBeEquivalentTo(new byte[12]); // Should not be all zeros
                _ = payload.AuthTag.Should().NotBeEquivalentTo(new byte[16]); // Should not be all zeros
            },
            error => Assert.Fail($"Expected success but got error: {error.Message}")
        );
    }

    [Test]
    public void Encrypt_MultipleTimes_ProducesDifferentCiphertexts()
    {
        // Act - encrypt same plaintext twice
        Result<EncryptedPayload, SmartCardError> result1 = _service.Encrypt(_validKey, _testPlaintext, _validUuid);
        Result<EncryptedPayload, SmartCardError> result2 = _service.Encrypt(_validKey, _testPlaintext, _validUuid);

        // Assert
        result1.Should().BeSuccess();
        result2.Should().BeSuccess();

        result1.Match(
            payload1 => result2.Match(
                payload2 =>
                {
                    // Different IVs should produce different ciphertexts
                    _ = payload1.IV.Should().NotBeEquivalentTo(payload2.IV);
                    _ = payload1.Ciphertext.Should().NotBeEquivalentTo(payload2.Ciphertext);
                    _ = payload1.AuthTag.Should().NotBeEquivalentTo(payload2.AuthTag);
                },
                error => Assert.Fail($"Second encryption failed: {error.Message}")
            ),
            error => Assert.Fail($"First encryption failed: {error.Message}")
        );
    }

    [Test]
    public void Encrypt_WithEmptyPlaintext_ReturnsSuccess()
    {
        // Arrange
        byte[] emptyPlaintext = [];

        // Act
        Result<EncryptedPayload, SmartCardError> result = _service.Encrypt(_validKey, emptyPlaintext, _validUuid);

        // Assert
        result.Should().BeSuccess();
        result.Match(
            payload =>
            {
                _ = payload.Ciphertext.Length.Should().Be(0);
                _ = payload.IsValid.Should().BeFalse(); // Empty ciphertext makes payload invalid
            },
            error => Assert.Fail($"Expected success but got error: {error.Message}")
        );
    }

    [Test]
    public void Decrypt_WithValidEncryptedPayload_ReturnsOriginalPlaintext()
    {
        // Arrange - first encrypt some data
        Result<EncryptedPayload, SmartCardError> encryptResult = _service.Encrypt(_validKey, _testPlaintext, _validUuid);
        encryptResult.Should().BeSuccess();

        encryptResult.Match(
            encryptedPayload =>
            {
                // Act - decrypt the payload
                Result<byte[], SmartCardError> decryptResult = _service.Decrypt(_validKey, encryptedPayload, _validUuid);

                // Assert
                decryptResult.Should().BeSuccess();
                decryptResult.Match(
                    decryptedData => decryptedData.Should().BeEquivalentTo(_testPlaintext),
                    error => Assert.Fail($"Decryption failed: {error.Message}")
                );
            },
            error => Assert.Fail($"Encryption failed: {error.Message}")
        );
    }

    [Test]
    public void Decrypt_WithWrongKey_ReturnsFailure()
    {
        // Arrange - encrypt with one key
        Result<EncryptedPayload, SmartCardError> encryptResult = _service.Encrypt(_validKey, _testPlaintext, _validUuid);
        encryptResult.Should().BeSuccess();

        // Create wrong key
        byte[] wrongKey = Enumerable.Range(0, 32).Select(i => (byte)(0x99)).ToArray();

        encryptResult.Match(
            encryptedPayload =>
            {
                // Act - try to decrypt with wrong key
                Result<byte[], SmartCardError> decryptResult = _service.Decrypt(wrongKey, encryptedPayload, _validUuid);

                // Assert
                decryptResult.Should().BeFailure();
                _ = decryptResult.Error.Code.Should().Be("INTEGRITY_ERROR");
            },
            error => Assert.Fail($"Encryption failed: {error.Message}")
        );
    }

    [Test]
    public void Decrypt_WithWrongUuid_ReturnsFailure()
    {
        // Arrange - encrypt with one UUID
        Result<EncryptedPayload, SmartCardError> encryptResult = _service.Encrypt(_validKey, _testPlaintext, _validUuid);
        encryptResult.Should().BeSuccess();

        // Create different UUID
        Result<CardUuid, SmartCardError> wrongUuidResult = CardUuid.Generate();
        wrongUuidResult.Should().BeSuccess();

        encryptResult.Match(
            encryptedPayload => wrongUuidResult.Match(
                wrongUuid =>
                {
                    // Act - try to decrypt with wrong UUID
                    Result<byte[], SmartCardError> decryptResult = _service.Decrypt(_validKey, encryptedPayload, wrongUuid);

                    // Assert
                    decryptResult.Should().BeFailure();
                    _ = decryptResult.Error.Code.Should().Be("INTEGRITY_ERROR");
                },
                error => Assert.Fail($"Wrong UUID generation failed: {error.Message}")
            ),
            error => Assert.Fail($"Encryption failed: {error.Message}")
        );
    }

    [Test]
    public void Decrypt_WithTamperedCiphertext_ReturnsFailure()
    {
        // Arrange - encrypt some data
        Result<EncryptedPayload, SmartCardError> encryptResult = _service.Encrypt(_validKey, _testPlaintext, _validUuid);
        encryptResult.Should().BeSuccess();

        encryptResult.Match(
            originalPayload =>
            {
                // Tamper with ciphertext
                byte[] tamperedCiphertext = originalPayload.Ciphertext.ToArray();
                tamperedCiphertext[0] ^= 0xFF; // Flip all bits in first byte

                EncryptedPayload tamperedPayload = originalPayload with { Ciphertext = tamperedCiphertext };

                // Act - try to decrypt tampered data
                Result<byte[], SmartCardError> decryptResult = _service.Decrypt(_validKey, tamperedPayload, _validUuid);

                // Assert
                decryptResult.Should().BeFailure();
                _ = decryptResult.Error.Code.Should().Be("INTEGRITY_ERROR");
            },
            error => Assert.Fail($"Encryption failed: {error.Message}")
        );
    }

    [Test]
    public void Decrypt_WithTamperedAuthTag_ReturnsFailure()
    {
        // Arrange - encrypt some data
        Result<EncryptedPayload, SmartCardError> encryptResult = _service.Encrypt(_validKey, _testPlaintext, _validUuid);
        encryptResult.Should().BeSuccess();

        encryptResult.Match(
            originalPayload =>
            {
                // Tamper with auth tag
                byte[] tamperedAuthTag = originalPayload.AuthTag.ToArray();
                tamperedAuthTag[0] ^= 0xFF; // Flip all bits in first byte

                EncryptedPayload tamperedPayload = originalPayload with { AuthTag = tamperedAuthTag };

                // Act - try to decrypt tampered data
                Result<byte[], SmartCardError> decryptResult = _service.Decrypt(_validKey, tamperedPayload, _validUuid);

                // Assert
                decryptResult.Should().BeFailure();
                _ = decryptResult.Error.Code.Should().Be("INTEGRITY_ERROR");
            },
            error => Assert.Fail($"Encryption failed: {error.Message}")
        );
    }

    [Test]
    public void Decrypt_WithTamperedIV_ReturnsFailure()
    {
        // Arrange - encrypt some data
        Result<EncryptedPayload, SmartCardError> encryptResult = _service.Encrypt(_validKey, _testPlaintext, _validUuid);
        encryptResult.Should().BeSuccess();

        encryptResult.Match(
            originalPayload =>
            {
                // Tamper with IV
                byte[] tamperedIV = originalPayload.IV.ToArray();
                tamperedIV[0] ^= 0xFF; // Flip all bits in first byte

                EncryptedPayload tamperedPayload = originalPayload with { IV = tamperedIV };

                // Act - try to decrypt tampered data
                Result<byte[], SmartCardError> decryptResult = _service.Decrypt(_validKey, tamperedPayload, _validUuid);

                // Assert
                decryptResult.Should().BeFailure();
                _ = decryptResult.Error.Code.Should().Be("INTEGRITY_ERROR");
            },
            error => Assert.Fail($"Encryption failed: {error.Message}")
        );
    }

    [Test]
    public void EncryptDecrypt_RoundTrip_PreservesData()
    {
        // Arrange
        byte[] originalData = Encoding.UTF8.GetBytes("Complex CBOR data with special chars: αβγδε 🔐");

        // Act - encrypt then decrypt
        Result<EncryptedPayload, SmartCardError> encryptResult = _service.Encrypt(_validKey, originalData, _validUuid);
        encryptResult.Should().BeSuccess();

        encryptResult.Match(
            encryptedPayload =>
            {
                Result<byte[], SmartCardError> decryptResult = _service.Decrypt(_validKey, encryptedPayload, _validUuid);
                decryptResult.Should().BeSuccess();

                decryptResult.Match(
                    decryptedData => decryptedData.Should().BeEquivalentTo(originalData),
                    error => Assert.Fail($"Decryption failed: {error.Message}")
                );
            },
            error => Assert.Fail($"Encryption failed: {error.Message}")
        );
    }

    [Test]
    public void EncryptDecrypt_LargeData_WorksCorrectly()
    {
        // Arrange - create large test data using functional approach
        byte[] largeData = Enumerable.Range(0, 10000).Select(i => (byte)(i % 256)).ToArray();

        // Act - encrypt then decrypt
        Result<EncryptedPayload, SmartCardError> encryptResult = _service.Encrypt(_validKey, largeData, _validUuid);
        encryptResult.Should().BeSuccess();

        encryptResult.Match(
            encryptedPayload =>
            {
                Result<byte[], SmartCardError> decryptResult = _service.Decrypt(_validKey, encryptedPayload, _validUuid);
                decryptResult.Should().BeSuccess();

                decryptResult.Match(
                    decryptedData => decryptedData.Should().BeEquivalentTo(largeData),
                    error => Assert.Fail($"Decryption failed: {error.Message}")
                );
            },
            error => Assert.Fail($"Encryption failed: {error.Message}")
        );
    }

    [Test]
    public void Encrypt_WithNullKey_ReturnsFailure()
    {
        // Act
        Result<EncryptedPayload, SmartCardError> result = _service.Encrypt(null, _testPlaintext, _validUuid);

        // Assert
        result.Should().BeFailure();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Message.Should().Contain("Encryption key must be 32 bytes");
    }

    [Test]
    public void Encrypt_WithWrongKeySize_ReturnsFailure()
    {
        // Arrange
        byte[] wrongSizeKey = new byte[16]; // AES-128, not AES-256

        // Act
        Result<EncryptedPayload, SmartCardError> result = _service.Encrypt(wrongSizeKey, _testPlaintext, _validUuid);

        // Assert
        result.Should().BeFailure();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Message.Should().Contain("Encryption key must be 32 bytes");
    }

    [Test]
    public void Encrypt_WithNullPlaintext_ReturnsFailure()
    {
        // Act
        Result<EncryptedPayload, SmartCardError> result = _service.Encrypt(_validKey, null, _validUuid);

        // Assert
        result.Should().BeFailure();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Message.Should().Contain("Plaintext cannot be null");
    }

    [Test]
    public void Encrypt_WithEmptyUuid_ReturnsFailure()
    {
        // Arrange
        CardUuid emptyUuid = CardUuid.Empty;

        // Act
        Result<EncryptedPayload, SmartCardError> result = _service.Encrypt(_validKey, _testPlaintext, emptyUuid);

        // Assert
        result.Should().BeFailure();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Message.Should().Contain("Card UUID cannot be empty");
    }

    [Test]
    public void Decrypt_WithNullKey_ReturnsFailure()
    {
        // Arrange
        EncryptedPayload validPayload = new EncryptedPayload(
            Algorithm: "aes-256-gcm",
            IV: new byte[12],
            Ciphertext: new byte[10],
            AuthTag: new byte[16]
        );

        // Act
        Result<byte[], SmartCardError> result = _service.Decrypt(null, validPayload, _validUuid);

        // Assert
        result.Should().BeFailure();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Message.Should().Contain("Encryption key must be 32 bytes");
    }

    [Test]
    public void Decrypt_WithInvalidPayload_ReturnsFailure()
    {
        // Arrange - create invalid payload
        EncryptedPayload invalidPayload = new EncryptedPayload(
            Algorithm: "invalid-algorithm",
            IV: new byte[10], // Wrong IV size
            Ciphertext: new byte[10],
            AuthTag: new byte[10] // Wrong auth tag size
        );

        // Act
        Result<byte[], SmartCardError> result = _service.Decrypt(_validKey, invalidPayload, _validUuid);

        // Assert
        result.Should().BeFailure();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Message.Should().Contain("Invalid encrypted payload structure");
    }

    [Test]
    public void Decrypt_WithNullPayload_ReturnsFailure()
    {
        // Act
        Result<byte[], SmartCardError> result = _service.Decrypt(_validKey, null, _validUuid);

        // Assert
        result.Should().BeFailure();
        _ = result.Error.Code.Should().Be("INVALID_ARGUMENT");
        _ = result.Error.Message.Should().Contain("Invalid encrypted payload structure");
    }

    [Test]
    public void Encrypt_AfterDispose_ReturnsFailure()
    {
        // Arrange
        _service.Dispose();

        // Act
        Result<EncryptedPayload, SmartCardError> result = _service.Encrypt(_validKey, _testPlaintext, _validUuid);

        // Assert
        result.Should().BeFailure();
        _ = result.Error.Code.Should().Be("COMMUNICATION_ERROR");
        _ = result.Error.Message.Should().Contain("AEAD service has been disposed");
    }

    [Test]
    public void Decrypt_AfterDispose_ReturnsFailure()
    {
        // Arrange
        EncryptedPayload validPayload = new EncryptedPayload(
            Algorithm: "aes-256-gcm",
            IV: new byte[12],
            Ciphertext: new byte[10],
            AuthTag: new byte[16]
        );
        _service.Dispose();

        // Act
        Result<byte[], SmartCardError> result = _service.Decrypt(_validKey, validPayload, _validUuid);

        // Assert
        result.Should().BeFailure();
        _ = result.Error.Code.Should().Be("COMMUNICATION_ERROR");
        _ = result.Error.Message.Should().Contain("AEAD service has been disposed");
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
        EncryptedPayload validPayload = new EncryptedPayload(
            Algorithm: "aes-256-gcm",
            IV: new byte[12],
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
        EncryptedPayload invalidPayload = new EncryptedPayload(
            Algorithm: "invalid",
            IV: new byte[12],
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
        EncryptedPayload invalidPayload = new EncryptedPayload(
            Algorithm: "aes-256-gcm",
            IV: new byte[16], // Should be 12
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
        EncryptedPayload invalidPayload = new EncryptedPayload(
            Algorithm: "aes-256-gcm",
            IV: new byte[12],
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
        EncryptedPayload invalidPayload = new EncryptedPayload(
            Algorithm: "aes-256-gcm",
            IV: new byte[12],
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
        EncryptedPayload payload = new EncryptedPayload(
            Algorithm: "aes-256-gcm",
            IV: new byte[12],
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
        Result<CardUuid, SmartCardError> uuid1Result = CardUuid.Generate();
        Result<CardUuid, SmartCardError> uuid2Result = CardUuid.Generate();
        uuid1Result.Should().BeSuccess();
        uuid2Result.Should().BeSuccess();

        uuid1Result.Match(
            uuid1 => uuid2Result.Match(
                uuid2 =>
                {
                    // Act - encrypt same data with different UUIDs
                    Result<EncryptedPayload, SmartCardError> result1 = _service.Encrypt(_validKey, _testPlaintext, uuid1);
                    Result<EncryptedPayload, SmartCardError> result2 = _service.Encrypt(_validKey, _testPlaintext, uuid2);

                    // Assert
                    result1.Should().BeSuccess();
                    result2.Should().BeSuccess();

                    result1.Match(
                        payload1 => result2.Match(
                            payload2 =>
                            {
                                // Different UUIDs should produce different auth tags (due to AAD)
                                _ = payload1.AuthTag.Should().NotBeEquivalentTo(payload2.AuthTag);
                                // Note: Ciphertexts might be different due to different IVs, but auth tags will definitely be different
                            },
                            error => Assert.Fail($"Second encryption failed: {error.Message}")
                        ),
                        error => Assert.Fail($"First encryption failed: {error.Message}")
                    );
                },
                error => Assert.Fail($"Second UUID generation failed: {error.Message}")
            ),
            error => Assert.Fail($"First UUID generation failed: {error.Message}")
        );
    }

    [Test]
    public void UuidBinding_CrossDecryption_ShouldFail()
    {
        // Arrange - create two different UUIDs
        Result<CardUuid, SmartCardError> uuid1Result = CardUuid.Generate();
        Result<CardUuid, SmartCardError> uuid2Result = CardUuid.Generate();
        uuid1Result.Should().BeSuccess();
        uuid2Result.Should().BeSuccess();

        uuid1Result.Match(
            uuid1 => uuid2Result.Match(
                uuid2 =>
                {
                    // Encrypt with uuid1
                    Result<EncryptedPayload, SmartCardError> encryptResult = _service.Encrypt(_validKey, _testPlaintext, uuid1);
                    encryptResult.Should().BeSuccess();

                    encryptResult.Match(
                        encryptedPayload =>
                        {
                            // Try to decrypt with uuid2
                            Result<byte[], SmartCardError> decryptResult = _service.Decrypt(_validKey, encryptedPayload, uuid2);

                            // Should fail due to UUID mismatch in AAD
                            decryptResult.Should().BeFailure();
                            _ = decryptResult.Error.Code.Should().Be("INTEGRITY_ERROR");
                        },
                        error => Assert.Fail($"Encryption failed: {error.Message}")
                    );
                },
                error => Assert.Fail($"Second UUID generation failed: {error.Message}")
            ),
            error => Assert.Fail($"First UUID generation failed: {error.Message}")
        );
    }

}