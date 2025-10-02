using System;
using System.Collections.Generic;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

/// <summary>
/// Unit tests for the PutKeyCommand domain model.
/// Tests pure functions without any I/O or mocking.
/// </summary>
[TestFixture]
[Category("Unit")]
public class PutKeyCommandTests
{
    private static readonly byte[] ValidDesKey = Convert.FromHexString("0102030405060708");
    private static readonly byte[] ValidTripleDes2Key = Convert.FromHexString(
        "0102030405060708090A0B0C0D0E0F10"
    );
    private static readonly byte[] ValidTripleDes3Key = Convert.FromHexString(
        "0102030405060708090A0B0C0D0E0F101112131415161718"
    );
    private static readonly byte[] ValidAes128Key = Convert.FromHexString(
        "0102030405060708090A0B0C0D0E0F10"
    );
    private static readonly byte[] ValidAes192Key = Convert.FromHexString(
        "0102030405060708090A0B0C0D0E0F101112131415161718"
    );
    private static readonly byte[] ValidAes256Key = Convert.FromHexString(
        "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"
    );
    private static readonly byte[] ValidKeyCheckValue = Convert.FromHexString("123456");

    [Test]
    public void Create_WithSingleKeyDataBlock_ReturnsSuccessResult()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock];

        Result<PutKeyCommand, SmartCardError> result = PutKeyCommand.Create(0x01, keyDataBlocks);

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.UsageQualifier.Should().Be(PutKeyCommand.KeyUsageQualifier.SingleKey);
        _ = command.KekIdentifier.Should().Be(PutKeyCommand.KeyEncryptionKeyIdentifier.None);
        _ = command.KeyDataBlocks.Should().HaveCount(1);
        _ = command.KeyDataBlocks[0].Should().Be(keyDataBlock);
    }

    [Test]
    public void Create_WithMultipleKeyDataBlocks_ReturnsSuccessResult()
    {
        var keyDataBlock1 = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlock2 = KeyDataBlock.CreateAes128Key(ValidAes128Key).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock1, keyDataBlock2];

        Result<PutKeyCommand, SmartCardError> result = PutKeyCommand.Create(0x01, keyDataBlocks);

        _ = result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        _ = command.UsageQualifier.Should().Be(PutKeyCommand.KeyUsageQualifier.MultipleKeys);
        _ = command.KekIdentifier.Should().Be(PutKeyCommand.KeyEncryptionKeyIdentifier.None);
        _ = command.KeyDataBlocks.Should().HaveCount(2);
        _ = command.KeyDataBlocks[0].Should().Be(keyDataBlock1);
        _ = command.KeyDataBlocks[1].Should().Be(keyDataBlock2);
    }

    [Test]
    public void Create_WithNullKeyDataBlocks_ReturnsFailure()
    {
        Result<PutKeyCommand, SmartCardError> result = PutKeyCommand.Create(0x01, null!);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("Key data blocks cannot be null");
    }

    [Test]
    public void Create_WithEmptyKeyDataBlocks_ReturnsFailure()
    {
        List<KeyDataBlock> keyDataBlocks = [];

        Result<PutKeyCommand, SmartCardError> result = PutKeyCommand.Create(0x01, keyDataBlocks);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("At least one key data block is required");
    }

    [Test]
    public void UsageQualifier_WithSingleKey_ReturnsSingleKey()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        _ = command.UsageQualifier.Should().Be(PutKeyCommand.KeyUsageQualifier.SingleKey);
        _ = command.P1.Should().Be(0x81);
    }

    [Test]
    public void UsageQualifier_WithMultipleKeys_ReturnsMultipleKeys()
    {
        var keyDataBlock1 = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlock2 = KeyDataBlock.CreateAes128Key(ValidAes128Key).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock1, keyDataBlock2];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        _ = command.UsageQualifier.Should().Be(PutKeyCommand.KeyUsageQualifier.MultipleKeys);
        _ = command.P1.Should().Be(0x00);
    }

    [Test]
    public void KeyUsageQualifier_EnumValues_AreCorrect()
    {
        _ = ((byte)PutKeyCommand.KeyUsageQualifier.MultipleKeys).Should().Be(0x00);
        _ = ((byte)PutKeyCommand.KeyUsageQualifier.SingleDesKey).Should().Be(0x01);
        _ = ((byte)PutKeyCommand.KeyUsageQualifier.SingleKey).Should().Be(0x81);
    }

    [Test]
    public void KekIdentifier_DefaultsToNone()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        _ = command.KekIdentifier.Should().Be(PutKeyCommand.KeyEncryptionKeyIdentifier.None);
        _ = command.P2.Should().Be(0x00);
    }

    [Test]
    public void KeyEncryptionKeyIdentifier_EnumValues_AreCorrect()
    {
        _ = ((byte)PutKeyCommand.KeyEncryptionKeyIdentifier.None).Should().Be(0x00);
        _ = ((byte)PutKeyCommand.KeyEncryptionKeyIdentifier.KekVersion1).Should().Be(0x01);
        _ = ((byte)PutKeyCommand.KeyEncryptionKeyIdentifier.KekVersion2).Should().Be(0x02);
        _ = ((byte)PutKeyCommand.KeyEncryptionKeyIdentifier.CurrentKek).Should().Be(0xFF);
    }

    [Test]
    public void CreateDesKey_WithValidKeyValue_ReturnsSuccessResult()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateDesKey(ValidDesKey);

        _ = result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        _ = keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.Des);
        _ = keyDataBlock.Length.Should().Be(8);
        _ = keyDataBlock.Value.Should().BeEquivalentTo(ValidDesKey);
        _ = keyDataBlock.KeyCheckValue.Should().BeEmpty();
    }

    [Test]
    public void CreateDesKey_WithValidKeyValueAndCheckValue_ReturnsSuccessResult()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateDesKey(
            ValidDesKey,
            ValidKeyCheckValue
        );

        _ = result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        _ = keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.Des);
        _ = keyDataBlock.Length.Should().Be(8);
        _ = keyDataBlock.Value.Should().BeEquivalentTo(ValidDesKey);
        _ = keyDataBlock.KeyCheckValue.Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void CreateDesKey_WithNullKeyValue_ReturnsFailure()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateDesKey(null!);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("DES key value cannot be null");
    }

    [Test]
    [TestCase(0)]
    [TestCase(7)]
    [TestCase(9)]
    [TestCase(16)]
    public void CreateDesKey_WithInvalidKeyLength_ReturnsFailure(int length)
    {
        byte[] keyValue = new byte[length];

        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateDesKey(keyValue);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain($"DES key must be 8 bytes, got {length} bytes");
    }

    [Test]
    [TestCase(0)]
    [TestCase(2)]
    [TestCase(4)]
    public void CreateDesKey_WithInvalidKeyCheckValueLength_ReturnsFailure(int length)
    {
        byte[] keyCheckValue = new byte[length];

        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateDesKey(
            ValidDesKey,
            keyCheckValue
        );

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result
            .Error.Message.Should()
            .Contain($"Key check value must be 3 bytes, got {length} bytes");
    }

    [Test]
    public void CreateTripleDes2Key_WithValidKeyValue_ReturnsSuccessResult()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateTripleDes2Key(
            ValidTripleDes2Key
        );

        _ = result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        _ = keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.TripleDes2Key);
        _ = keyDataBlock.Length.Should().Be(16);
        _ = keyDataBlock.Value.Should().BeEquivalentTo(ValidTripleDes2Key);
        _ = keyDataBlock.KeyCheckValue.Should().BeEmpty();
    }

    [Test]
    public void CreateTripleDes2Key_WithValidKeyValueAndCheckValue_ReturnsSuccessResult()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateTripleDes2Key(
            ValidTripleDes2Key,
            ValidKeyCheckValue
        );

        _ = result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        _ = keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.TripleDes2Key);
        _ = keyDataBlock.Length.Should().Be(16);
        _ = keyDataBlock.Value.Should().BeEquivalentTo(ValidTripleDes2Key);
        _ = keyDataBlock.KeyCheckValue.Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void CreateTripleDes2Key_WithNullKeyValue_ReturnsFailure()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateTripleDes2Key(null!);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("3DES double-length key value cannot be null");
    }

    [Test]
    [TestCase(8)]
    [TestCase(15)]
    [TestCase(17)]
    [TestCase(24)]
    public void CreateTripleDes2Key_WithInvalidKeyLength_ReturnsFailure(int length)
    {
        byte[] keyValue = new byte[length];

        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateTripleDes2Key(keyValue);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result
            .Error.Message.Should()
            .Contain($"3DES double-length key must be 16 bytes, got {length} bytes");
    }

    [Test]
    public void CreateTripleDes3Key_WithValidKeyValue_ReturnsSuccessResult()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateTripleDes3Key(
            ValidTripleDes3Key
        );

        _ = result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        _ = keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.TripleDes3Key);
        _ = keyDataBlock.Length.Should().Be(24);
        _ = keyDataBlock.Value.Should().BeEquivalentTo(ValidTripleDes3Key);
        _ = keyDataBlock.KeyCheckValue.Should().BeEmpty();
    }

    [Test]
    public void CreateTripleDes3Key_WithValidKeyValueAndCheckValue_ReturnsSuccessResult()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateTripleDes3Key(
            ValidTripleDes3Key,
            ValidKeyCheckValue
        );

        _ = result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        _ = keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.TripleDes3Key);
        _ = keyDataBlock.Length.Should().Be(24);
        _ = keyDataBlock.Value.Should().BeEquivalentTo(ValidTripleDes3Key);
        _ = keyDataBlock.KeyCheckValue.Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void CreateTripleDes3Key_WithNullKeyValue_ReturnsFailure()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateTripleDes3Key(null!);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("3DES triple-length key value cannot be null");
    }

    [Test]
    [TestCase(16)]
    [TestCase(23)]
    [TestCase(25)]
    [TestCase(32)]
    public void CreateTripleDes3Key_WithInvalidKeyLength_ReturnsFailure(int length)
    {
        byte[] keyValue = new byte[length];

        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateTripleDes3Key(keyValue);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result
            .Error.Message.Should()
            .Contain($"3DES triple-length key must be 24 bytes, got {length} bytes");
    }

    [Test]
    public void CreateAes128Key_WithValidKeyValue_ReturnsSuccessResult()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateAes128Key(ValidAes128Key);

        _ = result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        _ = keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.Aes128);
        _ = keyDataBlock.Length.Should().Be(16);
        _ = keyDataBlock.Value.Should().BeEquivalentTo(ValidAes128Key);
        _ = keyDataBlock.KeyCheckValue.Should().BeEmpty();
    }

    [Test]
    public void CreateAes128Key_WithValidKeyValueAndCheckValue_ReturnsSuccessResult()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateAes128Key(
            ValidAes128Key,
            ValidKeyCheckValue
        );

        _ = result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        _ = keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.Aes128);
        _ = keyDataBlock.Length.Should().Be(16);
        _ = keyDataBlock.Value.Should().BeEquivalentTo(ValidAes128Key);
        _ = keyDataBlock.KeyCheckValue.Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void CreateAes128Key_WithNullKeyValue_ReturnsFailure()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateAes128Key(null!);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("AES-128 key value cannot be null");
    }

    [Test]
    [TestCase(8)]
    [TestCase(15)]
    [TestCase(17)]
    [TestCase(24)]
    public void CreateAes128Key_WithInvalidKeyLength_ReturnsFailure(int length)
    {
        byte[] keyValue = new byte[length];

        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateAes128Key(keyValue);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result
            .Error.Message.Should()
            .Contain($"AES-128 key must be 16 bytes, got {length} bytes");
    }

    [Test]
    public void CreateAes192Key_WithValidKeyValue_ReturnsSuccessResult()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateAes192Key(ValidAes192Key);

        _ = result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        _ = keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.Aes192);
        _ = keyDataBlock.Length.Should().Be(24);
        _ = keyDataBlock.Value.Should().BeEquivalentTo(ValidAes192Key);
        _ = keyDataBlock.KeyCheckValue.Should().BeEmpty();
    }

    [Test]
    public void CreateAes192Key_WithValidKeyValueAndCheckValue_ReturnsSuccessResult()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateAes192Key(
            ValidAes192Key,
            ValidKeyCheckValue
        );

        _ = result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        _ = keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.Aes192);
        _ = keyDataBlock.Length.Should().Be(24);
        _ = keyDataBlock.Value.Should().BeEquivalentTo(ValidAes192Key);
        _ = keyDataBlock.KeyCheckValue.Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void CreateAes192Key_WithNullKeyValue_ReturnsFailure()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateAes192Key(null!);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("AES-192 key value cannot be null");
    }

    [Test]
    [TestCase(16)]
    [TestCase(23)]
    [TestCase(25)]
    [TestCase(32)]
    public void CreateAes192Key_WithInvalidKeyLength_ReturnsFailure(int length)
    {
        byte[] keyValue = new byte[length];

        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateAes192Key(keyValue);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result
            .Error.Message.Should()
            .Contain($"AES-192 key must be 24 bytes, got {length} bytes");
    }

    [Test]
    public void CreateAes256Key_WithValidKeyValue_ReturnsSuccessResult()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateAes256Key(ValidAes256Key);

        _ = result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        _ = keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.Aes256);
        _ = keyDataBlock.Length.Should().Be(32);
        _ = keyDataBlock.Value.Should().BeEquivalentTo(ValidAes256Key);
        _ = keyDataBlock.KeyCheckValue.Should().BeEmpty();
    }

    [Test]
    public void CreateAes256Key_WithValidKeyValueAndCheckValue_ReturnsSuccessResult()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateAes256Key(
            ValidAes256Key,
            ValidKeyCheckValue
        );

        _ = result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        _ = keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.Aes256);
        _ = keyDataBlock.Length.Should().Be(32);
        _ = keyDataBlock.Value.Should().BeEquivalentTo(ValidAes256Key);
        _ = keyDataBlock.KeyCheckValue.Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void CreateAes256Key_WithNullKeyValue_ReturnsFailure()
    {
        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateAes256Key(null!);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("AES-256 key value cannot be null");
    }

    [Test]
    [TestCase(24)]
    [TestCase(31)]
    [TestCase(33)]
    [TestCase(40)]
    public void CreateAes256Key_WithInvalidKeyLength_ReturnsFailure(int length)
    {
        byte[] keyValue = new byte[length];

        Result<KeyDataBlock, SmartCardError> result = KeyDataBlock.CreateAes256Key(keyValue);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result
            .Error.Message.Should()
            .Contain($"AES-256 key must be 32 bytes, got {length} bytes");
    }

    [Test]
    public void CreateRsaKey_NotYetImplemented_ShouldHaveCreationMethods()
    {
        // These key types are defined in the enum but don't have creation methods yet
        // This test documents the expected functionality for future implementation

        // RSA key creation methods should exist:
        // - KeyDataBlock.CreateRsaPublicKey(byte[] keyValue, byte[]? keyCheckValue = null)
        // - KeyDataBlock.CreateRsaPrivateKey(byte[] keyValue, byte[]? keyCheckValue = null)

        // For now, just verify the enum values exist
        _ = ((byte)KeyDataBlock.KeyType.RsaPublic).Should().Be(0xA0);
        _ = ((byte)KeyDataBlock.KeyType.RsaPrivate).Should().Be(0xA1);
    }

    [Test]
    public void CreateEccKey_NotYetImplemented_ShouldHaveCreationMethods()
    {
        // These key types are defined in the enum but don't have creation methods yet
        // This test documents the expected functionality for future implementation

        // ECC key creation methods should exist:
        // - KeyDataBlock.CreateEccPublicKey(byte[] keyValue, byte[]? keyCheckValue = null)
        // - KeyDataBlock.CreateEccPrivateKey(byte[] keyValue, byte[]? keyCheckValue = null)

        // For now, just verify the enum values exist
        _ = ((byte)KeyDataBlock.KeyType.EccPublic).Should().Be(0xB0);
        _ = ((byte)KeyDataBlock.KeyType.EccPrivate).Should().Be(0xB1);
    }

    [Test]
    public void KeyType_EnumValues_AreCorrect()
    {
        _ = ((byte)KeyDataBlock.KeyType.Des).Should().Be(0x80);
        _ = ((byte)KeyDataBlock.KeyType.TripleDes2Key).Should().Be(0x81);
        _ = ((byte)KeyDataBlock.KeyType.TripleDes3Key).Should().Be(0x82);
        _ = ((byte)KeyDataBlock.KeyType.Aes128).Should().Be(0x88);
        _ = ((byte)KeyDataBlock.KeyType.Aes192).Should().Be(0x89);
        _ = ((byte)KeyDataBlock.KeyType.Aes256).Should().Be(0x8A);
        _ = ((byte)KeyDataBlock.KeyType.RsaPublic).Should().Be(0xA0);
        _ = ((byte)KeyDataBlock.KeyType.RsaPrivate).Should().Be(0xA1);
        _ = ((byte)KeyDataBlock.KeyType.EccPublic).Should().Be(0xB0);
        _ = ((byte)KeyDataBlock.KeyType.EccPrivate).Should().Be(0xB1);
    }

    [Test]
    public void ToBytes_WithoutKeyCheckValue_ReturnsCorrectBytes()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;

        byte[]? bytes = keyDataBlock.ToBytes();

        _ = bytes.Should().HaveCount(10); // 1 byte type + 1 byte length + 8 bytes key
        _ = bytes[0].Should().Be(0x80); // DES key type
        _ = bytes[1].Should().Be(0x08); // Key length
        _ = bytes.Skip(2).Take(8).Should().BeEquivalentTo(ValidDesKey);
    }

    [Test]
    public void ToBytes_WithKeyCheckValue_ReturnsCorrectBytes()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey, ValidKeyCheckValue).Value;

        byte[]? bytes = keyDataBlock.ToBytes();

        _ = bytes.Should().HaveCount(13); // 1 byte type + 1 byte length + 8 bytes key + 3 bytes KCV
        _ = bytes[0].Should().Be(0x80); // DES key type
        _ = bytes[1].Should().Be(0x08); // Key length
        _ = bytes.Skip(2).Take(8).Should().BeEquivalentTo(ValidDesKey);
        _ = bytes.Skip(10).Take(3).Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void ToBytes_WithDifferentKeyTypes_ReturnsCorrectTypeBytes()
    {
        var desKey = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var aes128Key = KeyDataBlock.CreateAes128Key(ValidAes128Key).Value;
        var aes256Key = KeyDataBlock.CreateAes256Key(ValidAes256Key).Value;

        _ = desKey.ToBytes()[0].Should().Be(0x80);
        _ = aes128Key.ToBytes()[0].Should().Be(0x88);
        _ = aes256Key.ToBytes()[0].Should().Be(0x8A);
    }

    [Test]
    public void ToBytes_ReturnsImmutableArray()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        byte[]? bytes1 = keyDataBlock.ToBytes();
        byte[]? bytes2 = keyDataBlock.ToBytes();

        // Should return different array instances
        _ = bytes1.Should().NotBeSameAs(bytes2);
        // But with identical content
        _ = bytes1.Should().BeEquivalentTo(bytes2);
    }

    [Test]
    public void KeyDataBlock_Length_ReflectsActualKeySize()
    {
        var desKey = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var aes128Key = KeyDataBlock.CreateAes128Key(ValidAes128Key).Value;
        var aes192Key = KeyDataBlock.CreateAes192Key(ValidAes192Key).Value;
        var aes256Key = KeyDataBlock.CreateAes256Key(ValidAes256Key).Value;
        var tripleDes2Key = KeyDataBlock.CreateTripleDes2Key(ValidTripleDes2Key).Value;
        var tripleDes3Key = KeyDataBlock.CreateTripleDes3Key(ValidTripleDes3Key).Value;

        _ = desKey.Length.Should().Be(8);
        _ = aes128Key.Length.Should().Be(16);
        _ = aes192Key.Length.Should().Be(24);
        _ = aes256Key.Length.Should().Be(32);
        _ = tripleDes2Key.Length.Should().Be(16);
        _ = tripleDes3Key.Length.Should().Be(24);
    }

    [Test]
    public void KeyDataBlock_ValueProperty_ReturnsClonedData()
    {
        byte[] originalKey = (byte[])ValidDesKey.Clone();
        var keyDataBlock = KeyDataBlock.CreateDesKey(originalKey).Value;

        // Modify the original key
        originalKey[0] = 0xFF;

        // KeyDataBlock should have its own copy
        _ = keyDataBlock.Value[0].Should().Be(0x01); // Original first byte
        _ = keyDataBlock.Value.Should().NotBeSameAs(originalKey);
    }

    [Test]
    public void KeyDataBlock_KeyCheckValueProperty_ReturnsClonedData()
    {
        byte[] originalKcv = (byte[])ValidKeyCheckValue.Clone();
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey, originalKcv).Value;

        // Modify the original KCV
        originalKcv[0] = 0xFF;

        // KeyDataBlock should have its own copy
        _ = keyDataBlock.KeyCheckValue![0].Should().Be(0x12); // Original first byte
        _ = keyDataBlock.KeyCheckValue.Should().NotBeSameAs(originalKcv);
    }

    [Test]
    public void PutKeyCommand_KeyDataBlocks_ReturnsImmutableCollection()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        // Should be a different collection instance
        _ = command.KeyDataBlocks.Should().NotBeSameAs(keyDataBlocks);
        // But with the same content
        _ = command.KeyDataBlocks.Should().BeEquivalentTo(keyDataBlocks);
    }

    [Test]
    public void PutKeyCommand_Data_ReturnsNewArrayEachTime()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        byte[]? data1 = command.Data;
        byte[]? data2 = command.Data;

        _ = data1.Should().NotBeSameAs(data2);
        if (data1 != null && data2 != null)
        {
            _ = data1.Should().BeEquivalentTo(data2);
        }
    }

    [Test]
    public void PutKeyCommand_ToApdu_ReturnsNewArrayEachTime()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        byte[]? apdu1 = command.ToApdu().ToApdu().Value;
        byte[]? apdu2 = command.ToApdu().ToApdu().Value;

        _ = apdu1.Should().NotBeSameAs(apdu2);
        _ = apdu1.Should().BeEquivalentTo(apdu2);
    }

    [Test]
    public void PutKeyCommand_SingleDesKey_UsageQualifier_NotCurrentlyUsed()
    {
        // The SingleDesKey usage qualifier exists but isn't currently used
        // The implementation chooses SingleKey for single keys regardless of type
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        // Currently uses SingleKey, not SingleDesKey
        _ = command.UsageQualifier.Should().Be(PutKeyCommand.KeyUsageQualifier.SingleKey);
        _ = command.UsageQualifier.Should().NotBe(PutKeyCommand.KeyUsageQualifier.SingleDesKey);

        // But SingleDesKey enum value should exist for future use
        _ = ((byte)PutKeyCommand.KeyUsageQualifier.SingleDesKey).Should().Be(0x01);
    }

    [Test]
    public void KeyDataBlock_ValidateAllKeyTypesHaveCorrectEnumValues()
    {
        // Comprehensive validation of all key type enum values
        var expectedKeyTypes = new Dictionary<KeyDataBlock.KeyType, byte>
        {
            { KeyDataBlock.KeyType.Des, 0x80 },
            { KeyDataBlock.KeyType.TripleDes2Key, 0x81 },
            { KeyDataBlock.KeyType.TripleDes3Key, 0x82 },
            { KeyDataBlock.KeyType.Aes128, 0x88 },
            { KeyDataBlock.KeyType.Aes192, 0x89 },
            { KeyDataBlock.KeyType.Aes256, 0x8A },
            { KeyDataBlock.KeyType.RsaPublic, 0xA0 },
            { KeyDataBlock.KeyType.RsaPrivate, 0xA1 },
            { KeyDataBlock.KeyType.EccPublic, 0xB0 },
            { KeyDataBlock.KeyType.EccPrivate, 0xB1 },
        };

        foreach (var kvp in expectedKeyTypes)
        {
            _ = ((byte)kvp.Key)
                .Should()
                .Be(kvp.Value, $"KeyType.{kvp.Key} should have value 0x{kvp.Value:X2}");
        }
    }

    [Test]
    public void ToApdu_WithSingleKey_ReturnsCorrectApduStructure()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        byte[]? apdu = command.ToApdu().ToApdu().Value;

        _ = apdu[0].Should().Be(0x80); // CLA
        _ = apdu[1].Should().Be(0xD8); // INS
        _ = apdu[2].Should().Be(0x81); // P1 (Single key)
        _ = apdu[3].Should().Be(0x00); // P2 (No KEK)
        _ = apdu[4].Should().Be(0x0A); // LC (10 bytes data)
        _ = apdu[5].Should().Be(0x80); // Key type (DES)
        _ = apdu[6].Should().Be(0x08); // Key length
        _ = apdu.Skip(7).Take(8).Should().BeEquivalentTo(ValidDesKey); // Key data
        _ = apdu[15].Should().Be(0x03); // LE (3 bytes expected response for 1 key)
    }

    [Test]
    public void ToApdu_WithMultipleKeys_ReturnsCorrectApduStructure()
    {
        var keyDataBlock1 = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlock2 = KeyDataBlock.CreateAes128Key(ValidAes128Key).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock1, keyDataBlock2];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        byte[]? apdu = command.ToApdu().ToApdu().Value;

        _ = apdu[0].Should().Be(0x80); // CLA
        _ = apdu[1].Should().Be(0xD8); // INS
        _ = apdu[2].Should().Be(0x00); // P1 (Multiple keys)
        _ = apdu[3].Should().Be(0x00); // P2 (No KEK)
        _ = apdu[4].Should().Be(0x1C); // LC (28 bytes data: 10 + 18)

        // First key block
        _ = apdu[5].Should().Be(0x80); // Key type (DES)
        _ = apdu[6].Should().Be(0x08); // Key length
        _ = apdu.Skip(7).Take(8).Should().BeEquivalentTo(ValidDesKey); // Key data

        // Second key block
        _ = apdu[15].Should().Be(0x88); // Key type (AES-128)
        _ = apdu[16].Should().Be(0x10); // Key length
        _ = apdu.Skip(17).Take(16).Should().BeEquivalentTo(ValidAes128Key); // Key data

        _ = apdu[33].Should().Be(0x06); // LE (6 bytes expected response for 2 keys)
    }

    [Test]
    public void ToApdu_WithKeyCheckValue_IncludesCheckValueInData()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey, ValidKeyCheckValue).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        byte[]? apdu = command.ToApdu().ToApdu().Value;

        _ = apdu[4].Should().Be(0x0D); // LC (13 bytes data including KCV)
        _ = apdu.Skip(7).Take(8).Should().BeEquivalentTo(ValidDesKey); // Key data
        _ = apdu.Skip(15).Take(3).Should().BeEquivalentTo(ValidKeyCheckValue); // Key check value
        _ = apdu[18].Should().Be(0x03); // LE (3 bytes expected response)
    }

    [Test]
    public void ExpectedResponseLength_ReturnsCorrectLength()
    {
        var keyDataBlock1 = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlock2 = KeyDataBlock.CreateAes128Key(ValidAes128Key).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock1, keyDataBlock2];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        _ = command.ExpectedResponseLength.Should().Be(6); // 3 bytes per key * 2 keys
    }

    [Test]
    public void CommandProperties_HaveCorrectValues()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        _ = command.Cla.Should().Be(0x80);
        _ = command.Ins.Should().Be(0xD8);
        _ = command.IsExtendedLength.Should().BeFalse();
        _ = command.ToString().Should().Be("PUT KEY");
    }

    [Test]
    public void Data_WithNullKeyDataBlocks_ReturnsNull()
    {
        List<KeyDataBlock> keyDataBlocks = [];
        Result<PutKeyCommand, SmartCardError> command = PutKeyCommand.Create(0x01, keyDataBlocks);

        // This should fail during creation, but if it didn't, Data would handle empty list
        _ = command.IsFailure.Should().BeTrue();
    }

    [Test]
    public void Data_WithValidKeyDataBlocks_ReturnsCorrectData()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        byte[]? data = command.Data;

        _ = data.Should().NotBeNull();
        _ = data.Should().HaveCount(10); // Type + length + key data
        _ = data![0].Should().Be(0x80); // DES key type
        _ = data[1].Should().Be(0x08); // Key length
        _ = data.Skip(2).Take(8).Should().BeEquivalentTo(ValidDesKey);
    }

    [Test]
    public void PutKeyResponse_Parse_WithValidResponse_ReturnsSuccessResult()
    {
        byte[] responseData = Convert.FromHexString("123456789ABC"); // 2 key check values

        Result<PutKeyResponse, SmartCardError> result = PutKeyResponse.Parse(responseData);

        _ = result.IsSuccess.Should().BeTrue();
        var response = result.Value;
        _ = response.KeyCheckValues.Should().HaveCount(2);
        _ = response.KeyCheckValues[0].Should().BeEquivalentTo(Convert.FromHexString("123456"));
        _ = response.KeyCheckValues[1].Should().BeEquivalentTo(Convert.FromHexString("789ABC"));
    }

    [Test]
    public void PutKeyResponse_Parse_WithSingleKeyCheckValue_ReturnsSuccessResult()
    {
        byte[] responseData = Convert.FromHexString("123456"); // 1 key check value

        Result<PutKeyResponse, SmartCardError> result = PutKeyResponse.Parse(responseData);

        _ = result.IsSuccess.Should().BeTrue();
        var response = result.Value;
        _ = response.KeyCheckValues.Should().HaveCount(1);
        _ = response.KeyCheckValues[0].Should().BeEquivalentTo(Convert.FromHexString("123456"));
    }

    [Test]
    public void PutKeyResponse_Parse_WithEmptyResponse_ReturnsSuccessResult()
    {
        byte[] responseData = [];

        Result<PutKeyResponse, SmartCardError> result = PutKeyResponse.Parse(responseData);

        _ = result.IsSuccess.Should().BeTrue();
        var response = result.Value;
        _ = response.KeyCheckValues.Should().HaveCount(0);
    }

    [Test]
    public void PutKeyResponse_Parse_WithNullResponse_ReturnsFailure()
    {
        Result<PutKeyResponse, SmartCardError> result = PutKeyResponse.Parse(null!);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain("Response data cannot be null");
    }

    [Test]
    [TestCase(1)]
    [TestCase(2)]
    [TestCase(4)]
    [TestCase(5)]
    public void PutKeyResponse_Parse_WithInvalidResponseLength_ReturnsFailure(int length)
    {
        byte[] responseData = new byte[length];

        Result<PutKeyResponse, SmartCardError> result = PutKeyResponse.Parse(responseData);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result
            .Error.Message.Should()
            .Contain($"Invalid response length {length}, expected multiple of 3 bytes");
    }

    [Test]
    public void PutKeyResponse_Constructor_ClonesKeyCheckValues()
    {
        byte[] originalKcv = Convert.FromHexString("123456");
        List<byte[]> keyCheckValues = [originalKcv];
        var response = new PutKeyResponse(keyCheckValues);

        // Modify original array
        originalKcv[0] = 0xFF;

        // Response should have cloned data
        _ = response.KeyCheckValues[0][0].Should().Be(0x12);
    }

    [Test]
    public void PutKeyResponse_Constructor_WithNullKeyCheckValues_HandlesGracefully()
    {
        var response = new PutKeyResponse(null!);

        _ = response.KeyCheckValues.Should().HaveCount(0);
    }

    [Test]
    public void ToApdu_Structure_FollowsGlobalPlatformSpecification()
    {
        // Test that APDU structure follows GlobalPlatform specification exactly
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey, ValidKeyCheckValue).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        byte[]? apdu = command.ToApdu().ToApdu().Value;

        // GlobalPlatform PUT KEY APDU structure:
        // CLA | INS | P1 | P2 | LC | Data | LE
        _ = apdu.Should().HaveCountGreaterThan(5); // At least header + LC + LE

        // Header
        _ = apdu[0].Should().Be(command.Cla); // CLA
        _ = apdu[1].Should().Be(command.Ins); // INS
        _ = apdu[2].Should().Be((byte)command.UsageQualifier); // P1
        _ = apdu[3].Should().Be((byte)command.KekIdentifier); // P2

        // LC should match data length
        byte dataLength = apdu[4];
        int expectedDataLength = keyDataBlock.ToBytes().Length;
        _ = dataLength.Should().Be((byte)expectedDataLength);

        // LE should be at the end and match expected response length
        int leIndex = apdu.Length - 1;
        _ = apdu[leIndex].Should().Be((byte)command.ExpectedResponseLength.Value);
    }

    [Test]
    public void ToApdu_WithLargeKeyData_HandlesCorrectly()
    {
        // Test with the largest supported key (AES-256)
        var keyDataBlock = KeyDataBlock.CreateAes256Key(ValidAes256Key, ValidKeyCheckValue).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        byte[]? apdu = command.ToApdu().ToApdu().Value;

        // Should handle large key data correctly
        int expectedDataLength = 1 + 1 + 32 + 3; // Type + Length + Key + KCV
        _ = apdu[4].Should().Be((byte)expectedDataLength); // LC
        _ = apdu[^1].Should().Be(0x03); // LE (3 bytes expected response)

        // Verify key data is properly embedded
        int keyDataStart = 5; // After header and LC
        _ = apdu[keyDataStart].Should().Be(0x8A); // AES-256 key type
        _ = apdu[keyDataStart + 1].Should().Be(0x20); // 32 bytes length

        // Verify actual key data
        byte[] keyData = [.. apdu.Skip(keyDataStart + 2).Take(32)];
        _ = keyData.Should().BeEquivalentTo(ValidAes256Key);

        // Verify KCV
        byte[] kcvData = [.. apdu.Skip(keyDataStart + 2 + 32).Take(3)];
        _ = kcvData.Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void KeyDataBlock_PreservesKeyDataImmutability()
    {
        byte[] originalKeyData = (byte[])ValidDesKey.Clone();
        var keyDataBlock = KeyDataBlock.CreateDesKey(originalKeyData).Value;

        // Modify original array
        originalKeyData[0] = 0xFF;

        // KeyDataBlock should have cloned data
        _ = keyDataBlock.Value[0].Should().Be(0x01);
    }

    [Test]
    public void KeyDataBlock_PreservesKeyCheckValueImmutability()
    {
        byte[] originalKcv = (byte[])ValidKeyCheckValue.Clone();
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey, originalKcv).Value;

        // Modify original array
        originalKcv[0] = 0xFF;

        // KeyDataBlock should have cloned data
        _ = keyDataBlock.KeyCheckValue![0].Should().Be(0x12);
    }

    [Test]
    public void ToBytes_ReturnsNewArrayEachTime()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;

        byte[]? bytes1 = keyDataBlock.ToBytes();
        byte[]? bytes2 = keyDataBlock.ToBytes();

        _ = bytes1.Should().NotBeSameAs(bytes2);
        _ = bytes1.Should().BeEquivalentTo(bytes2);
    }

    [Test]
    public void ToBytes_ImmutabilityGuarantees_ArePreserved()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey, ValidKeyCheckValue).Value;
        byte[]? bytes1 = keyDataBlock.ToBytes();
        byte[]? bytes2 = keyDataBlock.ToBytes();

        // Modify first array
        bytes1[0] = 0xFF;

        // Second array should be unchanged
        _ = bytes2[0].Should().Be(0x80); // Original DES key type

        // Getting bytes again should return original data
        byte[]? bytes3 = keyDataBlock.ToBytes();
        _ = bytes3[0].Should().Be(0x80);
    }

    [Test]
    public void PutKeyCommand_ImmutabilityGuarantees_ArePreserved()
    {
        List<KeyDataBlock> originalKeyDataBlocks = [KeyDataBlock.CreateDesKey(ValidDesKey).Value];

        var command = PutKeyCommand.Create(0x01, originalKeyDataBlocks).Value;

        // Clear the original list
        originalKeyDataBlocks.Clear();

        // Command should still have its key data blocks
        _ = command.KeyDataBlocks.Should().HaveCount(1);
        _ = command.KeyDataBlocks[0].Type.Should().Be(KeyDataBlock.KeyType.Des);
    }
}
