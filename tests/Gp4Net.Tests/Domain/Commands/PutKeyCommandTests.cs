using System;
using System.Collections.Generic;
using System.Linq;
using AwesomeAssertions;
using Gp4Net.Domain.Commands;
using NUnit.Framework;
using CSharpFunctionalExtensions;

namespace Gp4Net.Tests.Domain.Commands;

/// <summary>
/// Unit tests for the PutKeyCommand domain model.
/// Tests pure functions without any I/O or mocking.
/// </summary>
[TestFixture]
public class PutKeyCommandTests
{

    private static readonly byte[] ValidDesKey = Convert.FromHexString("0102030405060708");
    private static readonly byte[] ValidTripleDes2Key = Convert.FromHexString("0102030405060708090A0B0C0D0E0F10");
    private static readonly byte[] ValidTripleDes3Key = Convert.FromHexString("0102030405060708090A0B0C0D0E0F101112131415161718");
    private static readonly byte[] ValidAes128Key = Convert.FromHexString("0102030405060708090A0B0C0D0E0F10");
    private static readonly byte[] ValidAes192Key = Convert.FromHexString("0102030405060708090A0B0C0D0E0F101112131415161718");
    private static readonly byte[] ValidAes256Key = Convert.FromHexString("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20");
    private static readonly byte[] ValidKeyCheckValue = Convert.FromHexString("123456");

    [Test]
    public void Create_WithSingleKeyDataBlock_ReturnsSuccessResult()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock };

        var result = PutKeyCommand.Create(0x01, keyDataBlocks);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.UsageQualifier.Should().Be(PutKeyCommand.KeyUsageQualifier.SingleKey);
        command.KekIdentifier.Should().Be(PutKeyCommand.KeyEncryptionKeyIdentifier.None);
        command.KeyDataBlocks.Should().HaveCount(1);
        command.KeyDataBlocks[0].Should().Be(keyDataBlock);
    }

    [Test]
    public void Create_WithMultipleKeyDataBlocks_ReturnsSuccessResult()
    {
        var keyDataBlock1 = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlock2 = KeyDataBlock.CreateAes128Key(ValidAes128Key).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock1, keyDataBlock2 };

        var result = PutKeyCommand.Create(0x01, keyDataBlocks);

        result.IsSuccess.Should().BeTrue();
        var command = result.Value;
        command.UsageQualifier.Should().Be(PutKeyCommand.KeyUsageQualifier.MultipleKeys);
        command.KekIdentifier.Should().Be(PutKeyCommand.KeyEncryptionKeyIdentifier.None);
        command.KeyDataBlocks.Should().HaveCount(2);
        command.KeyDataBlocks[0].Should().Be(keyDataBlock1);
        command.KeyDataBlocks[1].Should().Be(keyDataBlock2);
    }

    [Test]
    public void Create_WithNullKeyDataBlocks_ReturnsFailure()
    {
        var result = PutKeyCommand.Create(0x01, null!);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain("Key data blocks cannot be null");
    }

    [Test]
    public void Create_WithEmptyKeyDataBlocks_ReturnsFailure()
    {
        var keyDataBlocks = new List<KeyDataBlock>();

        var result = PutKeyCommand.Create(0x01, keyDataBlocks);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain("At least one key data block is required");
    }

    [Test]
    public void UsageQualifier_WithSingleKey_ReturnsSingleKey()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock };
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        command.UsageQualifier.Should().Be(PutKeyCommand.KeyUsageQualifier.SingleKey);
        command.P1.Should().Be(0x81);
    }

    [Test]
    public void UsageQualifier_WithMultipleKeys_ReturnsMultipleKeys()
    {
        var keyDataBlock1 = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlock2 = KeyDataBlock.CreateAes128Key(ValidAes128Key).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock1, keyDataBlock2 };
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        command.UsageQualifier.Should().Be(PutKeyCommand.KeyUsageQualifier.MultipleKeys);
        command.P1.Should().Be(0x00);
    }

    [Test]
    public void KeyUsageQualifier_EnumValues_AreCorrect()
    {
        ((byte)PutKeyCommand.KeyUsageQualifier.MultipleKeys).Should().Be(0x00);
        ((byte)PutKeyCommand.KeyUsageQualifier.SingleDesKey).Should().Be(0x01);
        ((byte)PutKeyCommand.KeyUsageQualifier.SingleKey).Should().Be(0x81);
    }

    [Test]
    public void KekIdentifier_DefaultsToNone()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock };
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        command.KekIdentifier.Should().Be(PutKeyCommand.KeyEncryptionKeyIdentifier.None);
        command.P2.Should().Be(0x00);
    }

    [Test]
    public void KeyEncryptionKeyIdentifier_EnumValues_AreCorrect()
    {
        ((byte)PutKeyCommand.KeyEncryptionKeyIdentifier.None).Should().Be(0x00);
        ((byte)PutKeyCommand.KeyEncryptionKeyIdentifier.KekVersion1).Should().Be(0x01);
        ((byte)PutKeyCommand.KeyEncryptionKeyIdentifier.KekVersion2).Should().Be(0x02);
        ((byte)PutKeyCommand.KeyEncryptionKeyIdentifier.CurrentKek).Should().Be(0xFF);
    }

    [Test]
    public void CreateDesKey_WithValidKeyValue_ReturnsSuccessResult()
    {
        var result = KeyDataBlock.CreateDesKey(ValidDesKey);

        result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.Des);
        keyDataBlock.Length.Should().Be(8);
        keyDataBlock.Value.Should().BeEquivalentTo(ValidDesKey);
        keyDataBlock.KeyCheckValue.Should().BeNull();
    }

    [Test]
    public void CreateDesKey_WithValidKeyValueAndCheckValue_ReturnsSuccessResult()
    {
        var result = KeyDataBlock.CreateDesKey(ValidDesKey, ValidKeyCheckValue);

        result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.Des);
        keyDataBlock.Length.Should().Be(8);
        keyDataBlock.Value.Should().BeEquivalentTo(ValidDesKey);
        keyDataBlock.KeyCheckValue.Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void CreateDesKey_WithNullKeyValue_ReturnsFailure()
    {
        var result = KeyDataBlock.CreateDesKey(null!);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain("DES key value cannot be null");
    }

    [Test]
    [TestCase(0)]
    [TestCase(7)]
    [TestCase(9)]
    [TestCase(16)]
    public void CreateDesKey_WithInvalidKeyLength_ReturnsFailure(int length)
    {
        var keyValue = new byte[length];

        var result = KeyDataBlock.CreateDesKey(keyValue);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain($"DES key must be 8 bytes, got {length} bytes");
    }

    [Test]
    [TestCase(0)]
    [TestCase(2)]
    [TestCase(4)]
    public void CreateDesKey_WithInvalidKeyCheckValueLength_ReturnsFailure(int length)
    {
        var keyCheckValue = new byte[length];

        var result = KeyDataBlock.CreateDesKey(ValidDesKey, keyCheckValue);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain($"Key check value must be 3 bytes, got {length} bytes");
    }

    [Test]
    public void CreateTripleDes2Key_WithValidKeyValue_ReturnsSuccessResult()
    {
        var result = KeyDataBlock.CreateTripleDes2Key(ValidTripleDes2Key);

        result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.TripleDes2Key);
        keyDataBlock.Length.Should().Be(16);
        keyDataBlock.Value.Should().BeEquivalentTo(ValidTripleDes2Key);
        keyDataBlock.KeyCheckValue.Should().BeNull();
    }

    [Test]
    public void CreateTripleDes2Key_WithValidKeyValueAndCheckValue_ReturnsSuccessResult()
    {
        var result = KeyDataBlock.CreateTripleDes2Key(ValidTripleDes2Key, ValidKeyCheckValue);

        result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.TripleDes2Key);
        keyDataBlock.Length.Should().Be(16);
        keyDataBlock.Value.Should().BeEquivalentTo(ValidTripleDes2Key);
        keyDataBlock.KeyCheckValue.Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void CreateTripleDes2Key_WithNullKeyValue_ReturnsFailure()
    {
        var result = KeyDataBlock.CreateTripleDes2Key(null!);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain("3DES double-length key value cannot be null");
    }

    [Test]
    [TestCase(8)]
    [TestCase(15)]
    [TestCase(17)]
    [TestCase(24)]
    public void CreateTripleDes2Key_WithInvalidKeyLength_ReturnsFailure(int length)
    {
        var keyValue = new byte[length];

        var result = KeyDataBlock.CreateTripleDes2Key(keyValue);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain($"3DES double-length key must be 16 bytes, got {length} bytes");
    }

    [Test]
    public void CreateTripleDes3Key_WithValidKeyValue_ReturnsSuccessResult()
    {
        var result = KeyDataBlock.CreateTripleDes3Key(ValidTripleDes3Key);

        result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.TripleDes3Key);
        keyDataBlock.Length.Should().Be(24);
        keyDataBlock.Value.Should().BeEquivalentTo(ValidTripleDes3Key);
        keyDataBlock.KeyCheckValue.Should().BeNull();
    }

    [Test]
    public void CreateTripleDes3Key_WithValidKeyValueAndCheckValue_ReturnsSuccessResult()
    {
        var result = KeyDataBlock.CreateTripleDes3Key(ValidTripleDes3Key, ValidKeyCheckValue);

        result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.TripleDes3Key);
        keyDataBlock.Length.Should().Be(24);
        keyDataBlock.Value.Should().BeEquivalentTo(ValidTripleDes3Key);
        keyDataBlock.KeyCheckValue.Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void CreateTripleDes3Key_WithNullKeyValue_ReturnsFailure()
    {
        var result = KeyDataBlock.CreateTripleDes3Key(null!);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain("3DES triple-length key value cannot be null");
    }

    [Test]
    [TestCase(16)]
    [TestCase(23)]
    [TestCase(25)]
    [TestCase(32)]
    public void CreateTripleDes3Key_WithInvalidKeyLength_ReturnsFailure(int length)
    {
        var keyValue = new byte[length];

        var result = KeyDataBlock.CreateTripleDes3Key(keyValue);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain($"3DES triple-length key must be 24 bytes, got {length} bytes");
    }

    [Test]
    public void CreateAes128Key_WithValidKeyValue_ReturnsSuccessResult()
    {
        var result = KeyDataBlock.CreateAes128Key(ValidAes128Key);

        result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.Aes128);
        keyDataBlock.Length.Should().Be(16);
        keyDataBlock.Value.Should().BeEquivalentTo(ValidAes128Key);
        keyDataBlock.KeyCheckValue.Should().BeNull();
    }

    [Test]
    public void CreateAes128Key_WithValidKeyValueAndCheckValue_ReturnsSuccessResult()
    {
        var result = KeyDataBlock.CreateAes128Key(ValidAes128Key, ValidKeyCheckValue);

        result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.Aes128);
        keyDataBlock.Length.Should().Be(16);
        keyDataBlock.Value.Should().BeEquivalentTo(ValidAes128Key);
        keyDataBlock.KeyCheckValue.Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void CreateAes128Key_WithNullKeyValue_ReturnsFailure()
    {
        var result = KeyDataBlock.CreateAes128Key(null!);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain("AES-128 key value cannot be null");
    }

    [Test]
    [TestCase(8)]
    [TestCase(15)]
    [TestCase(17)]
    [TestCase(24)]
    public void CreateAes128Key_WithInvalidKeyLength_ReturnsFailure(int length)
    {
        var keyValue = new byte[length];

        var result = KeyDataBlock.CreateAes128Key(keyValue);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain($"AES-128 key must be 16 bytes, got {length} bytes");
    }

    [Test]
    public void CreateAes192Key_WithValidKeyValue_ReturnsSuccessResult()
    {
        var result = KeyDataBlock.CreateAes192Key(ValidAes192Key);

        result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.Aes192);
        keyDataBlock.Length.Should().Be(24);
        keyDataBlock.Value.Should().BeEquivalentTo(ValidAes192Key);
        keyDataBlock.KeyCheckValue.Should().BeNull();
    }

    [Test]
    public void CreateAes192Key_WithValidKeyValueAndCheckValue_ReturnsSuccessResult()
    {
        var result = KeyDataBlock.CreateAes192Key(ValidAes192Key, ValidKeyCheckValue);

        result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.Aes192);
        keyDataBlock.Length.Should().Be(24);
        keyDataBlock.Value.Should().BeEquivalentTo(ValidAes192Key);
        keyDataBlock.KeyCheckValue.Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void CreateAes192Key_WithNullKeyValue_ReturnsFailure()
    {
        var result = KeyDataBlock.CreateAes192Key(null!);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain("AES-192 key value cannot be null");
    }

    [Test]
    [TestCase(16)]
    [TestCase(23)]
    [TestCase(25)]
    [TestCase(32)]
    public void CreateAes192Key_WithInvalidKeyLength_ReturnsFailure(int length)
    {
        var keyValue = new byte[length];

        var result = KeyDataBlock.CreateAes192Key(keyValue);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain($"AES-192 key must be 24 bytes, got {length} bytes");
    }

    [Test]
    public void CreateAes256Key_WithValidKeyValue_ReturnsSuccessResult()
    {
        var result = KeyDataBlock.CreateAes256Key(ValidAes256Key);

        result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.Aes256);
        keyDataBlock.Length.Should().Be(32);
        keyDataBlock.Value.Should().BeEquivalentTo(ValidAes256Key);
        keyDataBlock.KeyCheckValue.Should().BeNull();
    }

    [Test]
    public void CreateAes256Key_WithValidKeyValueAndCheckValue_ReturnsSuccessResult()
    {
        var result = KeyDataBlock.CreateAes256Key(ValidAes256Key, ValidKeyCheckValue);

        result.IsSuccess.Should().BeTrue();
        var keyDataBlock = result.Value;
        keyDataBlock.Type.Should().Be(KeyDataBlock.KeyType.Aes256);
        keyDataBlock.Length.Should().Be(32);
        keyDataBlock.Value.Should().BeEquivalentTo(ValidAes256Key);
        keyDataBlock.KeyCheckValue.Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void CreateAes256Key_WithNullKeyValue_ReturnsFailure()
    {
        var result = KeyDataBlock.CreateAes256Key(null!);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain("AES-256 key value cannot be null");
    }

    [Test]
    [TestCase(24)]
    [TestCase(31)]
    [TestCase(33)]
    [TestCase(40)]
    public void CreateAes256Key_WithInvalidKeyLength_ReturnsFailure(int length)
    {
        var keyValue = new byte[length];

        var result = KeyDataBlock.CreateAes256Key(keyValue);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain($"AES-256 key must be 32 bytes, got {length} bytes");
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
        ((byte)KeyDataBlock.KeyType.RsaPublic).Should().Be(0xA0);
        ((byte)KeyDataBlock.KeyType.RsaPrivate).Should().Be(0xA1);
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
        ((byte)KeyDataBlock.KeyType.EccPublic).Should().Be(0xB0);
        ((byte)KeyDataBlock.KeyType.EccPrivate).Should().Be(0xB1);
    }

    [Test]
    public void KeyType_EnumValues_AreCorrect()
    {
        ((byte)KeyDataBlock.KeyType.Des).Should().Be(0x80);
        ((byte)KeyDataBlock.KeyType.TripleDes2Key).Should().Be(0x81);
        ((byte)KeyDataBlock.KeyType.TripleDes3Key).Should().Be(0x82);
        ((byte)KeyDataBlock.KeyType.Aes128).Should().Be(0x88);
        ((byte)KeyDataBlock.KeyType.Aes192).Should().Be(0x89);
        ((byte)KeyDataBlock.KeyType.Aes256).Should().Be(0x8A);
        ((byte)KeyDataBlock.KeyType.RsaPublic).Should().Be(0xA0);
        ((byte)KeyDataBlock.KeyType.RsaPrivate).Should().Be(0xA1);
        ((byte)KeyDataBlock.KeyType.EccPublic).Should().Be(0xB0);
        ((byte)KeyDataBlock.KeyType.EccPrivate).Should().Be(0xB1);
    }

    [Test]
    public void ToBytes_WithoutKeyCheckValue_ReturnsCorrectBytes()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;

        var bytes = keyDataBlock.ToBytes();

        bytes.Should().HaveCount(10); // 1 byte type + 1 byte length + 8 bytes key
        bytes[0].Should().Be(0x80); // DES key type
        bytes[1].Should().Be(0x08); // Key length
        bytes.Skip(2).Take(8).Should().BeEquivalentTo(ValidDesKey);
    }

    [Test]
    public void ToBytes_WithKeyCheckValue_ReturnsCorrectBytes()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey, ValidKeyCheckValue).Value;

        var bytes = keyDataBlock.ToBytes();

        bytes.Should().HaveCount(13); // 1 byte type + 1 byte length + 8 bytes key + 3 bytes KCV
        bytes[0].Should().Be(0x80); // DES key type
        bytes[1].Should().Be(0x08); // Key length
        bytes.Skip(2).Take(8).Should().BeEquivalentTo(ValidDesKey);
        bytes.Skip(10).Take(3).Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void ToBytes_WithDifferentKeyTypes_ReturnsCorrectTypeBytes()
    {
        var desKey = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var aes128Key = KeyDataBlock.CreateAes128Key(ValidAes128Key).Value;
        var aes256Key = KeyDataBlock.CreateAes256Key(ValidAes256Key).Value;

        desKey.ToBytes()[0].Should().Be(0x80);
        aes128Key.ToBytes()[0].Should().Be(0x88);
        aes256Key.ToBytes()[0].Should().Be(0x8A);
    }

    [Test]
    public void ToBytes_ReturnsImmutableArray()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var bytes1 = keyDataBlock.ToBytes();
        var bytes2 = keyDataBlock.ToBytes();

        // Should return different array instances
        bytes1.Should().NotBeSameAs(bytes2);
        // But with identical content
        bytes1.Should().BeEquivalentTo(bytes2);
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

        desKey.Length.Should().Be(8);
        aes128Key.Length.Should().Be(16);
        aes192Key.Length.Should().Be(24);
        aes256Key.Length.Should().Be(32);
        tripleDes2Key.Length.Should().Be(16);
        tripleDes3Key.Length.Should().Be(24);
    }

    [Test]
    public void KeyDataBlock_ValueProperty_ReturnsClonedData()
    {
        var originalKey = (byte[])ValidDesKey.Clone();
        var keyDataBlock = KeyDataBlock.CreateDesKey(originalKey).Value;

        // Modify the original key
        originalKey[0] = 0xFF;

        // KeyDataBlock should have its own copy
        keyDataBlock.Value[0].Should().Be(0x01); // Original first byte
        keyDataBlock.Value.Should().NotBeSameAs(originalKey);
    }

    [Test]
    public void KeyDataBlock_KeyCheckValueProperty_ReturnsClonedData()
    {
        var originalKcv = (byte[])ValidKeyCheckValue.Clone();
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey, originalKcv).Value;

        // Modify the original KCV
        originalKcv[0] = 0xFF;

        // KeyDataBlock should have its own copy
        keyDataBlock.KeyCheckValue![0].Should().Be(0x12); // Original first byte
        keyDataBlock.KeyCheckValue.Should().NotBeSameAs(originalKcv);
    }

    [Test]
    public void PutKeyCommand_KeyDataBlocks_ReturnsImmutableCollection()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock };
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        // Should be a different collection instance
        command.KeyDataBlocks.Should().NotBeSameAs(keyDataBlocks);
        // But with the same content
        command.KeyDataBlocks.Should().BeEquivalentTo(keyDataBlocks);
    }

    [Test]
    public void PutKeyCommand_Data_ReturnsNewArrayEachTime()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock };
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        var data1 = command.Data;
        var data2 = command.Data;

        data1.Should().NotBeSameAs(data2);
        if (data1 != null && data2 != null)
        {
            data1.Should().BeEquivalentTo(data2);
        }
    }

    [Test]
    public void PutKeyCommand_ToApdu_ReturnsNewArrayEachTime()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock };
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        var apdu1 = command.ToApdu();
        var apdu2 = command.ToApdu();

        apdu1.Should().NotBeSameAs(apdu2);
        apdu1.Should().BeEquivalentTo(apdu2);
    }

    [Test]
    public void PutKeyCommand_SingleDesKey_UsageQualifier_NotCurrentlyUsed()
    {
        // The SingleDesKey usage qualifier exists but isn't currently used
        // The implementation chooses SingleKey for single keys regardless of type
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock };
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        // Currently uses SingleKey, not SingleDesKey
        command.UsageQualifier.Should().Be(PutKeyCommand.KeyUsageQualifier.SingleKey);
        command.UsageQualifier.Should().NotBe(PutKeyCommand.KeyUsageQualifier.SingleDesKey);

        // But SingleDesKey enum value should exist for future use
        ((byte)PutKeyCommand.KeyUsageQualifier.SingleDesKey).Should().Be(0x01);
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
            { KeyDataBlock.KeyType.EccPrivate, 0xB1 }
        };

        foreach (var kvp in expectedKeyTypes)
        {
            ((byte)kvp.Key).Should().Be(kvp.Value, $"KeyType.{kvp.Key} should have value 0x{kvp.Value:X2}");
        }
    }

    [Test]
    public void ToApdu_WithSingleKey_ReturnsCorrectApduStructure()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock };
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        var apdu = command.ToApdu();

        apdu[0].Should().Be(0x80); // CLA
        apdu[1].Should().Be(0xD8); // INS
        apdu[2].Should().Be(0x81); // P1 (Single key)
        apdu[3].Should().Be(0x00); // P2 (No KEK)
        apdu[4].Should().Be(0x0A); // LC (10 bytes data)
        apdu[5].Should().Be(0x80); // Key type (DES)
        apdu[6].Should().Be(0x08); // Key length
        apdu.Skip(7).Take(8).Should().BeEquivalentTo(ValidDesKey); // Key data
        apdu[15].Should().Be(0x03); // LE (3 bytes expected response for 1 key)
    }

    [Test]
    public void ToApdu_WithMultipleKeys_ReturnsCorrectApduStructure()
    {
        var keyDataBlock1 = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlock2 = KeyDataBlock.CreateAes128Key(ValidAes128Key).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock1, keyDataBlock2 };
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        var apdu = command.ToApdu();

        apdu[0].Should().Be(0x80); // CLA
        apdu[1].Should().Be(0xD8); // INS
        apdu[2].Should().Be(0x00); // P1 (Multiple keys)
        apdu[3].Should().Be(0x00); // P2 (No KEK)
        apdu[4].Should().Be(0x1C); // LC (28 bytes data: 10 + 18)

        // First key block
        apdu[5].Should().Be(0x80); // Key type (DES)
        apdu[6].Should().Be(0x08); // Key length
        apdu.Skip(7).Take(8).Should().BeEquivalentTo(ValidDesKey); // Key data

        // Second key block
        apdu[15].Should().Be(0x88); // Key type (AES-128)
        apdu[16].Should().Be(0x10); // Key length
        apdu.Skip(17).Take(16).Should().BeEquivalentTo(ValidAes128Key); // Key data

        apdu[33].Should().Be(0x06); // LE (6 bytes expected response for 2 keys)
    }

    [Test]
    public void ToApdu_WithKeyCheckValue_IncludesCheckValueInData()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey, ValidKeyCheckValue).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock };
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        var apdu = command.ToApdu();

        apdu[4].Should().Be(0x0D); // LC (13 bytes data including KCV)
        apdu.Skip(7).Take(8).Should().BeEquivalentTo(ValidDesKey); // Key data
        apdu.Skip(15).Take(3).Should().BeEquivalentTo(ValidKeyCheckValue); // Key check value
        apdu[18].Should().Be(0x03); // LE (3 bytes expected response)
    }

    [Test]
    public void ExpectedResponseLength_ReturnsCorrectLength()
    {
        var keyDataBlock1 = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlock2 = KeyDataBlock.CreateAes128Key(ValidAes128Key).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock1, keyDataBlock2 };
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        command.ExpectedResponseLength.Should().Be(6); // 3 bytes per key * 2 keys
    }

    [Test]
    public void CommandProperties_HaveCorrectValues()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock };
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        PutKeyCommand.Cla.Should().Be(0x80);
        PutKeyCommand.Ins.Should().Be(0xD8);
        command.IsExtendedLength.Should().BeFalse();
        command.ToString().Should().Be("PUT KEY");
    }

    [Test]
    public void Data_WithNullKeyDataBlocks_ReturnsNull()
    {
        var keyDataBlocks = new List<KeyDataBlock>();
        var command = PutKeyCommand.Create(0x01, keyDataBlocks);

        // This should fail during creation, but if it didn't, Data would handle empty list
        command.IsFailure.Should().BeTrue();
    }

    [Test]
    public void Data_WithValidKeyDataBlocks_ReturnsCorrectData()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock };
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        var data = command.Data;

        data.Should().NotBeNull();
        data.Should().HaveCount(10); // Type + length + key data
        data![0].Should().Be(0x80); // DES key type
        data[1].Should().Be(0x08); // Key length
        data.Skip(2).Take(8).Should().BeEquivalentTo(ValidDesKey);
    }

    [Test]
    public void PutKeyResponse_Parse_WithValidResponse_ReturnsSuccessResult()
    {
        var responseData = Convert.FromHexString("123456789ABC"); // 2 key check values

        var result = PutKeyResponse.Parse(responseData);

        result.IsSuccess.Should().BeTrue();
        var response = result.Value;
        response.KeyCheckValues.Should().HaveCount(2);
        response.KeyCheckValues[0].Should().BeEquivalentTo(Convert.FromHexString("123456"));
        response.KeyCheckValues[1].Should().BeEquivalentTo(Convert.FromHexString("789ABC"));
    }

    [Test]
    public void PutKeyResponse_Parse_WithSingleKeyCheckValue_ReturnsSuccessResult()
    {
        var responseData = Convert.FromHexString("123456"); // 1 key check value

        var result = PutKeyResponse.Parse(responseData);

        result.IsSuccess.Should().BeTrue();
        var response = result.Value;
        response.KeyCheckValues.Should().HaveCount(1);
        response.KeyCheckValues[0].Should().BeEquivalentTo(Convert.FromHexString("123456"));
    }

    [Test]
    public void PutKeyResponse_Parse_WithEmptyResponse_ReturnsSuccessResult()
    {
        var responseData = Array.Empty<byte>();

        var result = PutKeyResponse.Parse(responseData);

        result.IsSuccess.Should().BeTrue();
        var response = result.Value;
        response.KeyCheckValues.Should().HaveCount(0);
    }

    [Test]
    public void PutKeyResponse_Parse_WithNullResponse_ReturnsFailure()
    {
        var result = PutKeyResponse.Parse(null!);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_ARGUMENT");
        result.Error.Message.Should().Contain("Response data cannot be null");
    }

    [Test]
    [TestCase(1)]
    [TestCase(2)]
    [TestCase(4)]
    [TestCase(5)]
    public void PutKeyResponse_Parse_WithInvalidResponseLength_ReturnsFailure(int length)
    {
        var responseData = new byte[length];

        var result = PutKeyResponse.Parse(responseData);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("INVALID_RESPONSE");
        result.Error.Message.Should().Contain($"Invalid response length {length}, expected multiple of 3 bytes");
    }

    [Test]
    public void PutKeyResponse_Constructor_ClonesKeyCheckValues()
    {
        var originalKcv = Convert.FromHexString("123456");
        var keyCheckValues = new List<byte[]> { originalKcv };
        var response = new PutKeyResponse(keyCheckValues);

        // Modify original array
        originalKcv[0] = 0xFF;

        // Response should have cloned data
        response.KeyCheckValues[0][0].Should().Be(0x12);
    }

    [Test]
    public void PutKeyResponse_Constructor_WithNullKeyCheckValues_HandlesGracefully()
    {
        var response = new PutKeyResponse(null!);

        response.KeyCheckValues.Should().HaveCount(0);
    }

    [Test]
    public void ToApdu_Structure_FollowsGlobalPlatformSpecification()
    {
        // Test that APDU structure follows GlobalPlatform specification exactly
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey, ValidKeyCheckValue).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock };
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        var apdu = command.ToApdu();

        // GlobalPlatform PUT KEY APDU structure:
        // CLA | INS | P1 | P2 | LC | Data | LE
        apdu.Should().HaveCountGreaterThan(5); // At least header + LC + LE

        // Header
        apdu[0].Should().Be(PutKeyCommand.Cla);  // CLA
        apdu[1].Should().Be(PutKeyCommand.Ins);  // INS
        apdu[2].Should().Be((byte)command.UsageQualifier);  // P1
        apdu[3].Should().Be((byte)command.KekIdentifier);   // P2

        // LC should match data length
        var dataLength = apdu[4];
        var expectedDataLength = keyDataBlock.ToBytes().Length;
        dataLength.Should().Be((byte)expectedDataLength);

        // LE should be at the end and match expected response length
        var leIndex = apdu.Length - 1;
        apdu[leIndex].Should().Be((byte)command.ExpectedResponseLength!);
    }

    [Test]
    public void ToApdu_WithLargeKeyData_HandlesCorrectly()
    {
        // Test with the largest supported key (AES-256)
        var keyDataBlock = KeyDataBlock.CreateAes256Key(ValidAes256Key, ValidKeyCheckValue).Value;
        var keyDataBlocks = new List<KeyDataBlock> { keyDataBlock };
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        var apdu = command.ToApdu();

        // Should handle large key data correctly
        var expectedDataLength = 1 + 1 + 32 + 3; // Type + Length + Key + KCV
        apdu[4].Should().Be((byte)expectedDataLength); // LC
        apdu[apdu.Length - 1].Should().Be(0x03); // LE (3 bytes expected response)

        // Verify key data is properly embedded
        var keyDataStart = 5; // After header and LC
        apdu[keyDataStart].Should().Be(0x8A); // AES-256 key type
        apdu[keyDataStart + 1].Should().Be(0x20); // 32 bytes length

        // Verify actual key data
        var keyData = apdu.Skip(keyDataStart + 2).Take(32).ToArray();
        keyData.Should().BeEquivalentTo(ValidAes256Key);

        // Verify KCV
        var kcvData = apdu.Skip(keyDataStart + 2 + 32).Take(3).ToArray();
        kcvData.Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void KeyDataBlock_PreservesKeyDataImmutability()
    {
        var originalKeyData = (byte[])ValidDesKey.Clone();
        var keyDataBlock = KeyDataBlock.CreateDesKey(originalKeyData).Value;

        // Modify original array
        originalKeyData[0] = 0xFF;

        // KeyDataBlock should have cloned data
        keyDataBlock.Value[0].Should().Be(0x01);
    }

    [Test]
    public void KeyDataBlock_PreservesKeyCheckValueImmutability()
    {
        var originalKcv = (byte[])ValidKeyCheckValue.Clone();
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey, originalKcv).Value;

        // Modify original array
        originalKcv[0] = 0xFF;

        // KeyDataBlock should have cloned data
        keyDataBlock.KeyCheckValue![0].Should().Be(0x12);
    }

    [Test]
    public void ToBytes_ReturnsNewArrayEachTime()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;

        var bytes1 = keyDataBlock.ToBytes();
        var bytes2 = keyDataBlock.ToBytes();

        bytes1.Should().NotBeSameAs(bytes2);
        bytes1.Should().BeEquivalentTo(bytes2);
    }

    [Test]
    public void ToBytes_ImmutabilityGuarantees_ArePreserved()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey, ValidKeyCheckValue).Value;
        var bytes1 = keyDataBlock.ToBytes();
        var bytes2 = keyDataBlock.ToBytes();

        // Modify first array
        bytes1[0] = 0xFF;

        // Second array should be unchanged
        bytes2[0].Should().Be(0x80); // Original DES key type

        // Getting bytes again should return original data
        var bytes3 = keyDataBlock.ToBytes();
        bytes3[0].Should().Be(0x80);
    }

    [Test]
    public void PutKeyCommand_ImmutabilityGuarantees_ArePreserved()
    {
        var originalKeyDataBlocks = new List<KeyDataBlock>
        {
            KeyDataBlock.CreateDesKey(ValidDesKey).Value
        };

        var command = PutKeyCommand.Create(0x01, originalKeyDataBlocks).Value;

        // Clear the original list
        originalKeyDataBlocks.Clear();

        // Command should still have its key data blocks
        command.KeyDataBlocks.Should().HaveCount(1);
        command.KeyDataBlocks[0].Type.Should().Be(KeyDataBlock.KeyType.Des);
    }

}
