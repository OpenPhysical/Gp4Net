using System;
using System.Collections.Generic;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Extensions;
using Gp4Net.Services.GlobalPlatform;
using Gp4Net.Transport;
using NUnit.Framework;
using static Gp4Net.Cryptography.CryptoService;

namespace Gp4Net.Tests.Domain.Commands;

/// <summary>
/// Unit tests for the PutKeyCommand domain model.
/// Tests pure functions without any I/O or mocking.
/// </summary>
[TestFixture]
[Category("Unit")]
public class PutKeyCommandTests
{
    [TestCase(0x01, 0x01, 0x02)]
    [TestCase(0x7F, 0x7F, 0x01)]
    [TestCase(0xFF, 0x00, 0x01)]
    public void DefaultVersions_Should_Advance_And_Handle_Factory_Keys(
        byte active,
        byte replaced,
        byte next
    )
    {
        // GP Card Spec 2.3.1, 11.8.2.1/11.8.2.3: P1=00 adds keys;
        // a new Key Version Number is encoded from 01 through 7F.
        var result = KeyChange.GetDefaultVersions(active);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.ReplacedVersion.Should().Be(replaced);
        _ = result.Value.NewVersion.Should().Be(next);
    }

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
        _ = command.KekIdentifier.Should().Be(PutKeyCommand.KeyEncryptionKeyIdentifier.CurrentKek);
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
        _ = command.KekIdentifier.Should().Be(PutKeyCommand.KeyEncryptionKeyIdentifier.CurrentKek);
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
        _ = command.P1.Should().Be(0x00);
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
    public void P2_DefaultsToFirstKeyIdentifier()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        _ = command.KekIdentifier.Should().Be(PutKeyCommand.KeyEncryptionKeyIdentifier.CurrentKek);
        _ = command.P2.Should().Be(0x01);
    }

    [Test]
    public void P2_UsesMultipleKeyFlagAndEncKeyIdentifier_ForKeysetReplacement()
    {
        // GP Card Spec 2.3.1, 11.8.2.2, Table 11-66: b8 marks multiple keys
        // and b7-b1 identify the first key, ENC key ID 01 gives P2=81.
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock, keyDataBlock, keyDataBlock];
        var command = PutKeyCommand.CreateReplacement(0x00, 0x01, 0x01, keyDataBlocks).Value;

        _ = command.P1.Should().Be(0x00);
        _ = command.P2.Should().Be(0x81);
    }

    [Test]
    public void Scp03KeyComponents_Should_Use_Table_11_70_ExplicitLengthFormat()
    {
        // GP Card Spec 2.3.1, 11.8.2.3.2, Table 11-70 permits a clear-key
        // length prefix before the encrypted key component.
        // SCP03 1.1.2, 6.2.8 requires static Key-DEK, AES-CBC, and a zero ICV.
        var sessionKeys = SessionKeys
            .Create(new byte[16], new byte[16], new byte[16], new byte[16])
            .Value;
        var channel = SecureChannelState
            .Create(sessionKeys, SecurityLevel.CMac, ScpVersion.Scp03, new byte[16], 0x70)
            .Value;
        var keyset = Scp03KeySet.Create(ValidAes128Key, ValidAes128Key, ValidAes128Key, 0x01).Value;

        var command = KeyChange.CreateCommand(keyset, channel, 0x00).Value;

        _ = command.P2.Should().Be(0x81);
        _ = command.Data[0].Should().Be(0x01);
        _ = command.Data[1].Should().Be(0x88);
        _ = command.Data[2].Should().Be(0x11);
        _ = command.Data[3].Should().Be(0x10);
        _ = command.Data.Should().HaveCount(70);
        _ = command.ToApdu().BinaryCommand.Should().HaveCount(5 + command.Data.Length);
    }

    [Test]
    public void Scp03Mac_Should_Preserve_PutKey_As_Case3Apdu()
    {
        // SCP03 1.1.2, 6.2.4 appends C-MAC to command data without adding Le.
        var block = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var command = PutKeyCommand.Create(0x01, [block]).Value.ToApdu();

        var secured = command.WithMac(Enumerable.Repeat((byte)0xA5, 8).ToArray()).Value;

        _ = secured.BinaryCommand.Should().HaveCount(command.BinaryCommand.Length + 8);
        _ = secured.BinaryCommand[^1].Should().Be(0xA5);
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
        _ = keyDataBlock.KeyCheckValue.HasValue.Should().BeFalse();
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
        _ = keyDataBlock
            .KeyCheckValue.GetValueOrDefault(Array.Empty<byte>())
            .Should()
            .BeEquivalentTo(ValidKeyCheckValue);
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
            .Contain($"Key check value must be 3 bytes for DES, got {length} bytes");
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
        _ = keyDataBlock.KeyCheckValue.HasValue.Should().BeFalse();
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
        _ = keyDataBlock
            .KeyCheckValue.GetValueOrDefault(Array.Empty<byte>())
            .Should()
            .BeEquivalentTo(ValidKeyCheckValue);
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
        _ = keyDataBlock.KeyCheckValue.HasValue.Should().BeFalse();
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
        _ = keyDataBlock
            .KeyCheckValue.GetValueOrDefault(Array.Empty<byte>())
            .Should()
            .BeEquivalentTo(ValidKeyCheckValue);
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
        _ = keyDataBlock.KeyCheckValue.HasValue.Should().BeFalse();
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
        _ = keyDataBlock
            .KeyCheckValue.GetValueOrDefault(Array.Empty<byte>())
            .Should()
            .BeEquivalentTo(ValidKeyCheckValue);
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
        _ = keyDataBlock.KeyCheckValue.HasValue.Should().BeFalse();
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
        _ = keyDataBlock
            .KeyCheckValue.GetValueOrDefault(Array.Empty<byte>())
            .Should()
            .BeEquivalentTo(ValidKeyCheckValue);
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
        _ = keyDataBlock.KeyCheckValue.HasValue.Should().BeFalse();
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
        _ = keyDataBlock
            .KeyCheckValue.GetValueOrDefault(Array.Empty<byte>())
            .Should()
            .BeEquivalentTo(ValidKeyCheckValue);
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
        // GP Card Specification v2.3.1, Table 11-16: all DES key lengths use type 80.
        _ = ((byte)KeyDataBlock.KeyType.Des).Should().Be(0x80);
        _ = ((byte)KeyDataBlock.KeyType.TripleDes2Key).Should().Be(0x80);
        _ = ((byte)KeyDataBlock.KeyType.TripleDes3Key).Should().Be(0x80);
        _ = ((byte)KeyDataBlock.KeyType.Aes128).Should().Be(0x88);
        _ = ((byte)KeyDataBlock.KeyType.Aes192).Should().Be(0x88);
        _ = ((byte)KeyDataBlock.KeyType.Aes256).Should().Be(0x88);
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

        _ = bytes.Should().HaveCount(11); // type + length + key + zero KCV length
        _ = bytes[0].Should().Be(0x80); // DES key type
        _ = bytes[1].Should().Be(0x08); // Key length
        _ = bytes.Skip(2).Take(8).Should().BeEquivalentTo(ValidDesKey);
    }

    [Test]
    public void ToBytes_WithKeyCheckValue_ReturnsCorrectBytes()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey, ValidKeyCheckValue).Value;

        byte[]? bytes = keyDataBlock.ToBytes();

        _ = bytes.Should().HaveCount(14); // type + length + key + KCV length + KCV
        _ = bytes[0].Should().Be(0x80); // DES key type
        _ = bytes[1].Should().Be(0x08); // Key length
        _ = bytes.Skip(2).Take(8).Should().BeEquivalentTo(ValidDesKey);
        _ = bytes[10].Should().Be(3);
        _ = bytes.Skip(11).Take(3).Should().BeEquivalentTo(ValidKeyCheckValue);
    }

    [Test]
    public void ToBytes_WithDifferentKeyTypes_ReturnsCorrectTypeBytes()
    {
        // GP Card Specification v2.3.1, Table 11-16.
        var desKey = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var tripleDes2Key = KeyDataBlock.CreateTripleDes2Key(ValidTripleDes2Key).Value;
        var tripleDes3Key = KeyDataBlock.CreateTripleDes3Key(ValidTripleDes3Key).Value;
        var aes128Key = KeyDataBlock.CreateAes128Key(ValidAes128Key).Value;
        var aes256Key = KeyDataBlock.CreateAes256Key(ValidAes256Key).Value;

        _ = desKey.ToBytes()[0].Should().Be(0x80);
        _ = tripleDes2Key.ToBytes()[0].Should().Be(0x80);
        _ = tripleDes3Key.ToBytes()[0].Should().Be(0x80);
        _ = aes128Key.ToBytes()[0].Should().Be(0x88);
        _ = aes256Key.ToBytes()[0].Should().Be(0x88);
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
        _ = keyDataBlock.KeyCheckValue.GetValueOrDefault(Array.Empty<byte>())[0].Should().Be(0x12); // Original first byte
        _ = keyDataBlock
            .KeyCheckValue.GetValueOrDefault(Array.Empty<byte>())
            .Should()
            .NotBeSameAs(originalKcv);
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

        _ = command.UsageQualifier.Should().Be(PutKeyCommand.KeyUsageQualifier.SingleKey);
        _ = command.UsageQualifier.Should().NotBe(PutKeyCommand.KeyUsageQualifier.SingleDesKey);

        _ = ((byte)PutKeyCommand.KeyUsageQualifier.SingleDesKey).Should().Be(0x01);
    }

    [Test]
    public void KeyDataBlock_ValidateAllKeyTypesHaveCorrectEnumValues()
    {
        // GP Card Specification v2.3.1, Table 11-16.
        (KeyDataBlock.KeyType Type, byte Value)[] expectedKeyTypes =
        {
            (KeyDataBlock.KeyType.Des, 0x80),
            (KeyDataBlock.KeyType.TripleDes2Key, 0x80),
            (KeyDataBlock.KeyType.TripleDes3Key, 0x80),
            (KeyDataBlock.KeyType.Aes128, 0x88),
            (KeyDataBlock.KeyType.Aes192, 0x88),
            (KeyDataBlock.KeyType.Aes256, 0x88),
            (KeyDataBlock.KeyType.RsaPublic, 0xA0),
            (KeyDataBlock.KeyType.RsaPrivate, 0xA1),
            (KeyDataBlock.KeyType.EccPublic, 0xB0),
            (KeyDataBlock.KeyType.EccPrivate, 0xB1),
        };

        foreach (var kvp in expectedKeyTypes)
        {
            _ = ((byte)kvp.Type)
                .Should()
                .Be(kvp.Value, $"KeyType.{kvp.Type} should have value 0x{kvp.Value:X2}");
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
        _ = apdu[2].Should().Be(0x00); // P1 (add new version)
        _ = apdu[3].Should().Be(0x01); // P2 (single key, identifier 1)
        _ = apdu[4].Should().Be(0x0C);
        _ = apdu[5].Should().Be(0x01); // New key version
        _ = apdu[6].Should().Be(0x80);
        _ = apdu[7].Should().Be(0x08);
        _ = apdu.Skip(8).Take(8).Should().BeEquivalentTo(ValidDesKey);
        _ = apdu[^1].Should().Be(0x00);
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
        _ = apdu[3].Should().Be(0x81); // Multiple keys from identifier 1
        _ = apdu[4].Should().Be(0x1F);

        // First key block
        _ = apdu[5].Should().Be(0x01);
        _ = apdu[6].Should().Be(0x80);
        _ = apdu[7].Should().Be(0x08);
        _ = apdu.Skip(8).Take(8).Should().BeEquivalentTo(ValidDesKey);

        // Second key block
        _ = apdu[17].Should().Be(0x88);
        _ = apdu[18].Should().Be(0x10);
        _ = apdu.Skip(19).Take(16).Should().BeEquivalentTo(ValidAes128Key);

        _ = apdu[^1].Should().Be(0x00);
    }

    [Test]
    public void ToApdu_WithKeyCheckValue_IncludesCheckValueInData()
    {
        var keyDataBlock = KeyDataBlock.CreateDesKey(ValidDesKey, ValidKeyCheckValue).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        byte[]? apdu = command.ToApdu().ToApdu().Value;

        _ = apdu[4].Should().Be(0x0F);
        _ = apdu.Skip(8).Take(8).Should().BeEquivalentTo(ValidDesKey);
        _ = apdu[16].Should().Be(0x03);
        _ = apdu.Skip(17).Take(3).Should().BeEquivalentTo(ValidKeyCheckValue);
        _ = apdu[^1].Should().Be(0x56);
    }

    [Test]
    public void ExpectedResponseLength_ReturnsCorrectLength()
    {
        var keyDataBlock1 = KeyDataBlock.CreateDesKey(ValidDesKey).Value;
        var keyDataBlock2 = KeyDataBlock.CreateAes128Key(ValidAes128Key).Value;
        List<KeyDataBlock> keyDataBlocks = [keyDataBlock1, keyDataBlock2];
        var command = PutKeyCommand.Create(0x01, keyDataBlocks).Value;

        _ = command.ExpectedResponseLength.Should().Be(7); // key version plus two 3-byte KCVs
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
        _ = data.Should().HaveCount(12);
        _ = data![0].Should().Be(0x01);
        _ = data[1].Should().Be(0x80);
        _ = data[2].Should().Be(0x08);
        _ = data.Skip(3).Take(8).Should().BeEquivalentTo(ValidDesKey);
    }

    [Test]
    public void PutKeyResponse_Parse_WithValidResponse_ReturnsSuccessResult()
    {
        byte[] responseData = Convert.FromHexString("01123456789ABC");

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
        byte[] responseData = Convert.FromHexString("01123456");

        Result<PutKeyResponse, SmartCardError> result = PutKeyResponse.Parse(responseData);

        _ = result.IsSuccess.Should().BeTrue();
        var response = result.Value;
        _ = response.KeyCheckValues.Should().HaveCount(1);
        _ = response.KeyCheckValues[0].Should().BeEquivalentTo(Convert.FromHexString("123456"));
    }

    [Test]
    public void PutKeyResponse_Parse_WithEmptyResponse_ReturnsFailure()
    {
        byte[] responseData = [];

        Result<PutKeyResponse, SmartCardError> result = PutKeyResponse.Parse(responseData);

        _ = result.IsFailure.Should().BeTrue();
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
    [TestCase(2)]
    [TestCase(5)]
    public void PutKeyResponse_Parse_WithInvalidResponseLength_ReturnsFailure(int length)
    {
        byte[] responseData = new byte[length];

        Result<PutKeyResponse, SmartCardError> result = PutKeyResponse.Parse(responseData);

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
        _ = result.Error.Message.Should().Contain($"Invalid response length {length}");
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
        _ = apdu[2].Should().Be(command.ReplacedKeyVersion);
        _ = apdu[3].Should().Be(command.P2);

        // LC should match data length
        byte dataLength = apdu[4];
        int expectedDataLength = 1 + keyDataBlock.ToBytes().Length;
        _ = dataLength.Should().Be((byte)expectedDataLength);

        // GP Card Spec 2.3.1, Table 11-64: PUT KEY uses Le=00.
        _ = apdu.Should().HaveCount(5 + expectedDataLength);
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
        int expectedDataLength = 1 + 1 + 1 + 32 + 1 + 3;
        _ = apdu[4].Should().Be((byte)expectedDataLength); // LC
        _ = apdu[^1].Should().Be(0x56);

        // Verify key data is properly embedded
        int keyDataStart = 6; // After header, LC, and new key version
        _ = apdu[keyDataStart].Should().Be(0x88);
        _ = apdu[keyDataStart + 1].Should().Be(0x20); // 32 bytes length

        // Verify actual key data
        byte[] keyData = [.. apdu.Skip(keyDataStart + 2).Take(32)];
        _ = keyData.Should().BeEquivalentTo(ValidAes256Key);

        // Verify KCV
        byte[] kcvData = [.. apdu.Skip(keyDataStart + 2 + 32 + 1).Take(3)];
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
        _ = keyDataBlock.KeyCheckValue.GetValueOrDefault(Array.Empty<byte>())[0].Should().Be(0x12);
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
