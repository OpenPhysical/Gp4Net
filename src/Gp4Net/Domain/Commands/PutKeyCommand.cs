using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;
using JetBrains.Annotations;
using WSCT.ISO7816;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents the PUT KEY command for key establishment and replacement.
/// </summary>
[PublicAPI]
public class PutKeyCommand : IApduCommand
{
    /// <summary>
    /// Key usage qualifier values.
    /// </summary>
    public enum KeyUsageQualifier : byte
    {
        /// <summary>
        /// Multiple keys.
        /// </summary>
        MultipleKeys = 0x00,

        /// <summary>
        /// Single DES key.
        /// </summary>
        SingleDesKey = 0x01,

        /// <summary>
        /// Single key (AES or RSA).
        /// </summary>
        SingleKey = 0x81,
    }

    /// <summary>
    /// Key encryption key identifier values.
    /// </summary>
    public enum KeyEncryptionKeyIdentifier : byte
    {
        /// <summary>
        /// No key encryption key (plain text).
        /// </summary>
        None = 0x00,

        /// <summary>
        /// Key encrypted with KEK having key version number 1.
        /// </summary>
        KekVersion1 = 0x01,

        /// <summary>
        /// Key encrypted with KEK having key version number 2.
        /// </summary>
        KekVersion2 = 0x02,

        /// <summary>
        /// Key encrypted with current KEK.
        /// </summary>
        CurrentKek = 0xFF,
    }

    /// <summary>
    /// Gets the key usage qualifier.
    /// </summary>
    public KeyUsageQualifier UsageQualifier { get; }

    /// <summary>
    /// Gets the key encryption key identifier.
    /// </summary>
    public KeyEncryptionKeyIdentifier KekIdentifier { get; }

    /// <summary>
    /// Gets the list of key data blocks.
    /// </summary>
    public IReadOnlyList<KeyDataBlock> KeyDataBlocks { get; }

    public byte ReplacedKeyVersion { get; }

    public byte NewKeyVersion { get; }

    public byte FirstKeyIdentifier { get; }

    /// <summary>
    /// Converts this command to a CommandAPDU.
    /// </summary>
    /// <returns>A result containing the CommandAPDU or an error.</returns>
    public Result<CommandAPDU, SmartCardError> ToCommandApdu()
    {
        // GP Card Spec 2.3.1, 11.8.2.1 and 11.8.2.2, Tables 11-65/66:
        // P1 names the existing KVN; P2 is the first key ID with b8 set for multiple keys.
        var data = Data;

        return Result.Success<CommandAPDU, SmartCardError>(
            new CommandAPDU(
                GlobalPlatform.Cla.GP_STANDARD,
                GlobalPlatform.Ins.PUT_KEY,
                ReplacedKeyVersion,
                (byte)(FirstKeyIdentifier | (KeyDataBlocks.Count > 1 ? 0x80 : 0x00)),
                (uint)data.Length,
                data
            )
        );
    }

    /// <summary>
    /// Gets the parameter 1 byte.
    /// </summary>
    public byte P1
    {
        get { return ReplacedKeyVersion; }
    }

    /// <summary>
    /// Gets the parameter 2 byte.
    /// </summary>
    public byte P2
    {
        get { return (byte)(FirstKeyIdentifier | (KeyDataBlocks.Count > 1 ? 0x80 : 0x00)); }
    }

    /// <summary>
    /// Gets the command data.
    /// </summary>
    public byte[] Data
    {
        get
        {
            // GP Card Spec 2.3.1, 11.8.2.3, Table 11-67: new KVN precedes the
            // sequential key data fields identified by P2, P2+1, and P2+2.
            List<byte> data = [NewKeyVersion];
            foreach (var block in KeyDataBlocks)
            {
                data.AddRange(block.ToBytes());
            }
            return data.Count > 0 ? [.. data] : [];
        }
    }

    /// <summary>
    /// Gets the expected response length (key check values, typically 3 bytes per key).
    /// </summary>
    public Maybe<int> ExpectedResponseLength
    {
        get { return Maybe<int>.From(1 + KeyDataBlocks.Count * 3); }
    }

    /// <summary>
    /// Gets whether this command uses extended length.
    /// </summary>
    public bool IsExtendedLength
    {
        get { return false; }
    }

    /// <summary>
    /// Initializes a new instance of the PutKeyCommand class.
    /// </summary>
    /// <param name="replacedKeyVersion">Existing key version, or zero when adding.</param>
    /// <param name="newKeyVersion">Version assigned to the supplied keys.</param>
    /// <param name="firstKeyIdentifier">Identifier of the first supplied key.</param>
    /// <param name="usageQualifier">The key usage qualifier.</param>
    /// <param name="kekIdentifier">The key encryption key identifier.</param>
    /// <param name="keyDataBlocks">The key data blocks.</param>
    private PutKeyCommand(
        byte replacedKeyVersion,
        byte newKeyVersion,
        byte firstKeyIdentifier,
        KeyUsageQualifier usageQualifier,
        KeyEncryptionKeyIdentifier kekIdentifier,
        IList<KeyDataBlock> keyDataBlocks
    )
    {
        ReplacedKeyVersion = replacedKeyVersion;
        NewKeyVersion = newKeyVersion;
        FirstKeyIdentifier = firstKeyIdentifier;
        UsageQualifier = usageQualifier;
        KekIdentifier = kekIdentifier;
        KeyDataBlocks = new List<KeyDataBlock>(keyDataBlocks);
    }

    /// <summary>
    /// Creates a new PUT KEY command with the specified parameters.
    /// </summary>
    /// <param name="keyVersion">The key version number.</param>
    /// <param name="keyDataBlocks">The key data blocks.</param>
    /// <param name="firstKeyIdentifier">Identifier of the first supplied key.</param>
    /// <returns>A Result containing the PutKeyCommand or an error.</returns>
    public static Result<PutKeyCommand, SmartCardError> Create(
        byte keyVersion,
        IList<KeyDataBlock> keyDataBlocks,
        byte firstKeyIdentifier
    )
    {
        if (keyDataBlocks == null)
        {
            return SmartCardError.InvalidArgument("Key data blocks cannot be null.");
        }

        if (keyDataBlocks.Count == 0)
        {
            return SmartCardError.InvalidArgument("At least one key data block is required.");
        }

        // Determine usage qualifier based on number of keys
        var usageQualifier =
            keyDataBlocks.Count == 1 ? KeyUsageQualifier.SingleKey : KeyUsageQualifier.MultipleKeys;

        return CreateReplacement(0x00, keyVersion, firstKeyIdentifier, keyDataBlocks);
    }

    public static Result<PutKeyCommand, SmartCardError> CreateReplacement(
        byte replacedKeyVersion,
        byte newKeyVersion,
        byte firstKeyIdentifier,
        IList<KeyDataBlock> keyDataBlocks
    )
    {
        if (newKeyVersion is 0x00 or > 0x7F)
            return SmartCardError.InvalidArgument("New key version must be between 01 and 7F.");
        if (replacedKeyVersion > 0x7F)
            return SmartCardError.InvalidArgument(
                "Replaced key version must be between 00 and 7F."
            );
        if (firstKeyIdentifier > 0x7F)
            return SmartCardError.InvalidArgument(
                "First key identifier must be between 00 and 7F."
            );
        if (keyDataBlocks is not { Count: > 0 })
            return SmartCardError.InvalidArgument("At least one key data block is required.");

        var usageQualifier =
            keyDataBlocks.Count == 1 ? KeyUsageQualifier.SingleKey : KeyUsageQualifier.MultipleKeys;
        return new PutKeyCommand(
            replacedKeyVersion,
            newKeyVersion,
            firstKeyIdentifier,
            usageQualifier,
            KeyEncryptionKeyIdentifier.CurrentKek,
            keyDataBlocks
        );
    }

    /// <summary>
    /// Returns a string representation of this command.
    /// </summary>
    /// <returns>The command name.</returns>
    public override string ToString()
    {
        return "PUT KEY";
    }

    /// <inheritdoc />
    public CommandAPDU ToApdu()
    {
        return ToCommandApdu()
            .Match(
                onSuccess: apdu => apdu,
                onFailure: _ => new CommandAPDU(
                    GlobalPlatform.Cla.GP_STANDARD,
                    GlobalPlatform.Ins.PUT_KEY,
                    0x00,
                    0x00
                )
            );
    }

    /// <inheritdoc />
    public byte[] ToBytes()
    {
        return ToCommandApdu()
            .Match(
                onSuccess: cmd => cmd.ToBytes(),
                onFailure: _ =>
                    new CommandAPDU(
                        GlobalPlatform.Cla.GP_STANDARD,
                        GlobalPlatform.Ins.PUT_KEY,
                        0x00,
                        0x00
                    ).ToBytes()
            );
    }

    /// <inheritdoc />
    public byte Cla => GlobalPlatform.Cla.GP_STANDARD;

    /// <inheritdoc />
    public byte Ins => GlobalPlatform.Ins.PUT_KEY;
}

/// <summary>
/// Represents a key data block in a PUT KEY command.
/// </summary>
[PublicAPI]
public class KeyDataBlock
{
    /// <summary>
    /// Key type values.
    /// </summary>
    public enum KeyType : byte
    {
        /// <summary>
        /// DES key (single length).
        /// </summary>
        Des = 0x80,

        /// <summary>
        /// DES key with two key components.
        /// </summary>
        TripleDes2Key = 0x80,

        /// <summary>
        /// DES key with three key components.
        /// </summary>
        TripleDes3Key = 0x80,

        /// <summary>
        /// AES key (128 bits).
        /// </summary>
        Aes128 = 0x88,

        /// <summary>
        /// AES key (192 bits).
        /// </summary>
        Aes192 = 0x88,

        /// <summary>
        /// AES key (256 bits).
        /// </summary>
        Aes256 = 0x88,

        /// <summary>
        /// RSA public key.
        /// </summary>
        RsaPublic = 0xA0,

        /// <summary>
        /// RSA private key.
        /// </summary>
        RsaPrivate = 0xA1,

        /// <summary>
        /// ECC public key.
        /// </summary>
        EccPublic = 0xB0,

        /// <summary>
        /// ECC private key.
        /// </summary>
        EccPrivate = 0xB1,
    }

    /// <summary>
    /// Gets the key type.
    /// </summary>
    public KeyType Type { get; }

    /// <summary>
    /// Gets the key length.
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the key value.
    /// </summary>
    public byte[] Value { get; }

    /// <summary>
    /// Gets the key check value (optional).
    /// </summary>
    public Maybe<byte[]> KeyCheckValue { get; }

    /// <summary>
    /// Initializes a new instance of the KeyDataBlock class.
    /// </summary>
    /// <param name="type">The key type.</param>
    /// <param name="value">The key value.</param>
    /// <param name="keyCheckValue">The key check value (optional, 3 bytes).</param>
    private KeyDataBlock(KeyType type, byte[] value, Maybe<byte[]> keyCheckValue = default)
    {
        ArgumentNullException.ThrowIfNull(value);
        Type = type;
        Length = value.Length;
        Value = (byte[])value.Clone();
        KeyCheckValue = keyCheckValue.Map(kcv => (byte[])kcv.Clone());
    }

    /// <summary>
    /// Converts this key data block to bytes.
    /// </summary>
    /// <returns>The byte representation.</returns>
    public byte[] ToBytes()
    {
        List<byte> result = [(byte)Type];
        result.AddRange(GlobalPlatformLengthEncoding.EncodeBerLength(Length));

        result.AddRange(Value);

        result.Add((byte)KeyCheckValue.Match(kcv => kcv.Length, () => 0));
        KeyCheckValue.Execute(result.AddRange);

        return [.. result];
    }

    private static Result<KeyDataBlock, SmartCardError> CreateKeyBlock(
        KeyType keyType,
        string keyName,
        byte[]? keyValue,
        int expectedLength,
        Maybe<byte[]> keyCheckValue = default
    )
    {
        return ValidateKeyValue(keyValue, expectedLength, keyName)
            .Bind(validKey =>
                ValidateKeyCheckValue(keyCheckValue, keyName)
                    .Bind(validCheck =>
                        Result.Success<KeyDataBlock, SmartCardError>(
                            new KeyDataBlock(keyType, validKey, validCheck)
                        )
                    )
            );
    }

    public static Result<KeyDataBlock, SmartCardError> CreatePrepared(
        KeyType keyType,
        byte[] componentBlock,
        byte[] keyCheckValue
    )
    {
        return Maybe<byte[]>
            .From(componentBlock)
            .ToResult(SmartCardError.InvalidArgument("Key component block cannot be null."))
            .Bind(block =>
                block.Length is > 0 and <= 0xFFFF
                    ? ValidateKeyCheckValue(Maybe<byte[]>.From(keyCheckValue), keyType.ToString())
                        .Bind(kcv =>
                            Result.Success<KeyDataBlock, SmartCardError>(
                                new KeyDataBlock(keyType, block, kcv)
                            )
                        )
                    : Result.Failure<KeyDataBlock, SmartCardError>(
                        SmartCardError.InvalidArgument(
                            "Key component block must contain 1 to 65535 bytes."
                        )
                    )
            );
    }

    private static Result<byte[], SmartCardError> ValidateKeyValue(
        byte[]? keyValue,
        int expectedLength,
        string keyName
    )
    {
        return Maybe<byte[]>
            .From(keyValue)
            .ToResult(SmartCardError.InvalidArgument($"{keyName} key value cannot be null."))
            .Bind(value =>
                value.Length == expectedLength
                    ? Result.Success<byte[], SmartCardError>((byte[])value.Clone())
                    : Result.Failure<byte[], SmartCardError>(
                        SmartCardError.InvalidArgument(
                            $"{keyName} key must be {expectedLength} bytes, got {value.Length} bytes."
                        )
                    )
            );
    }

    private static Result<Maybe<byte[]>, SmartCardError> ValidateKeyCheckValue(
        Maybe<byte[]> keyCheckValue,
        string keyName
    )
    {
        return keyCheckValue.Match(
            value =>
                value.Length == 3
                    ? Result.Success<Maybe<byte[]>, SmartCardError>(
                        Maybe<byte[]>.From((byte[])value.Clone())
                    )
                    : Result.Failure<Maybe<byte[]>, SmartCardError>(
                        SmartCardError.InvalidArgument(
                            $"Key check value must be 3 bytes for {keyName}, got {value.Length} bytes."
                        )
                    ),
            () => Result.Success<Maybe<byte[]>, SmartCardError>(Maybe<byte[]>.None)
        );
    }

    /// <summary>
    /// Creates a key data block for a DES key.
    /// </summary>
    /// <param name="keyValue">The 8-byte DES key value.</param>
    /// <param name="keyCheckValue">The 3-byte key check value (optional).</param>
    /// <returns>A Result containing the KeyDataBlock for DES or an error.</returns>
    public static Result<KeyDataBlock, SmartCardError> CreateDesKey(
        byte[]? keyValue,
        byte[]? keyCheckValue = null
    )
    {
        return CreateKeyBlock(
            KeyType.Des,
            "DES",
            keyValue,
            expectedLength: 8,
            keyCheckValue: Maybe<byte[]>.From(keyCheckValue)
        );
    }

    /// <summary>
    /// Creates a key data block for a 3DES key (double length).
    /// </summary>
    /// <param name="keyValue">The 16-byte 3DES key value.</param>
    /// <param name="keyCheckValue">The 3-byte key check value (optional).</param>
    /// <returns>A Result containing the KeyDataBlock for 3DES (double length) or an error.</returns>
    public static Result<KeyDataBlock, SmartCardError> CreateTripleDes2Key(
        byte[]? keyValue,
        byte[]? keyCheckValue = null
    )
    {
        return CreateKeyBlock(
            KeyType.TripleDes2Key,
            "3DES double-length",
            keyValue,
            expectedLength: 16,
            keyCheckValue: Maybe<byte[]>.From(keyCheckValue)
        );
    }

    /// <summary>
    /// Creates a key data block for a 3DES key (triple length).
    /// </summary>
    /// <param name="keyValue">The 24-byte 3DES key value.</param>
    /// <param name="keyCheckValue">The 3-byte key check value (optional).</param>
    /// <returns>A Result containing the KeyDataBlock for 3DES (triple length) or an error.</returns>
    public static Result<KeyDataBlock, SmartCardError> CreateTripleDes3Key(
        byte[]? keyValue,
        byte[]? keyCheckValue = null
    )
    {
        return CreateKeyBlock(
            KeyType.TripleDes3Key,
            "3DES triple-length",
            keyValue,
            expectedLength: 24,
            keyCheckValue: Maybe<byte[]>.From(keyCheckValue)
        );
    }

    /// <summary>
    /// Creates a key data block for an AES-128 key.
    /// </summary>
    /// <param name="keyValue">The 16-byte AES key value.</param>
    /// <param name="keyCheckValue">The 3-byte key check value (optional).</param>
    /// <returns>A Result containing the KeyDataBlock for AES-128 or an error.</returns>
    public static Result<KeyDataBlock, SmartCardError> CreateAes128Key(
        byte[]? keyValue,
        byte[]? keyCheckValue = null
    )
    {
        return CreateKeyBlock(
            KeyType.Aes128,
            "AES-128",
            keyValue,
            expectedLength: 16,
            keyCheckValue: Maybe<byte[]>.From(keyCheckValue)
        );
    }

    /// <summary>
    /// Creates a key data block for an AES-192 key.
    /// </summary>
    /// <param name="keyValue">The 24-byte AES key value.</param>
    /// <param name="keyCheckValue">The 3-byte key check value (optional).</param>
    /// <returns>A Result containing the KeyDataBlock for AES-192 or an error.</returns>
    public static Result<KeyDataBlock, SmartCardError> CreateAes192Key(
        byte[]? keyValue,
        byte[]? keyCheckValue = null
    )
    {
        return CreateKeyBlock(
            KeyType.Aes192,
            "AES-192",
            keyValue,
            expectedLength: 24,
            keyCheckValue: Maybe<byte[]>.From(keyCheckValue)
        );
    }

    /// <summary>
    /// Creates a key data block for an AES-256 key.
    /// </summary>
    /// <param name="keyValue">The 32-byte AES key value.</param>
    /// <param name="keyCheckValue">The 3-byte key check value (optional).</param>
    /// <returns>A Result containing the KeyDataBlock for AES-256 or an error.</returns>
    public static Result<KeyDataBlock, SmartCardError> CreateAes256Key(
        byte[]? keyValue,
        byte[]? keyCheckValue = null
    )
    {
        return CreateKeyBlock(
            KeyType.Aes256,
            "AES-256",
            keyValue,
            expectedLength: 32,
            keyCheckValue: Maybe<byte[]>.From(keyCheckValue)
        );
    }
}

/// <summary>
/// Represents the response to a PUT KEY command.
/// </summary>
[PublicAPI]
public class PutKeyResponse
{
    public byte KeyVersion { get; }

    /// <summary>
    /// Gets the key check values for the installed keys.
    /// </summary>
    public IReadOnlyList<byte[]> KeyCheckValues { get; }

    /// <summary>
    /// Initializes a new instance of the PutKeyResponse class.
    /// </summary>
    /// <param name="keyCheckValues">The key check values.</param>
    public PutKeyResponse(IList<byte[]> keyCheckValues)
        : this(0x00, keyCheckValues) { }

    public PutKeyResponse(byte keyVersion, IList<byte[]> keyCheckValues)
    {
        KeyVersion = keyVersion;
        KeyCheckValues = new List<byte[]>(keyCheckValues?.Select(kcv => (byte[])kcv.Clone()) ?? []);
    }

    /// <summary>
    /// Parses a PUT KEY response.
    /// </summary>
    /// <param name="response">The response data (excluding status word).</param>
    /// <returns>A Result containing the parsed response or an error.</returns>
    public static Result<PutKeyResponse, SmartCardError> Parse(byte[] response)
    {
        if (response == null)
        {
            return SmartCardError.InvalidArgument("Response data cannot be null.");
        }

        if (response.Length < 1 || (response.Length - 1) % 3 != 0)
        {
            return SmartCardError.InvalidResponse(
                $"Invalid response length {response.Length}, expected a key version followed by 3-byte key check values."
            );
        }

        List<byte[]> keyCheckValues = [];

        // Each key check value is 3 bytes
        for (int i = 1; i + 2 < response.Length; i += 3)
        {
            byte[] kcv = [.. response.Skip(i).Take(3)];
            keyCheckValues.Add(kcv);
        }

        return new PutKeyResponse(response[0], keyCheckValues);
    }
}
