using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands
{
    /// <summary>
    /// Represents the PUT KEY command for key establishment and replacement.
    /// </summary>
    [PublicAPI]
    public class PutKeyCommand : IApduCommand
    {
        /// <summary>
        /// The command class byte.
        /// </summary>
        public const byte Cla = 0x80;

        /// <summary>
        /// The command instruction byte.
        /// </summary>
        public const byte Ins = 0xD8;

        /// <summary>
        /// Key usage qualifier values for P1.
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
        /// Key encryption key identifier values for P2.
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

        /// <summary>
        /// Gets the class byte.
        /// </summary>
        byte IApduCommand.Cla => Cla;

        /// <summary>
        /// Gets the instruction byte.
        /// </summary>
        byte IApduCommand.Ins => Ins;

        /// <summary>
        /// Gets the parameter 1 byte.
        /// </summary>
        public byte P1 => (byte)UsageQualifier;

        /// <summary>
        /// Gets the parameter 2 byte.
        /// </summary>
        public byte P2 => (byte)KekIdentifier;

        /// <summary>
        /// Gets the command data.
        /// </summary>
        public byte[]? Data
        {
            get
            {
                var data = new List<byte>();
                foreach (var block in KeyDataBlocks)
                {
                    data.AddRange(block.ToBytes());
                }
                return data.Count > 0 ? [.. data] : null;
            }
        }

        /// <summary>
        /// Gets the expected response length (null for PUT KEY as it's a case 3 command).
        /// </summary>
        public int? ExpectedResponseLength => null;

        /// <summary>
        /// Gets whether this command uses extended length.
        /// </summary>
        public bool IsExtendedLength => false;

        /// <summary>
        /// Initializes a new instance of the PutKeyCommand class.
        /// </summary>
        /// <param name="usageQualifier">The key usage qualifier.</param>
        /// <param name="kekIdentifier">The key encryption key identifier.</param>
        /// <param name="keyDataBlocks">The key data blocks.</param>
        public PutKeyCommand(
            KeyUsageQualifier usageQualifier,
            KeyEncryptionKeyIdentifier kekIdentifier,
            IList<KeyDataBlock> keyDataBlocks
        )
        {
            if (keyDataBlocks == null || keyDataBlocks.Count == 0)
            {
                throw new ArgumentException(
                    "At least one key data block is required.",
                    nameof(keyDataBlocks)
                );
            }

            UsageQualifier = usageQualifier;
            KekIdentifier = kekIdentifier;
            KeyDataBlocks = new List<KeyDataBlock>(keyDataBlocks);
        }

        /// <summary>
        /// Converts this command to an APDU byte array.
        /// </summary>
        /// <returns>The APDU command bytes.</returns>
        public byte[] ToApdu()
        {
            // Calculate total data length
            int dataLength = 0;
            foreach (var block in KeyDataBlocks)
            {
                dataLength += block.ToBytes().Length;
            }

            var apdu = new List<byte>
            {
                Cla,
                Ins,
                (byte)UsageQualifier,
                (byte)KekIdentifier,
                (byte)dataLength,
            };

            // Add key data blocks
            foreach (var block in KeyDataBlocks)
            {
                apdu.AddRange(block.ToBytes());
            }

            // Note: PUT KEY is Case 3 APDU (no response data expected)
            // Therefore, no LE byte should be added

            return [.. apdu];
        }
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
            /// 3DES key (double length).
            /// </summary>
            TripleDes2Key = 0x81,

            /// <summary>
            /// 3DES key (triple length).
            /// </summary>
            TripleDes3Key = 0x82,

            /// <summary>
            /// AES key (128 bits).
            /// </summary>
            Aes128 = 0x88,

            /// <summary>
            /// AES key (192 bits).
            /// </summary>
            Aes192 = 0x89,

            /// <summary>
            /// AES key (256 bits).
            /// </summary>
            Aes256 = 0x8A,

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
        public byte Length { get; }

        /// <summary>
        /// Gets the key value.
        /// </summary>
        public byte[] Value { get; }

        /// <summary>
        /// Gets the key check value (optional).
        /// </summary>
        public byte[]? KeyCheckValue { get; }

        /// <summary>
        /// Initializes a new instance of the KeyDataBlock class.
        /// </summary>
        /// <param name="type">The key type.</param>
        /// <param name="value">The key value.</param>
        /// <param name="keyCheckValue">The key check value (optional, 3 bytes).</param>
        public KeyDataBlock(KeyType type, byte[] value, byte[]? keyCheckValue = null)
        {
            ArgumentNullException.ThrowIfNull(value);

            if (keyCheckValue != null && keyCheckValue.Length != 3)
            {
                throw new ArgumentException(
                    "Key check value must be 3 bytes.",
                    nameof(keyCheckValue)
                );
            }

            Type = type;
            Length = (byte)value.Length;
            Value = (byte[])value.Clone();
            KeyCheckValue = keyCheckValue != null ? (byte[])keyCheckValue.Clone() : null;
        }

        /// <summary>
        /// Converts this key data block to bytes.
        /// </summary>
        /// <returns>The byte representation.</returns>
        public byte[] ToBytes()
        {
            var result = new List<byte> { (byte)Type, Length };

            result.AddRange(Value);

            if (KeyCheckValue != null)
            {
                result.AddRange(KeyCheckValue);
            }

            return [.. result];
        }

        /// <summary>
        /// Creates a key data block for a DES key.
        /// </summary>
        /// <param name="keyValue">The 8-byte DES key value.</param>
        /// <param name="keyCheckValue">The 3-byte key check value (optional).</param>
        /// <returns>A new KeyDataBlock for DES.</returns>
        public static KeyDataBlock CreateDesKey(byte[] keyValue, byte[]? keyCheckValue = null)
        {
            if (keyValue?.Length != 8)
            {
                throw new ArgumentException("DES key must be 8 bytes.", nameof(keyValue));
            }

            return new KeyDataBlock(KeyType.Des, keyValue, keyCheckValue);
        }

        /// <summary>
        /// Creates a key data block for a 3DES key (double length).
        /// </summary>
        /// <param name="keyValue">The 16-byte 3DES key value.</param>
        /// <param name="keyCheckValue">The 3-byte key check value (optional).</param>
        /// <returns>A new KeyDataBlock for 3DES (double length).</returns>
        public static KeyDataBlock CreateTripleDes2Key(
            byte[] keyValue,
            byte[]? keyCheckValue = null
        )
        {
            if (keyValue?.Length != 16)
            {
                throw new ArgumentException(
                    "3DES double-length key must be 16 bytes.",
                    nameof(keyValue)
                );
            }

            return new KeyDataBlock(KeyType.TripleDes2Key, keyValue, keyCheckValue);
        }

        /// <summary>
        /// Creates a key data block for a 3DES key (triple length).
        /// </summary>
        /// <param name="keyValue">The 24-byte 3DES key value.</param>
        /// <param name="keyCheckValue">The 3-byte key check value (optional).</param>
        /// <returns>A new KeyDataBlock for 3DES (triple length).</returns>
        public static KeyDataBlock CreateTripleDes3Key(
            byte[] keyValue,
            byte[]? keyCheckValue = null
        )
        {
            if (keyValue?.Length != 24)
            {
                throw new ArgumentException(
                    "3DES triple-length key must be 24 bytes.",
                    nameof(keyValue)
                );
            }

            return new KeyDataBlock(KeyType.TripleDes3Key, keyValue, keyCheckValue);
        }

        /// <summary>
        /// Creates a key data block for an AES-128 key.
        /// </summary>
        /// <param name="keyValue">The 16-byte AES key value.</param>
        /// <param name="keyCheckValue">The 3-byte key check value (optional).</param>
        /// <returns>A new KeyDataBlock for AES-128.</returns>
        public static KeyDataBlock CreateAes128Key(byte[] keyValue, byte[]? keyCheckValue = null)
        {
            if (keyValue?.Length != 16)
            {
                throw new ArgumentException("AES-128 key must be 16 bytes.", nameof(keyValue));
            }

            return new KeyDataBlock(KeyType.Aes128, keyValue, keyCheckValue);
        }

        /// <summary>
        /// Creates a key data block for an AES-192 key.
        /// </summary>
        /// <param name="keyValue">The 24-byte AES key value.</param>
        /// <param name="keyCheckValue">The 3-byte key check value (optional).</param>
        /// <returns>A new KeyDataBlock for AES-192.</returns>
        public static KeyDataBlock CreateAes192Key(byte[] keyValue, byte[]? keyCheckValue = null)
        {
            if (keyValue?.Length != 24)
            {
                throw new ArgumentException("AES-192 key must be 24 bytes.", nameof(keyValue));
            }

            return new KeyDataBlock(KeyType.Aes192, keyValue, keyCheckValue);
        }

        /// <summary>
        /// Creates a key data block for an AES-256 key.
        /// </summary>
        /// <param name="keyValue">The 32-byte AES key value.</param>
        /// <param name="keyCheckValue">The 3-byte key check value (optional).</param>
        /// <returns>A new KeyDataBlock for AES-256.</returns>
        public static KeyDataBlock CreateAes256Key(byte[] keyValue, byte[]? keyCheckValue = null)
        {
            if (keyValue?.Length != 32)
            {
                throw new ArgumentException("AES-256 key must be 32 bytes.", nameof(keyValue));
            }

            return new KeyDataBlock(KeyType.Aes256, keyValue, keyCheckValue);
        }
    }

    /// <summary>
    /// Represents the response to a PUT KEY command.
    /// </summary>
    [PublicAPI]
    public class PutKeyResponse
    {
        /// <summary>
        /// Gets the key check values for the installed keys.
        /// </summary>
        public IReadOnlyList<byte[]> KeyCheckValues { get; }

        /// <summary>
        /// Initializes a new instance of the PutKeyResponse class.
        /// </summary>
        /// <param name="keyCheckValues">The key check values.</param>
        public PutKeyResponse(IList<byte[]> keyCheckValues)
        {
            KeyCheckValues = new List<byte[]>(
                keyCheckValues?.Select(kcv => (byte[])kcv.Clone()) ?? Array.Empty<byte[]>()
            );
        }

        /// <summary>
        /// Parses a PUT KEY response.
        /// </summary>
        /// <param name="response">The response data (excluding status word).</param>
        /// <returns>The parsed response.</returns>
        public static PutKeyResponse Parse(byte[] response)
        {
            ArgumentNullException.ThrowIfNull(response);

            var keyCheckValues = new List<byte[]>();

            // Each key check value is 3 bytes
            for (int i = 0; i + 2 < response.Length; i += 3)
            {
                var kcv = new byte[3];
                Array.Copy(response, i, kcv, 0, 3);
                keyCheckValues.Add(kcv);
            }

            return new PutKeyResponse(keyCheckValues);
        }
    }
}
