using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Commands
{
    /// <summary>
    /// Represents the STORE DATA command for storing data objects on the card.
    /// </summary>
    [PublicAPI]
    public class StoreDataCommand : IApduCommand
    {
        /// <summary>
        /// The command class byte.
        /// </summary>
        public const byte Cla = 0x80;

        /// <summary>
        /// The command instruction byte.
        /// </summary>
        public const byte Ins = 0xE2;

        /// <summary>
        /// Data structure format values for P1.
        /// </summary>
        public enum DataStructureFormat : byte
        {
            /// <summary>
            /// Plain data (no structure).
            /// </summary>
            Plain = 0x00,

            /// <summary>
            /// DGI (Data Grouping Identifier) format.
            /// </summary>
            Dgi = 0x80,

            /// <summary>
            /// BER-TLV format.
            /// </summary>
            BerTlv = 0x60,

            /// <summary>
            /// Encrypted data.
            /// </summary>
            Encrypted = 0x20,
        }

        /// <summary>
        /// Block format values for P2.
        /// </summary>
        public enum BlockFormat : byte
        {
            /// <summary>
            /// First or only block.
            /// </summary>
            FirstOrOnly = 0x00,

            /// <summary>
            /// More blocks to follow.
            /// </summary>
            MoreBlocks = 0x01,

            /// <summary>
            /// Last block of sequence.
            /// </summary>
            LastBlock = 0x02,
        }

        /// <summary>
        /// Gets the data structure format.
        /// </summary>
        public DataStructureFormat StructureFormat { get; }

        /// <summary>
        /// Gets the block format.
        /// </summary>
        public BlockFormat Block { get; }

        /// <summary>
        /// Gets the data to store.
        /// </summary>
        public byte[] StoreData { get; }

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
        public byte P1 => (byte)StructureFormat;

        /// <summary>
        /// Gets the parameter 2 byte.
        /// </summary>
        public byte P2 => (byte)Block;

        /// <summary>
        /// Gets the command data.
        /// </summary>
        public byte[]? Data => StoreData.Length > 0 ? StoreData : null;

        /// <summary>
        /// Gets the expected response length (null for STORE DATA as it's a case 3 command).
        /// </summary>
        public int? ExpectedResponseLength => null;

        /// <summary>
        /// Gets whether this command uses extended length.
        /// </summary>
        public bool IsExtendedLength => false;

        /// <summary>
        /// Initializes a new instance of the StoreDataCommand class.
        /// </summary>
        /// <param name="structureFormat">The data structure format.</param>
        /// <param name="block">The block format.</param>
        /// <param name="data">The data to store.</param>
        private StoreDataCommand(DataStructureFormat structureFormat, BlockFormat block, byte[] data)
        {
            StructureFormat = structureFormat;
            Block = block;
            StoreData = data;
        }

        /// <summary>
        /// Creates a STORE DATA command with plain data.
        /// </summary>
        /// <param name="data">The data to store.</param>
        /// <returns>A Result containing either a new StoreDataCommand or an error.</returns>
        public static Result<StoreDataCommand, SmartCardError> Create(byte[] data)
        {
            if (data == null)
                return SmartCardError.InvalidArgument("Data cannot be null.");

            return new StoreDataCommand(DataStructureFormat.Plain, BlockFormat.FirstOrOnly, data);
        }

        /// <summary>
        /// Creates a STORE DATA command with specified format and block settings.
        /// </summary>
        /// <param name="structureFormat">The data structure format.</param>
        /// <param name="block">The block format.</param>
        /// <param name="data">The data to store.</param>
        /// <returns>A Result containing either a new StoreDataCommand or an error.</returns>
        public static Result<StoreDataCommand, SmartCardError> CreateWithFormat(
            DataStructureFormat structureFormat,
            BlockFormat block,
            byte[] data)
        {
            if (data == null)
                return SmartCardError.InvalidArgument("Data cannot be null.");

            return new StoreDataCommand(structureFormat, block, data);
        }


        /// <summary>
        /// Creates a STORE DATA command for setting the default key version.
        /// </summary>
        /// <param name="keyVersion">The default key version number.</param>
        /// <returns>A Result containing either a new StoreDataCommand or an error.</returns>
        public static Result<StoreDataCommand, SmartCardError> CreateDefaultKeyVersionCommand(byte keyVersion)
        {
            // Simple TLV format: 7F0D + length + key version
            var data = new byte[] { 0x7F, 0x0D, 0x01, keyVersion };

            return new StoreDataCommand(DataStructureFormat.Dgi, BlockFormat.FirstOrOnly, data);
        }

        /// <summary>
        /// Returns the string representation of this command.
        /// </summary>
        /// <returns>The string "STORE DATA".</returns>
        public override string ToString() => "STORE DATA";

        /// <summary>
        /// Converts this command to an APDU byte array.
        /// </summary>
        /// <returns>The APDU command bytes.</returns>
        public byte[] ToApdu()
        {
            var apdu = new List<byte> { Cla, Ins, P1, P2 };

            if (StoreData.Length > 0)
            {
                apdu.Add((byte)StoreData.Length);
                apdu.AddRange(StoreData);
            }

            return [.. apdu];
        }
    }

    /// <summary>
    /// Represents the response to a STORE DATA command.
    /// </summary>
    [PublicAPI]
    public class StoreDataResponse
    {
        /// <summary>
        /// Gets whether the operation was successful.
        /// </summary>
        public bool Success { get; }

        /// <summary>
        /// Initializes a new instance of the StoreDataResponse class.
        /// </summary>
        /// <param name="success">Whether the operation was successful.</param>
        public StoreDataResponse(bool success)
        {
            Success = success;
        }

        /// <summary>
        /// Parses a STORE DATA response.
        /// </summary>
        /// <param name="response">The response data (excluding status word).</param>
        /// <returns>The parsed response.</returns>
        public static StoreDataResponse Parse(byte[] response)
        {
            // STORE DATA typically returns no data on success
            return new StoreDataResponse(true);
        }
    }
}
