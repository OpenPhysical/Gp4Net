using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;
using JetBrains.Annotations;
using WSCT.ISO7816;
using static Gp4Net.Constants.Constants;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents the STORE DATA command for storing data objects on the card.
/// </summary>
[PublicAPI]
public class StoreDataCommand : IApduCommand
{
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

    /// <inheritdoc />
    public byte Cla => GlobalPlatform.Cla.GP_STANDARD;

    /// <inheritdoc />
    public byte Ins => GlobalPlatform.Ins.STORE_DATA;

    /// <summary>
    /// Converts this command to a CommandAPDU.
    /// </summary>
    /// <returns>A result containing the CommandAPDU or an error.</returns>
    public Result<CommandAPDU, SmartCardError> ToCommandApdu()
    {
        // Build APDU bytes using immutable construction
        var headerBytes = new byte[]
        {
            GlobalPlatform.Cla.GP_STANDARD,
            GlobalPlatform.Ins.STORE_DATA,
            (byte)StructureFormat,
            (byte)Block,
        };

        var apduBytes =
            StoreData.Length > 0
                ? headerBytes
                    .Concat([(byte)StoreData.Length]) // Lc
                    .Concat(StoreData)
                    .ToArray()
                : headerBytes;

        return Result.Success<CommandAPDU, SmartCardError>(new CommandAPDU(apduBytes));
    }

    /// <summary>
    /// Gets the parameter 1 byte.
    /// </summary>
    public byte P1
    {
        get { return (byte)StructureFormat; }
    }

    /// <summary>
    /// Gets the parameter 2 byte.
    /// </summary>
    public byte P2
    {
        get { return (byte)Block; }
    }

    /// <summary>
    /// Gets the command data.
    /// </summary>
    public byte[] Data
    {
        get { return StoreData.Length > 0 ? StoreData : []; }
    }

    /// <summary>
    /// Gets the expected response length (None for STORE DATA as it's a case 3 command).
    /// </summary>
    public Maybe<int> ExpectedResponseLength
    {
        get { return Maybe<int>.None; }
    }

    /// <summary>
    /// Gets whether this command uses extended length.
    /// </summary>
    public bool IsExtendedLength
    {
        get { return false; }
    }

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
        {
            return SmartCardError.InvalidArgument("Data cannot be null.");
        }

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
        byte[] data
    )
    {
        if (data == null)
        {
            return SmartCardError.InvalidArgument("Data cannot be null.");
        }

        return new StoreDataCommand(structureFormat, block, data);
    }

    /// <summary>
    /// Creates a STORE DATA command for setting the default key version.
    /// </summary>
    /// <param name="keyVersion">The default key version number.</param>
    /// <returns>A Result containing either a new StoreDataCommand or an error.</returns>
    public static Result<StoreDataCommand, SmartCardError> CreateDefaultKeyVersionCommand(
        byte keyVersion
    )
    {
        // Simple TLV format: 7F0D + length + key version
        byte[] data = [0x7F, 0x0D, 0x01, keyVersion];

        return new StoreDataCommand(DataStructureFormat.Dgi, BlockFormat.FirstOrOnly, data);
    }

    /// <summary>
    /// Returns the string representation of this command.
    /// </summary>
    /// <returns>The string "STORE DATA".</returns>
    public override string ToString()
    {
        return "STORE DATA";
    }

    /// <inheritdoc />
    public CommandAPDU ToApdu()
    {
        return ToCommandApdu().GetValueOrDefault(new CommandAPDU([]));
    }

    /// <inheritdoc />
    public byte[] ToBytes()
    {
        return ToCommandApdu().Map(cmd => cmd.ToBytes()).GetValueOrDefault([]);
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
