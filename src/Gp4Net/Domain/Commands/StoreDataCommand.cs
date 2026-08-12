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
        Dgi = 0x08,

        /// <summary>
        /// BER-TLV format.
        /// </summary>
        BerTlv = 0x10,
    }

    /// <summary>P1.b7-b6 data-encryption indication, independent of the structure bits.</summary>
    public enum EncryptionFormat : byte
    {
        None = 0x00,
        Encrypted = 0x60,
    }

    /// <summary>
    /// Last/more-block values for P1.b8.
    /// </summary>
    public enum BlockFormat : byte
    {
        /// <summary>
        /// First or only block.
        /// </summary>
        FirstOrOnly = 0x80,

        /// <summary>
        /// More blocks to follow.
        /// </summary>
        MoreBlocks = 0x00,

        /// <summary>
        /// Last block of sequence.
        /// </summary>
        LastBlock = 0x80,
    }

    /// <summary>
    /// Gets the data structure format.
    /// </summary>
    public DataStructureFormat StructureFormat { get; }

    public EncryptionFormat Encryption { get; }

    public bool ResponseDataExpected { get; }

    /// <summary>
    /// Gets the block format.
    /// </summary>
    public BlockFormat Block { get; }

    /// <summary>Zero-based block number encoded in P2.</summary>
    public byte BlockNumber { get; }

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
            P1,
            BlockNumber,
        };

        var apduBytes =
            StoreData.Length > 0
                ? headerBytes
                    .Concat([(byte)StoreData.Length]) // Lc
                    .Concat(StoreData)
                    .Concat(ResponseDataExpected ? new byte[] { 0x00 } : [])
                    .ToArray()
                : headerBytes;

        return Result.Success<CommandAPDU, SmartCardError>(new CommandAPDU(apduBytes));
    }

    /// <summary>
    /// Gets the parameter 1 byte.
    /// </summary>
    public byte P1
    {
        get
        {
            return (byte)(
                (byte)StructureFormat
                | (byte)Encryption
                | (byte)Block
                | (ResponseDataExpected ? 0x01 : 0x00)
            );
        }
    }

    /// <summary>
    /// Gets the parameter 2 byte.
    /// </summary>
    public byte P2
    {
        get { return BlockNumber; }
    }

    /// <summary>
    /// Gets the command data.
    /// </summary>
    public byte[] Data
    {
        get { return StoreData.Length > 0 ? StoreData : []; }
    }

    /// <summary>
    /// Gets the expected response length for case-4 STORE DATA.
    /// </summary>
    public Maybe<int> ExpectedResponseLength
    {
        get { return ResponseDataExpected ? Maybe<int>.From(256) : Maybe<int>.None; }
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
    /// <param name="encryption">The independent data-encryption indication.</param>
    /// <param name="block">The block format.</param>
    /// <param name="blockNumber">The sequential block number encoded in P2.</param>
    /// <param name="data">The data to store.</param>
    /// <param name="responseDataExpected">Whether P1.b1 requests response data.</param>
    private StoreDataCommand(
        DataStructureFormat structureFormat,
        EncryptionFormat encryption,
        BlockFormat block,
        byte blockNumber,
        byte[] data,
        bool responseDataExpected
    )
    {
        StructureFormat = structureFormat;
        Encryption = encryption;
        Block = block;
        BlockNumber = blockNumber;
        StoreData = data;
        ResponseDataExpected = responseDataExpected;
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

        // GP Card Spec 2.3.1, Table 11-89: a single block sets P1.b8 and uses P2=00.
        return new StoreDataCommand(
            DataStructureFormat.Plain,
            EncryptionFormat.None,
            BlockFormat.FirstOrOnly,
            0x00,
            data,
            false
        );
    }

    /// <summary>
    /// Creates a STORE DATA command with specified format and block settings.
    /// </summary>
    /// <param name="structureFormat">The data structure format.</param>
    /// <param name="block">The block format.</param>
    /// <param name="data">The data to store.</param>
    /// <param name="blockNumber">The sequential block number encoded in P2.</param>
    /// <param name="encryption">The independent data-encryption indication.</param>
    /// <param name="responseDataExpected">Whether P1.b1 requests response data.</param>
    /// <returns>A Result containing either a new StoreDataCommand or an error.</returns>
    public static Result<StoreDataCommand, SmartCardError> CreateWithFormat(
        DataStructureFormat structureFormat,
        BlockFormat block,
        byte[] data,
        byte blockNumber = 0x00,
        EncryptionFormat encryption = EncryptionFormat.None,
        bool responseDataExpected = false
    )
    {
        if (data == null)
        {
            return SmartCardError.InvalidArgument("Data cannot be null.");
        }

        // GP Card Spec 2.3.1, 11.11.2: all flags are in P1; P2 is the
        // sequential block number starting at 00.
        return new StoreDataCommand(
            structureFormat,
            encryption,
            block,
            blockNumber,
            data,
            responseDataExpected
        );
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

        return new StoreDataCommand(
            DataStructureFormat.Dgi,
            EncryptionFormat.None,
            BlockFormat.FirstOrOnly,
            0x00,
            data,
            false
        );
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
        return ToCommandApdu()
            .Match(
                onSuccess: apdu => apdu,
                onFailure: _ => new CommandAPDU(
                    GlobalPlatform.Cla.GP_STANDARD,
                    GlobalPlatform.Ins.STORE_DATA,
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
                        GlobalPlatform.Ins.STORE_DATA,
                        0x00,
                        0x00
                    ).ToBytes()
            );
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
