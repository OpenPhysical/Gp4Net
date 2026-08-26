using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;
using Gp4Net.Transport;
using JetBrains.Annotations;
using WSCT.ISO7816;

namespace Gp4Net.Domain.Commands;

/// <summary>
/// Represents the LOAD command for loading CAP file data to the card.
/// Used to transfer CAP file content in chunks after INSTALL [for load].
/// </summary>
[PublicAPI]
public class LoadCommand : IApduCommand
{
    /// <summary>
    /// CAP file data TLV tag.
    /// </summary>
    public const byte CAP_DATA_TAG = Constants.Constants.GlobalPlatform.Tags.CAP_DATA_TLV_TAG;

    /// <summary>
    /// P1 values for load operations.
    /// </summary>
    public enum LoadType : byte
    {
        /// <summary>
        /// Continuation block.
        /// </summary>
        Continuation = 0x00,

        /// <summary>
        /// Final block.
        /// </summary>
        Final = 0x80,
    }

    /// <summary>
    /// Gets the load type (continuation or final).
    /// </summary>
    public LoadType Type { get; }

    /// <summary>
    /// Gets the block number.
    /// </summary>
    public byte BlockNumber { get; }

    /// <summary>
    /// Backing field for load data.
    /// </summary>
    private readonly byte[] _data;

    /// <summary>
    /// Gets the data to load.
    /// </summary>
    public byte[] Data
    {
        get { return GetCommandData(); }
    }

    /// <summary>
    /// Gets the total CAP file size (only included in first block).
    /// </summary>
    public Maybe<uint> TotalCapSize { get; }

    /// <summary>
    /// Gets a value indicating whether this is the first block.
    /// </summary>
    public bool IsFirstBlock
    {
        get { return BlockNumber == 0; }
    }

    /// <inheritdoc />
    public byte Cla => Constants.Constants.GlobalPlatform.Cla.GP_STANDARD;

    /// <inheritdoc />
    public byte Ins => Constants.Constants.GlobalPlatform.Ins.LOAD;

    /// <summary>
    /// Gets a value indicating whether this is the final block.
    /// </summary>
    public bool IsFinalBlock
    {
        get { return Type == LoadType.Final; }
    }

    /// <summary>
    /// Converts this command to a CommandAPDU.
    /// </summary>
    /// <returns>A result containing the CommandAPDU or an error.</returns>
    public Result<CommandAPDU, SmartCardError> ToCommandApdu()
    {
        var data = GetCommandData();
        return Result.Success<CommandAPDU, SmartCardError>(
            new CommandAPDU(
                Constants.Constants.GlobalPlatform.Cla.GP_STANDARD,
                Constants.Constants.GlobalPlatform.Ins.LOAD,
                (byte)Type,
                BlockNumber,
                (uint)data.Length,
                data,
                0
            )
        );
    }

    /// <summary>
    /// Gets the parameter 1 byte.
    /// </summary>
    public byte P1
    {
        get { return (byte)Type; }
    }

    /// <summary>
    /// Gets the parameter 2 byte.
    /// </summary>
    public byte P2
    {
        get { return BlockNumber; }
    }

    /// <summary>
    /// Gets the expected response length.
    /// </summary>
    public Maybe<int> ExpectedResponseLength
    {
        get { return Maybe<int>.From(0); } // LE=0x00 means maximum response length
    }

    /// <summary>
    /// Gets whether this command uses extended length.
    /// </summary>
    public bool IsExtendedLength
    {
        get { return false; }
    }

    /// <summary>
    /// Gets the command data for the IApduCommand interface.
    /// </summary>
    private byte[] GetCommandData()
    {
        List<byte> data = [];

        if (IsFirstBlock && TotalCapSize.HasValue)
        {
            // First block includes TLV header: C4 <total_length> <data>
            data.Add(CAP_DATA_TAG);

            // Encode length (up to 3 bytes for length field)
            uint totalSize = TotalCapSize.Value;
            switch (totalSize)
            {
                case <= 0x7F:
                    data.Add((byte)totalSize);
                    break;
                case <= 0xFF:
                    data.Add(0x81);
                    data.Add((byte)totalSize);
                    break;
                case <= 0xFFFF:
                    data.Add(0x82);
                    data.Add((byte)(totalSize >> 8));
                    data.Add((byte)(totalSize & 0xFF));
                    break;
                case <= 0xFFFFFF:
                    data.Add(0x83);
                    data.Add((byte)(totalSize >> 16));
                    data.Add((byte)(totalSize >> 8 & 0xFF));
                    data.Add((byte)(totalSize & 0xFF));
                    break;
                default:
                    data.Add(0x84);
                    data.Add((byte)(totalSize >> 24));
                    data.Add((byte)(totalSize >> 16 & 0xFF));
                    data.Add((byte)(totalSize >> 8 & 0xFF));
                    data.Add((byte)(totalSize & 0xFF));
                    break;
            }
        }

        // Add the actual data
        data.AddRange(_data);

        return [.. data];
    }

    /// <summary>
    /// Initializes a new instance of the LoadCommand class.
    /// </summary>
    /// <param name="blockNumber">The block number (0-based).</param>
    /// <param name="data">The data to load.</param>
    /// <param name="isFinalBlock">Whether this is the final block.</param>
    /// <param name="totalCapSize">The total CAP file size (required for first block).</param>
    private LoadCommand(byte blockNumber, byte[] data, bool isFinalBlock, Maybe<uint> totalCapSize)
    {
        BlockNumber = blockNumber;
        _data = (byte[])data.Clone();
        Type = isFinalBlock ? LoadType.Final : LoadType.Continuation;
        TotalCapSize = totalCapSize;
    }

    /// <summary>
    /// Creates a single LOAD command with validation.
    /// </summary>
    /// <param name="blockNumber">The block number (0-based).</param>
    /// <param name="data">The data to load.</param>
    /// <param name="isLastBlock">Whether this is the last block.</param>
    /// <returns>A Result containing the LoadCommand or an error.</returns>
    public static Result<LoadCommand, SmartCardError> Create(
        byte blockNumber,
        byte[] data,
        bool isLastBlock = false
    )
    {
        if (data == null)
        {
            return Result.Failure<LoadCommand, SmartCardError>(
                SmartCardError.InvalidArgument("Data cannot be null.")
            );
        }

        if (data.Length == 0)
        {
            return Result.Failure<LoadCommand, SmartCardError>(
                SmartCardError.InvalidArgument("Data cannot be empty.")
            );
        }

        var totalCapSize =
            blockNumber == 0 ? Maybe<uint>.From((uint)data.Length) : Maybe<uint>.None;

        var command = new LoadCommand(blockNumber, data, isLastBlock, totalCapSize);
        return Result.Success<LoadCommand, SmartCardError>(command);
    }

    /// <summary>
    /// Creates a sequence of LOAD commands from CAP file data.
    /// </summary>
    /// <param name="capFileData">The complete CAP file data.</param>
    /// <param name="maxBlockSize">Maximum block size (default optimized for smart cards).</param>
    /// <returns>A Result containing the sequence of LOAD commands or an error.</returns>
    public static Result<IList<LoadCommand>, SmartCardError> CreateFromCapFile(
        byte[] capFileData,
        int maxBlockSize = Constants.Constants.GlobalPlatform.ApduLimits.DEFAULT_LOAD_BLOCK_SIZE
    )
    {
        if (capFileData == null)
        {
            return Result.Failure<IList<LoadCommand>, SmartCardError>(
                SmartCardError.InvalidArgument("CAP file data cannot be null.")
            );
        }

        if (capFileData.Length == 0)
        {
            return Result.Failure<IList<LoadCommand>, SmartCardError>(
                SmartCardError.InvalidArgument("CAP file data cannot be empty.")
            );
        }

        if (maxBlockSize is < 1 or > 255)
        {
            return Result.Failure<IList<LoadCommand>, SmartCardError>(
                SmartCardError.InvalidArgument("Block size must be between 1 and 255 bytes.")
            );
        }

        List<LoadCommand> commands = [];
        uint totalSize = (uint)capFileData.Length;
        int offset = 0;
        byte blockNumber = 0;

        while (offset < capFileData.Length)
        {
            int remainingBytes = capFileData.Length - offset;
            int effectiveBlockSize = maxBlockSize;

            // For first block, account for TLV header overhead
            if (blockNumber == 0)
            {
                int tlvHeaderSize = CalculateTlvHeaderSize(totalSize);
                effectiveBlockSize = Math.Max(1, maxBlockSize - tlvHeaderSize);
            }

            int blockSize = Math.Min(remainingBytes, effectiveBlockSize);
            byte[] blockData = new byte[blockSize];

            Array.Copy(capFileData, offset, blockData, 0, blockSize);

            bool isFinalBlock = offset + blockSize >= capFileData.Length;
            var totalCapSize = blockNumber == 0 ? Maybe<uint>.From(totalSize) : Maybe<uint>.None;

            commands.Add(new LoadCommand(blockNumber, blockData, isFinalBlock, totalCapSize));

            offset += blockSize;
            blockNumber++;
        }

        return Result.Success<IList<LoadCommand>, SmartCardError>(commands);
    }

    /// <summary>Creates LOAD commands from an already encoded Load File (optional E2 blocks followed by C4).</summary>
    public static Result<IList<LoadCommand>, SmartCardError> CreateFromEncodedLoadFile(
        byte[] encodedLoadFile,
        int maxBlockSize = Constants.Constants.GlobalPlatform.ApduLimits.DEFAULT_LOAD_BLOCK_SIZE
    )
    {
        if (encodedLoadFile is null || encodedLoadFile.Length == 0)
            return SmartCardError.InvalidArgument("Encoded Load File cannot be null or empty.");
        if (maxBlockSize is < 1 or > 255)
            return SmartCardError.InvalidArgument("Block size must be between 1 and 255 bytes.");

        List<LoadCommand> commands = [];
        int offset = 0;
        byte blockNumber = 0;
        while (offset < encodedLoadFile.Length)
        {
            if (blockNumber == byte.MaxValue && encodedLoadFile.Length - offset > maxBlockSize)
                return SmartCardError.InvalidArgument("Encoded Load File requires more than 256 LOAD blocks.");
            int count = Math.Min(maxBlockSize, encodedLoadFile.Length - offset);
            byte[] block = encodedLoadFile.AsSpan(offset, count).ToArray();
            bool final = offset + count == encodedLoadFile.Length;
            commands.Add(new LoadCommand(blockNumber, block, final, Maybe<uint>.None));
            offset += count;
            blockNumber++;
        }
        return commands;
    }

    /// <summary>
    /// Calculates the TLV header size for a given total CAP file size.
    /// </summary>
    /// <param name="totalSize">The total CAP file size.</param>
    /// <returns>The number of bytes needed for the TLV header (tag + length).</returns>
    private static int CalculateTlvHeaderSize(uint totalSize)
    {
        // C4 tag (1 byte) + length encoding
        int tagSize = 1;

        switch (totalSize)
        {
            case <= 0x7F:
                return tagSize + 1; // 1 byte length
            case <= 0xFF:
                return tagSize + 2; // 0x81 + 1 byte length
            case <= 0xFFFF:
                return tagSize + 3; // 0x82 + 2 bytes length
            case <= 0xFFFFFF:
                return tagSize + 4; // 0x83 + 3 bytes length
            default:
                return tagSize + 5; // 0x84 + 4 bytes length
        }
    }

    /// <summary>
    /// Creates a sequence of LOAD commands from a CAP file structure.
    /// </summary>
    /// <param name="capFile">The CAP file structure.</param>
    /// <param name="maxBlockSize">Maximum block size (default optimized for smart cards).</param>
    /// <returns>A Result containing the sequence of LOAD commands or an error.</returns>
    public static Result<IList<LoadCommand>, SmartCardError> CreateFromCapFile(
        CapFileStructure capFile,
        int maxBlockSize = Constants.Constants.GlobalPlatform.ApduLimits.DEFAULT_LOAD_BLOCK_SIZE
    )
    {
        if (capFile == null)
        {
            return Result.Failure<IList<LoadCommand>, SmartCardError>(
                SmartCardError.InvalidArgument("CAP file structure cannot be null.")
            );
        }

        var binaryDataResult = Gp4Net.Core.Functional.ResultExtensions.Try(
            () => capFile.ToBinaryFormat(),
            ex =>
                SmartCardError.InvalidData(
                    $"Failed to convert CAP file to binary format: {ex.Message}"
                )
        );

        return binaryDataResult.Bind(data => CreateFromCapFile(data, maxBlockSize));
    }

    /// <summary>
    /// Returns a string representation of this command.
    /// </summary>
    /// <returns>The string "LOAD".</returns>
    public override string ToString()
    {
        return "LOAD";
    }

    /// <inheritdoc />
    public CommandAPDU ToApdu()
    {
        return ToCommandApdu()
            .Match(onSuccess: apdu => apdu, onFailure: _ => new CommandAPDU(Cla, Ins, P1, P2));
    }

    /// <inheritdoc />
    public byte[] ToBytes()
    {
        return ToCommandApdu()
            .Match(
                onSuccess: cmd => cmd.ToBytes(),
                onFailure: _ => new CommandAPDU(Cla, Ins, P1, P2).ToBytes()
            );
    }
}

/// <summary>
/// Represents a strictly parsed LOAD response.
/// See GlobalPlatform Card Specification v2.3.1, sections 11.6.3 and 11.1.6.
/// </summary>
[PublicAPI]
public sealed class LoadResponse
{
    /// <summary>
    /// Gets the response data (typically empty for LOAD commands).
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Gets a value indicating whether the load was successful.
    /// </summary>
    public bool IsSuccessful { get; }

    /// <summary>
    /// Gets the status word from the response.
    /// </summary>
    public ushort StatusWord { get; }

    /// <summary>
    /// Gets the delegated-management receipt and Confirmation Data, when returned.
    /// See GlobalPlatform Card Specification v2.3.1, section 11.1.6 and Appendix C.5.1.
    /// </summary>
    public Maybe<LoadConfirmation> Confirmation { get; }

    /// <summary>
    /// Initializes a new instance of the LoadResponse class.
    /// </summary>
    /// <param name="data">The response data.</param>
    /// <param name="statusWord">The status word.</param>
    public LoadResponse(byte[] data, ushort statusWord)
        : this(data, statusWord, Maybe<LoadConfirmation>.None) { }

    private LoadResponse(byte[] data, ushort statusWord, Maybe<LoadConfirmation> confirmation)
    {
        Data = data != null ? (byte[])data.Clone() : [];
        StatusWord = statusWord;
        IsSuccessful = statusWord == 0x9000;
        Confirmation = confirmation;
    }

    /// <summary>
    /// Parses a LOAD response and rejects non-canonical lengths, truncation, and trailing data.
    /// </summary>
    /// <param name="response">The response data (excluding status word).</param>
    /// <param name="statusWord">The status word from the response.</param>
    /// <returns>The parsed response.</returns>
    public static Result<LoadResponse, SmartCardError> Parse(byte[] response, ushort statusWord)
    {
        response ??= [];
        if (statusWord != 0x9000)
            return new LoadResponse(response, statusWord);
        if (response.Length == 1 && response[0] == 0x00)
            return new LoadResponse(response, statusWord);
        if (response.Length == 0)
            return SmartCardError.InvalidData("LOAD response is missing its mandatory confirmation length.");

        return ReadBerLength(response, 0).Bind(length =>
        {
            if (length.Offset + length.Length != response.Length)
                return Result.Failure<LoadResponse, SmartCardError>(
                    SmartCardError.InvalidData("LOAD confirmation length does not consume the response."));
            if (length.Length == 0)
                return Result.Success<LoadResponse, SmartCardError>(new LoadResponse(response, statusWord));
            return ParseConfirmation(response.AsSpan(length.Offset, length.Length).ToArray())
                .Map(value => new LoadResponse(response, statusWord, Maybe<LoadConfirmation>.From(value)));
        });
    }

    private static Result<LoadConfirmation, SmartCardError> ParseConfirmation(byte[] data) =>
        ReadBerLength(data, 0).Bind(receiptLength =>
        {
            int receiptEnd = receiptLength.Offset + receiptLength.Length;
            if (receiptEnd > data.Length)
                return Result.Failure<LoadConfirmation, SmartCardError>(SmartCardError.InvalidData("Load Receipt is truncated."));
            byte[] receipt = data.AsSpan(receiptLength.Offset, receiptLength.Length).ToArray();
            int offset = receiptEnd;
            if (offset >= data.Length || data[offset++] != 2 || offset + 2 > data.Length)
                return Result.Failure<LoadConfirmation, SmartCardError>(SmartCardError.InvalidData("Confirmation Counter must contain two bytes."));
            ushort counter = (ushort)(data[offset] << 8 | data[offset + 1]);
            offset += 2;
            if (offset >= data.Length)
                return Result.Failure<LoadConfirmation, SmartCardError>(SmartCardError.InvalidData("SD Unique Data length is missing."));
            int uniqueLength = data[offset++];
            if (uniqueLength == 0 || offset + uniqueLength > data.Length)
                return Result.Failure<LoadConfirmation, SmartCardError>(SmartCardError.InvalidData("SD Unique Data is invalid."));
            byte[] uniqueData = data.AsSpan(offset, uniqueLength).ToArray();
            offset += uniqueLength;
            byte[] digest = [];
            if (offset < data.Length)
            {
                int digestLength = data[offset++];
                if (digestLength != 32 || offset + digestLength != data.Length)
                    return Result.Failure<LoadConfirmation, SmartCardError>(SmartCardError.InvalidData("Token Data digest must be a complete SHA-256 value."));
                digest = data.AsSpan(offset, digestLength).ToArray();
                offset += digestLength;
            }
            if (offset != data.Length)
                return Result.Failure<LoadConfirmation, SmartCardError>(SmartCardError.InvalidData("LOAD confirmation has trailing data."));
            return Result.Success<LoadConfirmation, SmartCardError>(new LoadConfirmation(receipt, counter, uniqueData, digest));
        });

    private static Result<(int Length, int Offset), SmartCardError> ReadBerLength(byte[] data, int offset)
    {
        if (offset >= data.Length)
            return SmartCardError.InvalidData("BER length is missing.");
        byte first = data[offset++];
        if (first <= 0x7F)
            return (first, offset);
        if (first != 0x81 || offset >= data.Length || data[offset] < 0x80)
            return SmartCardError.InvalidData("BER length is non-canonical or unsupported.");
        return (data[offset], offset + 1);
    }
}

/// <summary>
/// Contains a delegated LOAD Receipt and its Confirmation Data.
/// See GlobalPlatform Card Specification v2.3.1, section 11.1.6 and Appendix C.5.1.
/// </summary>
public sealed class LoadConfirmation
{
    private readonly byte[] _receipt;
    private readonly byte[] _sdUniqueData;
    private readonly byte[] _tokenDataDigest;
    /// <summary>Gets a defensive copy of the Load Receipt.</summary>
    public byte[] Receipt => (byte[])_receipt.Clone();

    /// <summary>Gets the 16-bit Receipt Generation Security Domain counter.</summary>
    public ushort ConfirmationCounter { get; }

    /// <summary>Gets a defensive copy of the SD Unique Data.</summary>
    public byte[] SecurityDomainUniqueData => (byte[])_sdUniqueData.Clone();

    /// <summary>Gets the optional SHA-256 token-data digest.</summary>
    public Maybe<byte[]> TokenDataDigest => _tokenDataDigest.Length == 0
        ? Maybe<byte[]>.None
        : Maybe<byte[]>.From((byte[])_tokenDataDigest.Clone());

    /// <summary>Creates an immutable parsed confirmation value.</summary>
    public LoadConfirmation(
        byte[] receipt,
        ushort confirmationCounter,
        byte[] sdUniqueData,
        byte[] tokenDataDigest)
    {
        _receipt = (byte[])receipt.Clone();
        ConfirmationCounter = confirmationCounter;
        _sdUniqueData = (byte[])sdUniqueData.Clone();
        _tokenDataDigest = (byte[])tokenDataDigest.Clone();
    }
}

/// <summary>
/// Helper class for managing CAP file loading operations.
/// </summary>
[PublicAPI]
public static class CapFileLoader
{
    /// <summary>
    /// Common error status words for CAP file loading.
    /// </summary>
    public static class ErrorCodes
    {
        /// <summary>
        /// Incorrect data (e.g., wrong AID, TLV malformed).
        /// </summary>
        public const ushort INCORRECT_DATA = 0x6A80;

        /// <summary>
        /// Memory error.
        /// </summary>
        public const ushort MEMORY_ERROR = 0x6A84;

        /// <summary>
        /// Conditions not satisfied (e.g., missing INSTALL [for load]).
        /// </summary>
        public const ushort CONDITIONS_NOT_SATISFIED = 0x6985;

        /// <summary>
        /// Generic failure (possibly applet exception during install).
        /// </summary>
        public const ushort GENERIC_FAILURE = 0x6F00;

        /// <summary>
        /// Success.
        /// </summary>
        public const ushort SUCCESS = 0x9000;
    }

    /// <summary>
    /// Validates a CAP file before loading.
    /// </summary>
    /// <param name="capFileData">The CAP file data to validate.</param>
    /// <returns>True if the CAP file appears valid, false otherwise.</returns>
    public static bool ValidateCapFile(byte[] capFileData)
    {
        if (capFileData == null || capFileData.Length < 10)
        {
            return false;
        }

        // Try to parse the CAP file structure
        var capFileResult = CapFileStructure.Parse(capFileData);

        if (capFileResult.IsFailure)
        {
            return false;
        }

        return capFileResult.Match(
            capFile =>
                capFile.PackageAid.Length > 0
                && capFile.Components.Count > 0
                && capFile.TotalSize > 0,
            _ => false
        );
    }

    /// <summary>
    /// Gets a human-readable description of an error status word.
    /// </summary>
    /// <param name="statusWord">The status word.</param>
    /// <returns>The error description.</returns>
    public static string GetErrorDescription(ushort statusWord)
    {
        return statusWord switch
        {
            ErrorCodes.SUCCESS => "Success",
            ErrorCodes.INCORRECT_DATA => "Incorrect data (wrong AID or malformed TLV)",
            ErrorCodes.MEMORY_ERROR => "Memory error",
            ErrorCodes.CONDITIONS_NOT_SATISFIED
                => "Conditions not satisfied (missing INSTALL [for load])",
            ErrorCodes.GENERIC_FAILURE => "Generic failure (possibly applet exception)",
            _ => $"Unknown error: {statusWord:X4}",
        };
    }
}
