using System;
using System.Collections.Generic;
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
    public uint? TotalCapSize { get; }

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

        if (IsFirstBlock)
        {
            // First block includes TLV header: C4 <total_length> <data>
            data.Add(CAP_DATA_TAG);

            // Encode length (up to 3 bytes for length field)
            uint totalSize = TotalCapSize!.Value;
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
    private LoadCommand(byte blockNumber, byte[] data, bool isFinalBlock, uint? totalCapSize = null)
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

        uint? totalCapSize = blockNumber == 0 ? (uint)data.Length : null;

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
            uint? totalCapSize = blockNumber == 0 ? totalSize : null;

            commands.Add(new LoadCommand(blockNumber, blockData, isFinalBlock, totalCapSize));

            offset += blockSize;
            blockNumber++;
        }

        return Result.Success<IList<LoadCommand>, SmartCardError>(commands);
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
            ex => SmartCardError.InvalidData(
                $"Failed to convert CAP file to binary format: {ex.Message}"
            )
        );

        if (binaryDataResult.IsFailure)
        {
            return Result.Failure<IList<LoadCommand>, SmartCardError>(binaryDataResult.Error);
        }

        if (binaryDataResult.IsSuccess)
        {
            return CreateFromCapFile(binaryDataResult.Value, maxBlockSize);
        }

        return Result.Failure<IList<LoadCommand>, SmartCardError>(
            SmartCardError.InvalidData("Unexpected state in binary data conversion")
        );
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
        return ToCommandApdu().GetValueOrDefault(new CommandAPDU([]));
    }

    /// <inheritdoc />
    public byte[] ToBytes()
    {
        return ToCommandApdu().Map(cmd => cmd.ToBytes()).GetValueOrDefault([]);
    }
}

/// <summary>
/// Represents the response to a LOAD command.
/// </summary>
[PublicAPI]
public class LoadResponse
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
    /// Initializes a new instance of the LoadResponse class.
    /// </summary>
    /// <param name="data">The response data.</param>
    /// <param name="statusWord">The status word.</param>
    public LoadResponse(byte[] data, ushort statusWord)
    {
        Data = data != null ? (byte[])data.Clone() : [];
        StatusWord = statusWord;
        IsSuccessful = statusWord == 0x9000;
    }

    /// <summary>
    /// Parses a LOAD response.
    /// </summary>
    /// <param name="response">The response data (excluding status word).</param>
    /// <param name="statusWord">The status word from the response.</param>
    /// <returns>The parsed response.</returns>
    public static LoadResponse Parse(byte[] response, ushort statusWord)
    {
        return new LoadResponse(response ?? [], statusWord);
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

        if (capFileResult.IsSuccess)
        {
            var capFile = capFileResult.Value;
            
            // Basic validation checks
            return capFile.PackageAid.Length > 0
                && capFile.Components.Count > 0
                && capFile.TotalSize > 0;
        }

        return false;
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
            ErrorCodes.CONDITIONS_NOT_SATISFIED =>
                "Conditions not satisfied (missing INSTALL [for load])",
            ErrorCodes.GENERIC_FAILURE => "Generic failure (possibly applet exception)",
            _ => $"Unknown error: {statusWord:X4}",
        };
    }
}
