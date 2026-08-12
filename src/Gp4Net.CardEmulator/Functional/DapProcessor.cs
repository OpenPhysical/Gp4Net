// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Parses Data Authentication Pattern blocks from a GlobalPlatform Load File.
/// </summary>
[PublicAPI]
public static class DapProcessor
{
    /// <summary>
    /// Verifies DAP blocks when present.
    /// </summary>
    public static Result<bool, SmartCardError> VerifyDapSignature(byte[] loadFileData)
    {
        return ParseDapBlocks(loadFileData)
            .Bind(blocks =>
                blocks.IsEmpty
                    ? Result.Success<bool, SmartCardError>(true)
                    : MissingVerificationKey(blocks[0])
            );
    }

    /// <summary>
    /// GP Card Specification v2.3.1, Table 11-58: DAP Blocks are E2 BER-TLVs at
    /// the beginning of the Load File, each containing one 4F and one C3 object.
    /// </summary>
    public static Result<ImmutableArray<DapBlock>, SmartCardError> ParseDapBlocks(
        byte[] loadFileData
    )
    {
        if (loadFileData is null)
        {
            return Result.Failure<ImmutableArray<DapBlock>, SmartCardError>(
                SmartCardError.InvalidData("Load File data is required")
            );
        }

        var blocks = ImmutableArray.CreateBuilder<DapBlock>();
        int offset = 0;

        while (offset < loadFileData.Length && loadFileData[offset] == 0xE2)
        {
            var outer = ReadTlv(loadFileData, offset, 0xE2, 1, int.MaxValue, loadFileData.Length);
            if (outer.IsFailure)
            {
                return Result.Failure<ImmutableArray<DapBlock>, SmartCardError>(outer.Error);
            }

            var parsedBlock = ParseDapBlock(outer.Value.Value);
            if (parsedBlock.IsFailure)
            {
                return Result.Failure<ImmutableArray<DapBlock>, SmartCardError>(parsedBlock.Error);
            }

            blocks.Add(parsedBlock.Value);
            offset = outer.Value.NextOffset;
        }

        return Result.Success<ImmutableArray<DapBlock>, SmartCardError>(blocks.ToImmutable());
    }

    private static Result<DapBlock, SmartCardError> ParseDapBlock(byte[] value)
    {
        var aid = ReadTlv(value, 0, 0x4F, 5, 16, value.Length);
        if (aid.IsFailure)
        {
            return Result.Failure<DapBlock, SmartCardError>(aid.Error);
        }

        var signature = ReadTlv(value, aid.Value.NextOffset, 0xC3, 1, int.MaxValue, value.Length);
        if (signature.IsFailure)
        {
            return Result.Failure<DapBlock, SmartCardError>(signature.Error);
        }

        if (signature.Value.NextOffset != value.Length)
        {
            return Result.Failure<DapBlock, SmartCardError>(
                SmartCardError.InvalidData("DAP Block contains data after the C3 object")
            );
        }

        return Result.Success<DapBlock, SmartCardError>(
            new DapBlock(
                aid.Value.Value.ToImmutableArray(),
                signature.Value.Value.ToImmutableArray()
            )
        );
    }

    private static Result<Tlv, SmartCardError> ReadTlv(
        byte[] data,
        int offset,
        byte expectedTag,
        int minimumLength,
        int maximumLength,
        int limit
    )
    {
        if (offset >= limit || data[offset] != expectedTag)
        {
            return Result.Failure<Tlv, SmartCardError>(
                SmartCardError.InvalidData($"Expected DAP tag {expectedTag:X2}")
            );
        }

        var length = ReadBerLength(data, offset + 1, limit);
        if (length.IsFailure)
        {
            return Result.Failure<Tlv, SmartCardError>(length.Error);
        }

        int valueOffset = length.Value.ValueOffset;
        int valueLength = length.Value.Length;
        if (
            valueLength < minimumLength
            || valueLength > maximumLength
            || valueOffset > limit - valueLength
        )
        {
            return Result.Failure<Tlv, SmartCardError>(
                SmartCardError.InvalidData($"Invalid length for DAP tag {expectedTag:X2}")
            );
        }

        byte[] value = new byte[valueLength];
        Array.Copy(data, valueOffset, value, 0, valueLength);
        return Result.Success<Tlv, SmartCardError>(new Tlv(value, valueOffset + valueLength));
    }

    private static Result<BerLength, SmartCardError> ReadBerLength(
        byte[] data,
        int offset,
        int limit
    )
    {
        if (offset >= limit)
        {
            return Result.Failure<BerLength, SmartCardError>(
                SmartCardError.InvalidData("DAP TLV length is missing")
            );
        }

        byte first = data[offset];
        if ((first & 0x80) == 0)
        {
            return Result.Success<BerLength, SmartCardError>(new BerLength(first, offset + 1));
        }

        int lengthBytes = first & 0x7F;
        if (lengthBytes is 0 or > 4 || offset + lengthBytes >= limit)
        {
            return Result.Failure<BerLength, SmartCardError>(
                SmartCardError.InvalidData("Invalid DAP TLV BER length")
            );
        }

        int length = 0;
        for (int index = 0; index < lengthBytes; index++)
        {
            if (length > (int.MaxValue >> 8))
            {
                return Result.Failure<BerLength, SmartCardError>(
                    SmartCardError.InvalidData("DAP TLV length is too large")
                );
            }

            length = length << 8 | data[offset + 1 + index];
        }

        return Result.Success<BerLength, SmartCardError>(
            new BerLength(length, offset + 1 + lengthBytes)
        );
    }

    private static Result<bool, SmartCardError> MissingVerificationKey(DapBlock block)
    {
        return Result.Failure<bool, SmartCardError>(
            SmartCardError.SecurityStatusNotSatisfied(
                $"No DAP verification key is configured for Security Domain {Convert.ToHexString(block.SecurityDomainAid.AsSpan())}"
            )
        );
    }

    private readonly record struct Tlv(byte[] Value, int NextOffset);

    private readonly record struct BerLength(int Length, int ValueOffset);

    /// <summary>GP Card Specification v2.3.1, Table 11-58.</summary>
    public sealed record DapBlock(
        ImmutableArray<byte> SecurityDomainAid,
        ImmutableArray<byte> LoadFileDataBlockSignature
    );
}
