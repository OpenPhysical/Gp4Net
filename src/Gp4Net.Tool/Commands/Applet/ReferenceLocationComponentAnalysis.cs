using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;

namespace Gp4Net.Tool.Commands.Applet;

public sealed record ReferenceLocationComponentAnalysis(
    IReadOnlyList<ReferenceLocationSiteInfo> Sites,
    int ByteIndexCount,
    int Byte2IndexCount,
    int ComponentBodySize
)
{
    public IReadOnlyList<ReferenceLocationGroupInfo> Groups =>
        Sites
            .GroupBy(site => site.ConstantPoolIndex)
            .Select(group => new ReferenceLocationGroupInfo(
                group.Key,
                group.First().ConstantPoolEntry,
                group.Count(),
                group.Count(site => site.OperandWidth == ReferenceOperandWidth.OneByte),
                group.Count(site => site.OperandWidth == ReferenceOperandWidth.TwoByte),
                [.. group.Select(site => site.MethodComponentOffset).OrderBy(offset => offset)]
            ))
            .OrderBy(group => group.ConstantPoolIndex)
            .ToList();

    public static Result<ReferenceLocationComponentAnalysis, SmartCardError> Parse(
        CapFileStructure capFile,
        ConstantPoolComponentAnalysis constantPool
    )
    {
        var referenceLocationComponent = capFile.Components.FirstOrDefault(c =>
            c.Tag == Constants.Constants.JavaCard.ComponentTags.REFERENCE_LOCATION
        );
        if (referenceLocationComponent == null)
        {
            return Result.Failure<ReferenceLocationComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Reference Location component not found")
            );
        }

        var methodComponent = capFile.Components.FirstOrDefault(c =>
            c.Tag == Constants.Constants.JavaCard.ComponentTags.METHOD
        );
        if (methodComponent == null)
        {
            return Result.Failure<ReferenceLocationComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Method component not found")
            );
        }

        byte[] data = referenceLocationComponent.Data;
        if (data.Length < 2)
        {
            return Result.Failure<ReferenceLocationComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData(
                    "Reference Location component body must contain byte_index_count"
                )
            );
        }

        int offset = 0;
        ushort byteIndexCount = CapAnalysisUtilities.ReadU2(data, ref offset);
        var sites = new List<ReferenceLocationSiteInfo>();

        var byteSitesResult = ParseSites(
            data,
            methodComponent.Data,
            constantPool,
            byteIndexCount,
            ReferenceOperandWidth.OneByte,
            ref offset
        );
        if (byteSitesResult.IsFailure)
        {
            return Result.Failure<ReferenceLocationComponentAnalysis, SmartCardError>(
                byteSitesResult.Error
            );
        }

        sites.AddRange(byteSitesResult.Value);

        if (offset + 2 > data.Length)
        {
            return Result.Failure<ReferenceLocationComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData(
                    "Reference Location component body must contain byte2_index_count"
                )
            );
        }

        ushort byte2IndexCount = CapAnalysisUtilities.ReadU2(data, ref offset);
        var byte2SitesResult = ParseSites(
            data,
            methodComponent.Data,
            constantPool,
            byte2IndexCount,
            ReferenceOperandWidth.TwoByte,
            ref offset
        );
        if (byte2SitesResult.IsFailure)
        {
            return Result.Failure<ReferenceLocationComponentAnalysis, SmartCardError>(
                byte2SitesResult.Error
            );
        }

        sites.AddRange(byte2SitesResult.Value);

        return offset == data.Length
            ? Result.Success<ReferenceLocationComponentAnalysis, SmartCardError>(
                new ReferenceLocationComponentAnalysis(
                    sites,
                    byteIndexCount,
                    byte2IndexCount,
                    data.Length
                )
            )
            : Result.Failure<ReferenceLocationComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Reference Location component has trailing bytes")
            );
    }

    private static Result<IReadOnlyList<ReferenceLocationSiteInfo>, SmartCardError> ParseSites(
        byte[] referenceLocationData,
        byte[] methodData,
        ConstantPoolComponentAnalysis constantPool,
        ushort count,
        ReferenceOperandWidth operandWidth,
        ref int offset
    )
    {
        var sites = new List<ReferenceLocationSiteInfo>();
        int methodOffset = 0;

        for (ushort ordinal = 0; ordinal < count; ordinal++)
        {
            if (offset >= referenceLocationData.Length)
            {
                return Result.Failure<IReadOnlyList<ReferenceLocationSiteInfo>, SmartCardError>(
                    SmartCardError.InvalidData("Reference Location delta list is truncated")
                );
            }

            byte delta = referenceLocationData[offset++];
            methodOffset += delta;
            if (delta == 0xFF)
            {
                continue;
            }

            int operandSize = operandWidth == ReferenceOperandWidth.OneByte ? 1 : 2;
            if (methodOffset + operandSize > methodData.Length)
            {
                return Result.Failure<IReadOnlyList<ReferenceLocationSiteInfo>, SmartCardError>(
                    SmartCardError.InvalidData(
                        $"Reference Location points outside Method component at 0x{methodOffset:X4}"
                    )
                );
            }

            ushort cpIndex =
                operandWidth == ReferenceOperandWidth.OneByte
                    ? methodData[methodOffset]
                    : (ushort)(methodData[methodOffset] << 8 | methodData[methodOffset + 1]);
            var cpEntry = constantPool.FindEntry(cpIndex);

            sites.Add(
                new ReferenceLocationSiteInfo(
                    ordinal,
                    operandWidth,
                    methodOffset,
                    delta,
                    cpIndex,
                    cpEntry
                )
            );
        }

        return Result.Success<IReadOnlyList<ReferenceLocationSiteInfo>, SmartCardError>(sites);
    }
}

public sealed record ReferenceLocationSiteInfo(
    ushort Ordinal,
    ReferenceOperandWidth OperandWidth,
    int MethodComponentOffset,
    byte Delta,
    ushort ConstantPoolIndex,
    Maybe<ConstantPoolEntryInfo> ConstantPoolEntry
);

public sealed record ReferenceLocationGroupInfo(
    ushort ConstantPoolIndex,
    Maybe<ConstantPoolEntryInfo> ConstantPoolEntry,
    int ReferenceCount,
    int OneByteReferenceCount,
    int TwoByteReferenceCount,
    IReadOnlyList<int> MethodComponentOffsets
);

public enum ReferenceOperandWidth
{
    OneByte,
    TwoByte,
}
