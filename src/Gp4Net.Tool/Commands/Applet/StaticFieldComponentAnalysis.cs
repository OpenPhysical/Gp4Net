using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.Tool.Commands.Applet;

public sealed record StaticFieldComponentAnalysis
{
    public ushort ImageSize { get; }
    public ushort ReferenceCount { get; }
    public ushort ArrayInitCount { get; }
    public ushort DefaultValueCount { get; }
    public ushort NonDefaultValueCount { get; }
    public IReadOnlyList<StaticFieldArrayInitInfo> InitializedArrays { get; }
    public byte[] NonDefaultValues { get; }
    public int ComponentBodySize { get; }

    public int HeaderSize => 10;

    public int ParsedSize =>
        HeaderSize
        + InitializedArrays.Sum(array => 3 + array.Values.Length)
        + NonDefaultValues.Length;

    public int TrailingByteCount => Math.Max(0, ComponentBodySize - ParsedSize);

    private StaticFieldComponentAnalysis(
        ushort imageSize,
        ushort referenceCount,
        ushort arrayInitCount,
        ushort defaultValueCount,
        ushort nonDefaultValueCount,
        IReadOnlyList<StaticFieldArrayInitInfo> initializedArrays,
        byte[] nonDefaultValues,
        int componentBodySize
    )
    {
        ImageSize = imageSize;
        ReferenceCount = referenceCount;
        ArrayInitCount = arrayInitCount;
        DefaultValueCount = defaultValueCount;
        NonDefaultValueCount = nonDefaultValueCount;
        InitializedArrays = initializedArrays;
        NonDefaultValues = (byte[])nonDefaultValues.Clone();
        ComponentBodySize = componentBodySize;
    }

    public static Result<StaticFieldComponentAnalysis, SmartCardError> Parse(byte[] data)
    {
        if (data.Length < 10)
        {
            return Result.Failure<StaticFieldComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Static Field component body must be at least 10 bytes")
            );
        }

        int offset = 0;
        ushort imageSize = ReadU2(data, ref offset);
        ushort referenceCount = ReadU2(data, ref offset);
        ushort arrayInitCount = ReadU2(data, ref offset);

        var initializedArrays = new List<StaticFieldArrayInitInfo>(arrayInitCount);
        for (int i = 0; i < arrayInitCount; i++)
        {
            if (offset + 3 > data.Length)
            {
                return Result.Failure<StaticFieldComponentAnalysis, SmartCardError>(
                    SmartCardError.InvalidData("Static Field array_init_info is truncated")
                );
            }

            byte type = data[offset++];
            ushort count = ReadU2(data, ref offset);

            if (offset + count > data.Length)
            {
                return Result.Failure<StaticFieldComponentAnalysis, SmartCardError>(
                    SmartCardError.InvalidData("Static Field array_init_info values are truncated")
                );
            }

            byte[] values = data.Skip(offset).Take(count).ToArray();
            offset += count;
            initializedArrays.Add(new StaticFieldArrayInitInfo(type, values));
        }

        if (offset + 4 > data.Length)
        {
            return Result.Failure<StaticFieldComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Static Field value counts are truncated")
            );
        }

        ushort defaultValueCount = ReadU2(data, ref offset);
        ushort nonDefaultValueCount = ReadU2(data, ref offset);

        if (offset + nonDefaultValueCount > data.Length)
        {
            return Result.Failure<StaticFieldComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Static Field non-default values are truncated")
            );
        }

        byte[] nonDefaultValues = data.Skip(offset).Take(nonDefaultValueCount).ToArray();

        return Result.Success<StaticFieldComponentAnalysis, SmartCardError>(
            new StaticFieldComponentAnalysis(
                imageSize,
                referenceCount,
                arrayInitCount,
                defaultValueCount,
                nonDefaultValueCount,
                initializedArrays,
                nonDefaultValues,
                data.Length
            )
        );
    }

    private static ushort ReadU2(byte[] data, ref int offset)
    {
        ushort value = (ushort)(data[offset] << 8 | data[offset + 1]);
        offset += 2;
        return value;
    }
}

public sealed record StaticFieldArrayInitInfo(byte Type, byte[] Values)
{
    public byte[] Values { get; } = (byte[])Values.Clone();
}
