using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;

namespace Gp4Net.Tool.Commands.Applet;

public sealed record ExportComponentAnalysis
{
    public IReadOnlyList<ExportedClassInfo> Classes { get; }
    public int ComponentBodySize { get; }
    public int StaticFieldCount => Classes.Sum(classInfo => classInfo.StaticFields.Count);
    public int StaticMethodCount => Classes.Sum(classInfo => classInfo.StaticMethods.Count);

    private ExportComponentAnalysis(IReadOnlyList<ExportedClassInfo> classes, int componentBodySize)
    {
        Classes = classes;
        ComponentBodySize = componentBodySize;
    }

    public static Result<ExportComponentAnalysis, SmartCardError> Parse(CapFileStructure capFile)
    {
        var exportComponent = capFile.Components.FirstOrDefault(c =>
            c.Tag == Constants.Constants.JavaCard.ComponentTags.EXPORT
        );
        if (exportComponent == null)
        {
            return Result.Failure<ExportComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Export component not found")
            );
        }

        var classDescriptors = DescriptorComponentAnalysis
            .Parse(capFile)
            .Map(analysis => analysis.ClassesByThisClassRef)
            .GetValueOrDefault(new Dictionary<ushort, DescriptorClassInfo>());
        byte[] data = exportComponent.Data;
        if (data.Length < 1)
        {
            return Result.Failure<ExportComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Export component body must contain class_count")
            );
        }

        int offset = 0;
        byte classCount = data[offset++];
        var classes = new List<ExportedClassInfo>(classCount);

        for (int classToken = 0; classToken < classCount; classToken++)
        {
            if (offset + 4 > data.Length)
            {
                return Result.Failure<ExportComponentAnalysis, SmartCardError>(
                    SmartCardError.InvalidData("Export class entry is truncated")
                );
            }

            ushort classOffset = ReadU2(data, ref offset);
            byte staticFieldCount = data[offset++];
            byte staticMethodCount = data[offset++];

            if (offset + staticFieldCount * 2 + staticMethodCount * 2 > data.Length)
            {
                return Result.Failure<ExportComponentAnalysis, SmartCardError>(
                    SmartCardError.InvalidData("Export class static member offsets are truncated")
                );
            }

            var staticFields = new List<ExportedStaticFieldInfo>(staticFieldCount);
            for (int fieldToken = 0; fieldToken < staticFieldCount; fieldToken++)
            {
                ushort fieldOffset = ReadU2(data, ref offset);
                staticFields.Add(new ExportedStaticFieldInfo((byte)fieldToken, fieldOffset));
            }

            var staticMethods = new List<ExportedStaticMethodInfo>(staticMethodCount);
            for (int methodToken = 0; methodToken < staticMethodCount; methodToken++)
            {
                ushort methodOffset = ReadU2(data, ref offset);
                var descriptor = classDescriptors
                    .GetValueOrDefault(classOffset)
                    ?.Methods.FirstOrDefault(method =>
                        method.Token == methodToken && method.MethodOffset == methodOffset
                    );

                staticMethods.Add(
                    new ExportedStaticMethodInfo(
                        (byte)methodToken,
                        methodOffset,
                        Maybe<MethodDescriptorInfo>.From(descriptor),
                        descriptor?.MethodHeader ?? Maybe<MethodHeaderInfo>.None
                    )
                );
            }

            classes.Add(
                new ExportedClassInfo(
                    (byte)classToken,
                    classOffset,
                    staticFields,
                    staticMethods,
                    Maybe<DescriptorClassInfo>.From(classDescriptors.GetValueOrDefault(classOffset))
                )
            );
        }

        return offset == data.Length
            ? Result.Success<ExportComponentAnalysis, SmartCardError>(
                new ExportComponentAnalysis(classes, data.Length)
            )
            : Result.Failure<ExportComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Export component has trailing bytes")
            );
    }

    private static ushort ReadU2(byte[] data, ref int offset)
    {
        ushort value = (ushort)(data[offset] << 8 | data[offset + 1]);
        offset += 2;
        return value;
    }
}

public sealed record ExportedClassInfo(
    byte Token,
    ushort ClassOffset,
    IReadOnlyList<ExportedStaticFieldInfo> StaticFields,
    IReadOnlyList<ExportedStaticMethodInfo> StaticMethods,
    Maybe<DescriptorClassInfo> Descriptor
);

public sealed record ExportedStaticFieldInfo(byte Token, ushort StaticFieldImageOffset);

public sealed record ExportedStaticMethodInfo(
    byte Token,
    ushort MethodOffset,
    Maybe<MethodDescriptorInfo> Descriptor,
    Maybe<MethodHeaderInfo> MethodHeader
);
