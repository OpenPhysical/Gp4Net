using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;

namespace Gp4Net.Tool.Commands.Applet;

public sealed record DescriptorComponentAnalysis(
    IReadOnlyList<DescriptorClassInfo> Classes,
    IReadOnlyList<DescriptorTypeInfo> TypeDescriptors,
    byte[] TypeDescriptorTail,
    int ComponentBodySize
)
{
    public byte[] TypeDescriptorTail { get; } = (byte[])TypeDescriptorTail.Clone();

    public static Result<DescriptorComponentAnalysis, SmartCardError> Parse(
        CapFileStructure capFile
    )
    {
        var descriptorComponent = capFile.Components.FirstOrDefault(c =>
            c.Tag == Constants.Constants.JavaCard.ComponentTags.DESCRIPTOR
        );
        if (descriptorComponent == null)
        {
            return Result.Failure<DescriptorComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Descriptor component not found")
            );
        }

        var methodComponentInfo = MethodComponentInfo.Parse(capFile);
        byte[] data = descriptorComponent.Data;
        if (data.Length < 1)
        {
            return Result.Failure<DescriptorComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Descriptor component body must contain class_count")
            );
        }

        int offset = 0;
        byte classCount = data[offset++];
        var classes = new List<DescriptorClassInfo>(classCount);

        for (byte i = 0; i < classCount; i++)
        {
            var classResult = ParseClass(data, methodComponentInfo, ref offset);
            if (classResult.IsFailure)
            {
                return Result.Failure<DescriptorComponentAnalysis, SmartCardError>(
                    classResult.Error
                );
            }

            classes.Add(classResult.Value);
        }

        if (offset + 2 > data.Length)
        {
            return Result.Failure<DescriptorComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Descriptor type descriptor count is truncated")
            );
        }

        ushort typeCount = CapAnalysisUtilities.ReadU2(data, ref offset);
        var types = new List<DescriptorTypeInfo>(typeCount);
        for (ushort i = 0; i < typeCount; i++)
        {
            if (offset + 2 > data.Length)
            {
                return Result.Failure<DescriptorComponentAnalysis, SmartCardError>(
                    SmartCardError.InvalidData("Descriptor type entry is truncated")
                );
            }

            int typeOffset = offset;
            ushort value = CapAnalysisUtilities.ReadU2(data, ref offset);
            types.Add(new DescriptorTypeInfo(i, typeOffset, value));
        }

        byte[] typeDescriptorTail = CapAnalysisUtilities.Slice(data, offset, data.Length - offset);
        return Result.Success<DescriptorComponentAnalysis, SmartCardError>(
            new DescriptorComponentAnalysis(classes, types, typeDescriptorTail, data.Length)
        );
    }

    public IReadOnlyDictionary<ushort, DescriptorClassInfo> ClassesByThisClassRef =>
        Classes.ToDictionary(classInfo => classInfo.ThisClassRef);

    private static Result<DescriptorClassInfo, SmartCardError> ParseClass(
        byte[] data,
        Maybe<MethodComponentInfo> methodComponentInfo,
        ref int offset
    )
    {
        int classOffset = offset;
        var available = CapAnalysisUtilities.RequireAvailable(
            data,
            offset,
            9,
            "Descriptor class entry is truncated"
        );
        if (available.IsFailure)
        {
            return Result.Failure<DescriptorClassInfo, SmartCardError>(available.Error);
        }

        byte token = data[offset++];
        byte accessFlags = data[offset++];
        ushort thisClassRef = CapAnalysisUtilities.ReadU2(data, ref offset);
        byte interfaceCount = data[offset++];
        ushort fieldCount = CapAnalysisUtilities.ReadU2(data, ref offset);
        ushort methodCount = CapAnalysisUtilities.ReadU2(data, ref offset);

        var interfaces = new List<ushort>(interfaceCount);
        for (int i = 0; i < interfaceCount; i++)
        {
            if (offset + 2 > data.Length)
            {
                return Result.Failure<DescriptorClassInfo, SmartCardError>(
                    SmartCardError.InvalidData("Descriptor interface ref is truncated")
                );
            }

            interfaces.Add(CapAnalysisUtilities.ReadU2(data, ref offset));
        }

        var fields = new List<DescriptorFieldInfo>(fieldCount);
        for (int i = 0; i < fieldCount; i++)
        {
            var fieldResult = ParseField(data, ref offset);
            if (fieldResult.IsFailure)
            {
                return Result.Failure<DescriptorClassInfo, SmartCardError>(fieldResult.Error);
            }

            fields.Add(fieldResult.Value);
        }

        var methods = new List<MethodDescriptorInfo>(methodCount);
        for (int i = 0; i < methodCount; i++)
        {
            var methodResult = ParseMethod(data, methodComponentInfo, ref offset);
            if (methodResult.IsFailure)
            {
                return Result.Failure<DescriptorClassInfo, SmartCardError>(methodResult.Error);
            }

            methods.Add(methodResult.Value);
        }

        return Result.Success<DescriptorClassInfo, SmartCardError>(
            new DescriptorClassInfo(
                token,
                accessFlags,
                thisClassRef,
                interfaces,
                fields,
                methods,
                classOffset
            )
        );
    }

    private static Result<DescriptorFieldInfo, SmartCardError> ParseField(
        byte[] data,
        ref int offset
    )
    {
        int fieldOffset = offset;
        var available = CapAnalysisUtilities.RequireAvailable(
            data,
            offset,
            7,
            "Descriptor field entry is truncated"
        );
        if (available.IsFailure)
        {
            return Result.Failure<DescriptorFieldInfo, SmartCardError>(available.Error);
        }

        byte token = data[offset++];
        byte accessFlags = data[offset++];
        byte firstRefByte = data[offset++];
        byte secondRefByte = data[offset++];
        byte thirdRefByte = data[offset++];
        ushort type = CapAnalysisUtilities.ReadU2(data, ref offset);
        bool isStatic = (accessFlags & 0x08) != 0;

        var reference = isStatic
            ? DescriptorFieldReference.FromStaticRef(firstRefByte, secondRefByte, thirdRefByte)
            : DescriptorFieldReference.FromInstanceRef(firstRefByte, secondRefByte, thirdRefByte);

        return Result.Success<DescriptorFieldInfo, SmartCardError>(
            new DescriptorFieldInfo(
                token,
                accessFlags,
                reference,
                type,
                DescriptorTypeReference.FromRaw(type),
                fieldOffset
            )
        );
    }

    private static Result<MethodDescriptorInfo, SmartCardError> ParseMethod(
        byte[] data,
        Maybe<MethodComponentInfo> methodComponentInfo,
        ref int offset
    )
    {
        int methodDescriptorOffset = offset;
        var available = CapAnalysisUtilities.RequireAvailable(
            data,
            offset,
            12,
            "Descriptor method entry is truncated"
        );
        if (available.IsFailure)
        {
            return Result.Failure<MethodDescriptorInfo, SmartCardError>(available.Error);
        }

        byte methodToken = data[offset++];
        byte methodAccessFlags = data[offset++];
        ushort methodOffset = CapAnalysisUtilities.ReadU2(data, ref offset);
        ushort typeOffset = CapAnalysisUtilities.ReadU2(data, ref offset);
        ushort bytecodeCount = CapAnalysisUtilities.ReadU2(data, ref offset);
        ushort exceptionHandlerCount = CapAnalysisUtilities.ReadU2(data, ref offset);
        ushort exceptionHandlerIndex = CapAnalysisUtilities.ReadU2(data, ref offset);
        var methodHeader = methodComponentInfo
            .Map(info => info.ParseMethodHeader(methodOffset))
            .GetValueOrDefault(Maybe<MethodHeaderInfo>.None);

        return Result.Success<MethodDescriptorInfo, SmartCardError>(
            new MethodDescriptorInfo(
                methodToken,
                methodAccessFlags,
                methodOffset,
                typeOffset,
                bytecodeCount,
                exceptionHandlerCount,
                exceptionHandlerIndex,
                methodHeader,
                methodDescriptorOffset
            )
        );
    }
}

public sealed record DescriptorClassInfo(
    byte Token,
    byte AccessFlags,
    ushort ThisClassRef,
    IReadOnlyList<ushort> Interfaces,
    IReadOnlyList<DescriptorFieldInfo> Fields,
    IReadOnlyList<MethodDescriptorInfo> Methods,
    int ComponentOffset
);

public sealed record DescriptorFieldInfo(
    byte Token,
    byte AccessFlags,
    DescriptorFieldReference Reference,
    ushort TypeRawValue,
    DescriptorTypeReference TypeReference,
    int ComponentOffset
);

public sealed record DescriptorFieldReference(
    bool IsStatic,
    bool IsExternal,
    Maybe<ushort> InternalClassRef,
    Maybe<ushort> StaticFieldImageOffset,
    Maybe<byte> PackageToken,
    Maybe<byte> ClassToken,
    Maybe<byte> MemberToken
)
{
    public static DescriptorFieldReference FromInstanceRef(byte first, byte second, byte token)
    {
        ushort classRef = (ushort)(first << 8 | second);
        bool isExternal = (classRef & 0x8000) != 0;
        return isExternal
            ? new DescriptorFieldReference(
                false,
                true,
                Maybe<ushort>.None,
                Maybe<ushort>.None,
                Maybe<byte>.From((byte)(classRef >> 8)),
                Maybe<byte>.From((byte)(classRef & 0xFF)),
                Maybe<byte>.From(token)
            )
            : new DescriptorFieldReference(
                false,
                false,
                Maybe<ushort>.From(classRef),
                Maybe<ushort>.None,
                Maybe<byte>.None,
                Maybe<byte>.None,
                Maybe<byte>.From(token)
            );
    }

    public static DescriptorFieldReference FromStaticRef(byte first, byte second, byte third)
    {
        bool isExternal = (first & 0x80) != 0;
        return isExternal
            ? new DescriptorFieldReference(
                true,
                true,
                Maybe<ushort>.None,
                Maybe<ushort>.None,
                Maybe<byte>.From(first),
                Maybe<byte>.From(second),
                Maybe<byte>.From(third)
            )
            : new DescriptorFieldReference(
                true,
                false,
                Maybe<ushort>.None,
                Maybe<ushort>.From((ushort)(second << 8 | third)),
                Maybe<byte>.None,
                Maybe<byte>.None,
                Maybe<byte>.None
            );
    }
}

public sealed record DescriptorTypeReference(
    bool IsPrimitive,
    Maybe<byte> PrimitiveType,
    Maybe<ushort> TypeDescriptorOffset
)
{
    public static DescriptorTypeReference FromRaw(ushort value)
    {
        return (value & 0x8000) != 0
            ? new DescriptorTypeReference(
                true,
                Maybe<byte>.From((byte)(value & 0x0F)),
                Maybe<ushort>.None
            )
            : new DescriptorTypeReference(
                false,
                Maybe<byte>.None,
                Maybe<ushort>.From((ushort)(value & 0x7FFF))
            );
    }
}

public sealed record DescriptorTypeInfo(ushort Index, int ComponentOffset, ushort RawValue);

public sealed record MethodDescriptorInfo(
    byte Token,
    byte AccessFlags,
    ushort MethodOffset,
    ushort TypeOffset,
    ushort BytecodeCount,
    ushort ExceptionHandlerCount,
    ushort ExceptionHandlerIndex,
    Maybe<MethodHeaderInfo> MethodHeader,
    int ComponentOffset
);

public sealed record MethodHeaderInfo(
    byte Flags,
    byte MaxStack,
    byte ArgumentCount,
    byte MaxLocals,
    bool IsExtended,
    bool IsAbstract
);

public sealed record MethodComponentInfo(byte[] Data, int FirstMethodOffset)
{
    public static Maybe<MethodComponentInfo> Parse(CapFileStructure capFile)
    {
        var methodComponent = capFile.Components.FirstOrDefault(c =>
            c.Tag == Constants.Constants.JavaCard.ComponentTags.METHOD
        );
        if (methodComponent == null || methodComponent.Data.Length < 1)
        {
            return Maybe<MethodComponentInfo>.None;
        }

        byte handlerCount = methodComponent.Data[0];
        int firstMethodOffset = 1 + handlerCount * 8;
        return firstMethodOffset <= methodComponent.Data.Length
            ? Maybe<MethodComponentInfo>.From(
                new MethodComponentInfo(methodComponent.Data, firstMethodOffset)
            )
            : Maybe<MethodComponentInfo>.None;
    }

    public Maybe<MethodHeaderInfo> ParseMethodHeader(ushort methodOffset)
    {
        int offset = methodOffset;
        if (offset < FirstMethodOffset)
        {
            return Maybe<MethodHeaderInfo>.None;
        }

        if (offset + 2 > Data.Length)
        {
            return Maybe<MethodHeaderInfo>.None;
        }

        byte first = Data[offset];
        byte flags = (byte)(first >> 4);
        bool isExtended = (flags & 0x8) != 0;
        bool isAbstract = (flags & 0x4) != 0;

        if (isExtended)
        {
            if (offset + 4 > Data.Length)
            {
                return Maybe<MethodHeaderInfo>.None;
            }

            return Maybe<MethodHeaderInfo>.From(
                new MethodHeaderInfo(
                    flags,
                    Data[offset + 1],
                    Data[offset + 2],
                    Data[offset + 3],
                    true,
                    isAbstract
                )
            );
        }

        byte second = Data[offset + 1];
        return Maybe<MethodHeaderInfo>.From(
            new MethodHeaderInfo(
                flags,
                (byte)(first & 0x0F),
                (byte)(second >> 4),
                (byte)(second & 0x0F),
                false,
                isAbstract
            )
        );
    }
}
