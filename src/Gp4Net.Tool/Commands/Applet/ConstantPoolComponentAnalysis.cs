using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;
using Gp4Net.Services;

namespace Gp4Net.Tool.Commands.Applet;

public sealed record ConstantPoolComponentAnalysis(
    IReadOnlyList<ConstantPoolEntryInfo> Entries,
    ImportComponentAnalysis Imports,
    int ComponentBodySize
)
{
    public static Result<ConstantPoolComponentAnalysis, SmartCardError> Parse(
        CapFileStructure capFile,
        PackageCatalog packageRegistry
    )
    {
        var constantPoolComponent = capFile.Components.FirstOrDefault(c =>
            c.Tag == Constants.Constants.JavaCard.ComponentTags.CONSTANT_POOL
        );
        if (constantPoolComponent == null)
        {
            return Result.Failure<ConstantPoolComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Constant Pool component not found")
            );
        }

        var importsResult = ImportComponentAnalysis.Parse(capFile, packageRegistry);
        if (importsResult.IsFailure)
        {
            return Result.Failure<ConstantPoolComponentAnalysis, SmartCardError>(
                importsResult.Error
            );
        }

        byte[] data = constantPoolComponent.Data;
        if (data.Length < 2)
        {
            return Result.Failure<ConstantPoolComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Constant Pool component body must contain count")
            );
        }

        int offset = 0;
        ushort count = CapAnalysisUtilities.ReadU2(data, ref offset);
        var entries = new List<ConstantPoolEntryInfo>(count);

        for (ushort index = 0; index < count; index++)
        {
            int entryOffset = offset;
            if (offset >= data.Length)
            {
                return Result.Failure<ConstantPoolComponentAnalysis, SmartCardError>(
                    SmartCardError.InvalidData("Constant Pool entry tag is truncated")
                );
            }

            byte tag = data[offset++];
            var parseResult = tag switch
            {
                0x01 => ParseClassRef(data, entryOffset, index, tag, ref offset),
                0x02
                    => ParseMemberRef(
                        data,
                        entryOffset,
                        index,
                        tag,
                        ConstantPoolEntryKind.InstanceField,
                        1,
                        ref offset
                    ),
                0x03
                    => ParseMemberRef(
                        data,
                        entryOffset,
                        index,
                        tag,
                        ConstantPoolEntryKind.VirtualMethod,
                        1,
                        ref offset
                    ),
                0x04
                    => ParseMemberRef(
                        data,
                        entryOffset,
                        index,
                        tag,
                        ConstantPoolEntryKind.SuperMethod,
                        1,
                        ref offset
                    ),
                0x05
                    => ParseStaticRef(
                        data,
                        entryOffset,
                        index,
                        tag,
                        ConstantPoolEntryKind.StaticField,
                        ref offset
                    ),
                0x06
                    => ParseStaticRef(
                        data,
                        entryOffset,
                        index,
                        tag,
                        ConstantPoolEntryKind.StaticMethod,
                        ref offset
                    ),
                _
                    => Result.Failure<ConstantPoolEntryInfo, SmartCardError>(
                        SmartCardError.InvalidData($"Unknown Constant Pool tag 0x{tag:X2}")
                    ),
            };

            if (parseResult.IsFailure)
            {
                return Result.Failure<ConstantPoolComponentAnalysis, SmartCardError>(
                    parseResult.Error
                );
            }

            entries.Add(ResolveExternalPackage(parseResult.Value, importsResult.Value));
        }

        return offset == data.Length
            ? Result.Success<ConstantPoolComponentAnalysis, SmartCardError>(
                new ConstantPoolComponentAnalysis(entries, importsResult.Value, data.Length)
            )
            : Result.Failure<ConstantPoolComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Constant Pool component has trailing bytes")
            );
    }

    public Maybe<ConstantPoolEntryInfo> FindEntry(ushort index) =>
        index < Entries.Count
            ? Maybe<ConstantPoolEntryInfo>.From(Entries[index])
            : Maybe<ConstantPoolEntryInfo>.None;

    private static Result<ConstantPoolEntryInfo, SmartCardError> ParseClassRef(
        byte[] data,
        int entryOffset,
        ushort index,
        byte tag,
        ref int offset
    )
    {
        var available = CapAnalysisUtilities.RequireAvailable(
            data,
            offset,
            3,
            "Constant Pool class ref is truncated"
        );
        if (available.IsFailure)
        {
            return Result.Failure<ConstantPoolEntryInfo, SmartCardError>(available.Error);
        }

        ushort classRef = CapAnalysisUtilities.ReadU2(data, ref offset);
        offset++;
        var target = ConstantPoolTarget.FromClassRef(classRef);
        return Result.Success<ConstantPoolEntryInfo, SmartCardError>(
            CreateEntry(index, tag, ConstantPoolEntryKind.Class, target, data, entryOffset, offset)
        );
    }

    private static Result<ConstantPoolEntryInfo, SmartCardError> ParseMemberRef(
        byte[] data,
        int entryOffset,
        ushort index,
        byte tag,
        ConstantPoolEntryKind kind,
        int memberTokenSize,
        ref int offset
    )
    {
        var available = CapAnalysisUtilities.RequireAvailable(
            data,
            offset,
            2 + memberTokenSize,
            "Constant Pool member ref is truncated"
        );
        if (available.IsFailure)
        {
            return Result.Failure<ConstantPoolEntryInfo, SmartCardError>(available.Error);
        }

        ushort classRef = CapAnalysisUtilities.ReadU2(data, ref offset);
        ushort memberToken =
            memberTokenSize == 1 ? data[offset++] : CapAnalysisUtilities.ReadU2(data, ref offset);
        var target = ConstantPoolTarget.FromClassRef(classRef) with
        {
            MemberToken = Maybe<ushort>.From(memberToken),
        };
        return Result.Success<ConstantPoolEntryInfo, SmartCardError>(
            CreateEntry(index, tag, kind, target, data, entryOffset, offset)
        );
    }

    private static Result<ConstantPoolEntryInfo, SmartCardError> ParseStaticRef(
        byte[] data,
        int entryOffset,
        ushort index,
        byte tag,
        ConstantPoolEntryKind kind,
        ref int offset
    )
    {
        var available = CapAnalysisUtilities.RequireAvailable(
            data,
            offset,
            3,
            "Constant Pool static ref is truncated"
        );
        if (available.IsFailure)
        {
            return Result.Failure<ConstantPoolEntryInfo, SmartCardError>(available.Error);
        }

        byte first = data[offset++];
        if ((first & 0x80) != 0)
        {
            byte classToken = data[offset++];
            byte memberToken = data[offset++];
            var target = new ConstantPoolTarget(
                true,
                Maybe<ushort>.None,
                Maybe<byte>.From(first),
                Maybe<byte>.From(classToken),
                Maybe<ushort>.From(memberToken),
                Maybe<ImportedPackageInfo>.None
            );
            return Result.Success<ConstantPoolEntryInfo, SmartCardError>(
                CreateEntry(index, tag, kind, target, data, entryOffset, offset)
            );
        }

        ushort internalOffset = (ushort)(first << 8 | data[offset++]);
        byte paddingOrToken = data[offset++];
        var internalTarget = new ConstantPoolTarget(
            false,
            Maybe<ushort>.From(internalOffset),
            Maybe<byte>.None,
            Maybe<byte>.None,
            Maybe<ushort>.From(paddingOrToken),
            Maybe<ImportedPackageInfo>.None
        );
        return Result.Success<ConstantPoolEntryInfo, SmartCardError>(
            CreateEntry(index, tag, kind, internalTarget, data, entryOffset, offset)
        );
    }

    private static ConstantPoolEntryInfo CreateEntry(
        ushort index,
        byte tag,
        ConstantPoolEntryKind kind,
        ConstantPoolTarget target,
        byte[] data,
        int entryOffset,
        int endOffset
    ) =>
        new(
            index,
            tag,
            kind,
            target,
            entryOffset,
            CapAnalysisUtilities.Slice(data, entryOffset, endOffset - entryOffset)
        );

    private static ConstantPoolEntryInfo ResolveExternalPackage(
        ConstantPoolEntryInfo entry,
        ImportComponentAnalysis imports
    )
    {
        if (!entry.Target.IsExternal || !entry.Target.PackageToken.HasValue)
        {
            return entry;
        }

        byte token = (byte)(entry.Target.PackageToken.Value & 0x7F);
        var importedPackage = imports.Packages.FirstOrDefault(package => package.Token == token);
        if (importedPackage == null)
        {
            return entry;
        }

        return entry with
        {
            Target = entry.Target with
            {
                ImportedPackage = Maybe<ImportedPackageInfo>.From(importedPackage),
            },
        };
    }
}

public sealed record ConstantPoolEntryInfo(
    ushort Index,
    byte Tag,
    ConstantPoolEntryKind Kind,
    ConstantPoolTarget Target,
    int ComponentOffset,
    byte[] RawBytes
)
{
    public byte[] RawBytes { get; } = (byte[])RawBytes.Clone();
}

public sealed record ConstantPoolTarget(
    bool IsExternal,
    Maybe<ushort> InternalOffset,
    Maybe<byte> PackageToken,
    Maybe<byte> ClassToken,
    Maybe<ushort> MemberToken,
    Maybe<ImportedPackageInfo> ImportedPackage
)
{
    public static ConstantPoolTarget FromClassRef(ushort classRef)
    {
        bool isExternal = (classRef & 0x8000) != 0;
        return isExternal
            ? new ConstantPoolTarget(
                true,
                Maybe<ushort>.None,
                Maybe<byte>.From((byte)(classRef >> 8)),
                Maybe<byte>.From((byte)(classRef & 0xFF)),
                Maybe<ushort>.None,
                Maybe<ImportedPackageInfo>.None
            )
            : new ConstantPoolTarget(
                false,
                Maybe<ushort>.From(classRef),
                Maybe<byte>.None,
                Maybe<byte>.None,
                Maybe<ushort>.None,
                Maybe<ImportedPackageInfo>.None
            );
    }
}

public enum ConstantPoolEntryKind
{
    Class,
    InstanceField,
    VirtualMethod,
    SuperMethod,
    StaticField,
    StaticMethod,
}
