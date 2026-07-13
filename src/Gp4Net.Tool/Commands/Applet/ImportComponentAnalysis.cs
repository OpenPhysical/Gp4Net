using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;
using Gp4Net.Services;

namespace Gp4Net.Tool.Commands.Applet;

public sealed record ImportComponentAnalysis(IReadOnlyList<ImportedPackageInfo> Packages)
{
    public static Result<ImportComponentAnalysis, SmartCardError> Parse(
        CapFileStructure capFile,
        PackageRegistry packageRegistry
    )
    {
        var importComponent = capFile.Components.FirstOrDefault(c =>
            c.Tag == Constants.Constants.JavaCard.ComponentTags.IMPORT
        );
        if (importComponent == null)
        {
            return Result.Success<ImportComponentAnalysis, SmartCardError>(
                new ImportComponentAnalysis([])
            );
        }

        byte[] data = importComponent.Data;
        if (data.Length < 1)
        {
            return Result.Failure<ImportComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Import component body must contain package_count")
            );
        }

        int offset = 0;
        byte count = data[offset++];
        var packages = new List<ImportedPackageInfo>(count);

        for (byte token = 0; token < count; token++)
        {
            if (offset + 3 > data.Length)
            {
                return Result.Failure<ImportComponentAnalysis, SmartCardError>(
                    SmartCardError.InvalidData("Import package entry is truncated")
                );
            }

            byte minorVersion = data[offset++];
            byte majorVersion = data[offset++];
            byte aidLength = data[offset++];

            if (offset + aidLength > data.Length)
            {
                return Result.Failure<ImportComponentAnalysis, SmartCardError>(
                    SmartCardError.InvalidData("Import package AID is truncated")
                );
            }

            byte[] aid = CapAnalysisUtilities.Slice(data, offset, aidLength);
            offset += aidLength;
            string aidHex = Convert.ToHexString(aid);
            Maybe<PackageInfo> packageInfo = packageRegistry.TryResolveAid(aidHex, out var resolved)
                ? Maybe<PackageInfo>.From(resolved)
                : Maybe<PackageInfo>.None;

            packages.Add(
                new ImportedPackageInfo(
                    token,
                    aid,
                    majorVersion,
                    minorVersion,
                    packageInfo.Map(info => info.DisplayName),
                    packageInfo.Map(info => info.SdkVersion)
                )
            );
        }

        return offset == data.Length
            ? Result.Success<ImportComponentAnalysis, SmartCardError>(
                new ImportComponentAnalysis(packages)
            )
            : Result.Failure<ImportComponentAnalysis, SmartCardError>(
                SmartCardError.InvalidData("Import component has trailing bytes")
            );
    }
}

public sealed record ImportedPackageInfo(
    byte Token,
    byte[] Aid,
    byte MajorVersion,
    byte MinorVersion,
    Maybe<string> ResolvedName,
    Maybe<string> SdkVersion
)
{
    public byte[] Aid { get; } = (byte[])Aid.Clone();
    public string AidHex => Convert.ToHexString(Aid);
    public string Version => $"{MajorVersion}.{MinorVersion}";
}
