using System;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;

namespace Gp4Net.Tool.Commands.Applet;

internal static class CapAnalysisUtilities
{
    public static Maybe<CapComponent> FindComponent(CapFileStructure capFile, byte tag) =>
        Maybe<CapComponent>.From(
            capFile.Components.FirstOrDefault(component => component.Tag == tag)
        );

    public static ushort ReadU2(byte[] data, ref int offset)
    {
        ushort value = (ushort)(data[offset] << 8 | data[offset + 1]);
        offset += 2;
        return value;
    }

    public static byte[] Slice(byte[] data, int offset, int count)
    {
        byte[] value = new byte[count];
        Array.Copy(data, offset, value, 0, count);
        return value;
    }

    public static Result<bool, SmartCardError> RequireAvailable(
        byte[] data,
        int offset,
        int count,
        string message
    )
    {
        return offset >= 0 && count >= 0 && offset + count <= data.Length
            ? Result.Success<bool, SmartCardError>(true)
            : Result.Failure<bool, SmartCardError>(SmartCardError.InvalidData(message));
    }
}
