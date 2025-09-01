using System;
using System.Collections.Generic;

namespace Gp4Net.Tests.Domain.Commands.TestHelpers;

/// <summary>
/// Helper class to build TLV structures for testing.
/// </summary>
internal class TlvTestBuilder
{
    private readonly List<byte> _data = [];

    public void Add(int tag, byte[] value)
    {
        AddTag(tag);
        AddLength(value.Length);
        _data.AddRange(value);
    }

    public void Add(int tag, Action<TlvTestBuilder> constructedContent)
    {
        TlvTestBuilder subBuilder = new TlvTestBuilder();
        constructedContent(subBuilder);
        byte[] value = subBuilder.Build();
        Add(tag, value);
    }

    public byte[] Build()
    {
        return [.. _data];
    }

    private void AddTag(int tag)
    {
        switch (tag)
        {
            case <= 0xFF:
                _data.Add((byte)tag);
                break;
            case <= 0xFFFF:
                _data.Add((byte)(tag >> 8));
                _data.Add((byte)(tag & 0xFF));
                break;
            default:
                throw new NotSupportedException(
                    "Tags larger than 2 bytes not supported in this helper"
                );
        }
    }

    private void AddLength(int length)
    {
        switch (length)
        {
            case <= 127:
                _data.Add((byte)length);
                break;
            case <= 255:
                _data.Add(0x81);
                _data.Add((byte)length);
                break;
            default:
                throw new NotSupportedException(
                    "Lengths larger than 255 not supported in this helper"
                );
        }
    }
}
