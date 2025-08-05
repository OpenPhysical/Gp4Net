using System;
using System.Collections.Generic;
using CSharpFunctionalExtensions;

namespace Gp4Net.Tests.Domain.Commands.TestHelpers;

/// <summary>
/// Helper class to build TLV structures for testing.
/// </summary>
internal class TlvTestBuilder
{
    private readonly List<byte> _data = new();

    public void Add(int tag, byte[] value)
    {
        AddTag(tag);
        AddLength(value.Length);
        _data.AddRange(value);
    }

    public void Add(int tag, Action<TlvTestBuilder> constructedContent)
    {
        var subBuilder = new TlvTestBuilder();
        constructedContent(subBuilder);
        var value = subBuilder.Build();
        Add(tag, value);
    }

    public byte[] Build()
    {
        return _data.ToArray();
    }

    private void AddTag(int tag)
    {
        if (tag <= 0xFF)
        {
            _data.Add((byte)tag);
        }
        else if (tag <= 0xFFFF)
        {
            _data.Add((byte)(tag >> 8));
            _data.Add((byte)(tag & 0xFF));
        }
        else
        {
            throw new NotSupportedException("Tags larger than 2 bytes not supported in this helper");
        }
    }

    private void AddLength(int length)
    {
        if (length <= 127)
        {
            _data.Add((byte)length);
        }
        else if (length <= 255)
        {
            _data.Add(0x81);
            _data.Add((byte)length);
        }
        else
        {
            throw new NotSupportedException("Lengths larger than 255 not supported in this helper");
        }
    }
}