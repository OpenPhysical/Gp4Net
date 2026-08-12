using System;
using System.Collections.Generic;
using WSCT.Wrapper;
using WSCT.Wrapper.Desktop.Core;

namespace Gp4Net.Tool.Services.CardCommunication.Wsct;

/// <summary>
/// Owns the native WSCT context used to enumerate and connect card readers.
/// </summary>
public sealed class WsctCardContextWrapper : IDisposable
{
    private readonly CardContext context = new();
    private bool disposed;

    public IReadOnlyList<string> Readers =>
        context.Readers is IReadOnlyList<string> readers ? readers : [];

    public ErrorCode Establish() => context.Establish();

    public ErrorCode ListReaders(string groups) => context.ListReaders(groups);

    public WsctCardChannelWrapper CreateCardChannel(string readerName) =>
        new WsctCardChannelWrapper(context, readerName, ShareMode.Exclusive);

    public ErrorCode Release() => disposed ? ErrorCode.Success : context.Release();

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        _ = context.Release();
        disposed = true;
    }
}
