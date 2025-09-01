using System.Collections.Generic;
using WSCT.Wrapper;
using WSCT.Wrapper.Desktop.Core;

namespace Gp4Net.Tool.Services.CardCommunication.Wsct;

/// <summary>
/// Concrete implementation of ICardContextWrapper using WSCT.
/// </summary>
public class WsctCardContextWrapper : ICardContextWrapper
{
    private readonly CardContext _context;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the WsctCardContextWrapper class.
    /// </summary>
    public WsctCardContextWrapper()
    {
        _context = new CardContext();
    }

    /// <inheritdoc />
    public IReadOnlyList<string> Readers
    {
        get { return _context.Readers ?? []; }
    }

    /// <inheritdoc />
    public ErrorCode Establish()
    {
        return _context.Establish();
    }

    /// <inheritdoc />
    public ErrorCode ListReaders(string groups)
    {
        return _context.ListReaders(groups);
    }

    /// <inheritdoc />
    public ICardChannelWrapper CreateCardChannel(string readerName)
    {
        return new WsctCardChannelWrapper(_context, readerName, ShareMode.Exclusive);
    }

    /// <inheritdoc />
    public ErrorCode Release()
    {
        if (!_disposed)
        {
            return _context.Release();
        }
        return ErrorCode.Success;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!_disposed)
        {
            try
            {
                _ = _context.Release();
            }
            catch
            {
                // Ignore errors during cleanup
            }
            _disposed = true;
        }
    }
}
