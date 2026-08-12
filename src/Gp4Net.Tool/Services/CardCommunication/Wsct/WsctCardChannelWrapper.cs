using System;
using WSCT.Core.APDU;
using WSCT.Wrapper;
using WSCT.Wrapper.Desktop.Core;

namespace Gp4Net.Tool.Services.CardCommunication.Wsct;

/// <summary>
/// Concrete implementation of WsctCardChannelWrapper using WSCT.
/// </summary>
public class WsctCardChannelWrapper : IDisposable
{
    private readonly CardChannel _channel;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the WsctCardChannelWrapper class.
    /// </summary>
    /// <param name="context">The WSCT card context.</param>
    /// <param name="readerName">The reader name.</param>
    /// <param name="shareMode">The share mode.</param>
    public WsctCardChannelWrapper(CardContext context, string readerName, ShareMode shareMode)
    {
        _channel = new CardChannel(context, readerName);
    }

    /// <inheritdoc />
    public ErrorCode Connect(ShareMode shareMode, Protocol protocol)
    {
        return _channel.Connect(shareMode, protocol);
    }

    /// <inheritdoc />
    public ErrorCode Disconnect(Disposition disposition)
    {
        if (!_disposed)
        {
            return _channel.Disconnect(disposition);
        }
        return ErrorCode.Success;
    }

    /// <inheritdoc />
    public State GetStatus()
    {
        return _channel.GetStatus();
    }

    /// <inheritdoc />
    public ErrorCode GetAttrib(Attrib attrib, ref byte[] buffer)
    {
        return _channel.GetAttrib(attrib, ref buffer);
    }

    /// <inheritdoc />
    public ErrorCode Transmit(ICardCommand command, ICardResponse response)
    {
        return _channel.Transmit(command, response);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!_disposed)
        {
            try
            {
                _ = _channel.Disconnect(Disposition.UnpowerCard);
            }
            catch
            {
                // Ignore errors during cleanup
            }
            _disposed = true;
        }
    }
}
