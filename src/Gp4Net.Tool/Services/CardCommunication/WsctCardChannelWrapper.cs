using System;
using WSCT.Core;
using WSCT.Core.APDU;
using WSCT.Wrapper;
using WSCT.Wrapper.Desktop.Core;

namespace Gp4Net.Tool.Services.CardCommunication
{
    /// <summary>
    /// Concrete implementation of ICardChannelWrapper using WSCT.
    /// </summary>
    public class WsctCardChannelWrapper : ICardChannelWrapper
    {
        private readonly CardChannel _channel;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the WsctCardChannelWrapper class.
        /// </summary>
        /// <param name="context">The card context.</param>
        /// <param name="readerName">The reader name.</param>
        public WsctCardChannelWrapper(ICardContext context, string readerName)
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
            return _channel.Disconnect(disposition);
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
                    _channel.Disconnect(Disposition.UnpowerCard);
                }
                catch
                {
                    // Ignore errors during cleanup
                }
                _disposed = true;
            }
        }
    }
}