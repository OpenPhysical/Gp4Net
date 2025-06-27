using System;
using System.Collections.Generic;
using System.Linq;
using WSCT.Core;
using WSCT.Wrapper;
using WSCT.Wrapper.Desktop.Core;

namespace Gp4Net.Tool.Services.CardCommunication
{
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
        public IReadOnlyList<string> Readers => _context.Readers?.ToList() ?? new List<string>();

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
            return new WsctCardChannelWrapper(_context, readerName);
        }

        /// <inheritdoc />
        public ErrorCode Release()
        {
            return _context.Release();
        }

        /// <inheritdoc />
        public void Dispose()
        {
            if (!_disposed)
            {
                try
                {
                    _context.Release();
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