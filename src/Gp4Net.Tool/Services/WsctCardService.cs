using System;
using System.Collections.Generic;
using Gp4Net.Tool.Services.CardCommunication;
using JetBrains.Annotations;
using log4net;
using WSCT.ISO7816;
using WSCT.Wrapper;

namespace Gp4Net.Tool.Services
{
    /// <summary>
    /// WSCT-based implementation of the card service.
    /// </summary>
    [PublicAPI]
    public class WsctCardService : ICardService
    {
        private static readonly ILog Logger = LogManager.GetLogger(typeof(WsctCardService));

        private readonly IWsctFactory _wsctFactory;
        private readonly ICardContextWrapper _context;
        private ICardChannelWrapper? _channel;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the WsctCardService class.
        /// </summary>
        /// <param name="wsctFactory">Factory for creating WSCT objects.</param>
        public WsctCardService(IWsctFactory wsctFactory)
        {
            _wsctFactory = wsctFactory ?? throw new ArgumentNullException(nameof(wsctFactory));
            _context = _wsctFactory.CreateCardContext();
            
            var result = _context.Establish();
            if (result != ErrorCode.Success)
            {
                throw new InvalidOperationException($"Failed to establish card context: {result}");
            }
        }

        /// <summary>
        /// Initializes a new instance of the WsctCardService class with default factory.
        /// </summary>
        public WsctCardService() : this(new WsctFactory())
        {
        }

        /// <inheritdoc />
        public IReadOnlyList<string> GetReaders()
        {
            try
            {
                var result = _context.ListReaders("");
                if (result != ErrorCode.Success)
                {
                    Logger.Warn($"Failed to list readers: {result}");
                    return Array.Empty<string>();
                }
                
                var readers = _context.Readers;
                Logger.Debug($"Found {readers.Count} card readers");
                return readers;
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to list card readers", ex);
                return Array.Empty<string>();
            }
        }

        /// <inheritdoc />
        public bool Connect(string readerName)
        {
            if (string.IsNullOrEmpty(readerName))
                throw new ArgumentException("Reader name cannot be null or empty", nameof(readerName));

            try
            {
                Disconnect(); // Ensure clean state

                _channel = _context.CreateCardChannel(readerName);
                var result = _channel.Connect(ShareMode.Shared, Protocol.Any);
                if (result != ErrorCode.Success)
                {
                    _channel.Dispose();
                    _channel = null;
                    Logger.Error($"Failed to connect to reader {readerName}: {result}");
                    return false;
                }
                Logger.Info($"Connected to card in reader: {readerName}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to connect to reader {readerName}", ex);
                return false;
            }
        }

        /// <inheritdoc />
        public void Disconnect()
        {
            if (_channel != null)
            {
                try
                {
                    _channel.Disconnect(Disposition.UnpowerCard);
                    Logger.Debug("Disconnected from card");
                }
                catch (Exception ex)
                {
                    Logger.Warn("Error during card disconnect", ex);
                }
                finally
                {
                    _channel.Dispose();
                    _channel = null;
                }
            }
        }

        /// <inheritdoc />
        public bool IsConnected
        {
            get
            {
                if (_channel == null)
                    return false;
                
                try
                {
                    var state = _channel.GetStatus();
                    return state == State.Specific || state == State.Negotiable || state == State.Powered;
                }
                catch
                {
                    return false;
                }
            }
        }

        /// <inheritdoc />
        public byte[]? GetAtr()
        {
            if (!IsConnected)
                return null;

            try
            {
                var atrBuffer = new byte[256];
                var result = _channel!.GetAttrib(Attrib.AtrString, ref atrBuffer);
                if (result != ErrorCode.Success)
                {
                    throw new InvalidOperationException($"Failed to get ATR: {result}");
                }
                
                // Extract actual ATR length from buffer
                var atrLength = Array.IndexOf(atrBuffer, (byte)0);
                if (atrLength == -1) atrLength = atrBuffer.Length;
                var atr = new byte[atrLength];
                Array.Copy(atrBuffer, atr, atrLength);
                Logger.Debug($"Card ATR: {Convert.ToHexString(atr)}");
                return atr;
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to get card ATR", ex);
                return null;
            }
        }

        /// <inheritdoc />
        public CardResponse SendCommand(byte[] command)
        {
            if (command == null)
                throw new ArgumentNullException(nameof(command));

            if (!IsConnected)
                throw new InvalidOperationException("Card is not connected");

            try
            {
                Logger.Debug($"Sending APDU: {Convert.ToHexString(command)}");

                var apdu = _wsctFactory.CreateCommandApdu(command);
                var response = _wsctFactory.CreateResponseApdu();
                var result = _channel!.Transmit(apdu, response);

                if (result != ErrorCode.Success)
                {
                    throw new InvalidOperationException($"Transmit failed: {result}");
                }

                var responseApdu = response as ResponseAPDU;
                if (responseApdu == null)
                {
                    throw new InvalidOperationException("Invalid response type received");
                }
                
                var responseData = responseApdu.Udr ?? Array.Empty<byte>();
                var statusWord = responseApdu.StatusWord;

                Logger.Debug($"Received response: Data={Convert.ToHexString(responseData)}, SW={statusWord:X4}");

                return new CardResponse(responseData, statusWord);
            }
            catch (InvalidOperationException)
            {
                // Re-throw InvalidOperationException with original message for specific error cases
                throw;
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to send APDU command: {Convert.ToHexString(command)}", ex);
                throw new InvalidOperationException("Failed to communicate with card", ex);
            }
        }

        /// <inheritdoc />
        public bool EstablishSecureChannel(byte[] keySet, byte securityLevel)
        {
            // This is a placeholder implementation
            // In a real implementation, this would use the GP4Net library
            // to perform mutual authentication and establish a secure channel
            Logger.Warn("Secure channel establishment not yet implemented");
            return false;
        }

        /// <inheritdoc />
        public bool IsSecureChannelEstablished => false; // Placeholder

        /// <inheritdoc />
        public void Dispose()
        {
            if (!_disposed)
            {
                Disconnect();
                _context?.Dispose();
                _disposed = true;
            }
        }
    }
}