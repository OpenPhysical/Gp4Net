using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.Tool.Services.CardCommunication;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services
{
    /// <summary>
    /// Simplified factory that selects between physical and virtual card services.
    /// </summary>
    [PublicAPI]
    public class SimpleCardServiceFactory : ICardService
    {
        private readonly WsctCardService _wsctService;
        private readonly SimpleJsonCardService _jsonService;
        private ICardService? _activeService;
        private TraceBasedCardService? _traceService;

        public SimpleCardServiceFactory(WsctCardService wsctService, SimpleJsonCardService jsonService)
        {
            _wsctService = wsctService ?? throw new ArgumentNullException(nameof(wsctService));
            _jsonService = jsonService ?? throw new ArgumentNullException(nameof(jsonService));
        }

        /// <inheritdoc />
        public IReadOnlyList<string> GetReaders()
        {
            // Combine readers from both services
            var allReaders = new List<string>();
            
            // Add physical readers
            allReaders.AddRange(_wsctService.GetReaders());
            
            // Add JSON virtual readers
            allReaders.AddRange(_jsonService.GetReaders());
            
            return allReaders.AsReadOnly();
        }

        /// <inheritdoc />
        public bool Connect(string readerName)
        {
            // Disconnect any existing connection
            Disconnect();

            // Select appropriate service based on reader name
            if (readerName.StartsWith("json:"))
            {
                _activeService = _jsonService;
            }
            else if (readerName.StartsWith("TraceBasedReader:"))
            {
                // Parse trace path and operations from reader name
                var (tracePath, operations) = TraceBasedCardServiceExtensions.ParseTraceReaderName(readerName);
                _traceService = new TraceBasedCardService(tracePath, operations);
                _activeService = _traceService;
            }
            else
            {
                _activeService = _wsctService;
            }

            return _activeService.Connect(readerName);
        }

        /// <inheritdoc />
        public void Disconnect()
        {
            _activeService?.Disconnect();
            _activeService = null;
            _traceService?.Dispose();
            _traceService = null;
        }

        /// <inheritdoc />
        public bool IsConnected => _activeService?.IsConnected ?? false;

        /// <inheritdoc />
        public byte[]? GetAtr()
        {
            return _activeService?.GetAtr();
        }

        /// <inheritdoc />
        public CardResponse SendCommand(byte[] command)
        {
            if (_activeService == null)
            {
                throw new InvalidOperationException("Not connected to any card reader");
            }

            return _activeService.SendCommand(command);
        }

        /// <inheritdoc />
        public CardResponse SendCommand(IApduCommand command)
        {
            if (_activeService == null)
            {
                throw new InvalidOperationException("Not connected to any card reader");
            }

            return _activeService.SendCommand(command);
        }

        /// <inheritdoc />
        public bool EstablishSecureChannel(byte[] keySet, byte securityLevel)
        {
            if (_activeService == null)
            {
                throw new InvalidOperationException("Not connected to any card reader");
            }

            return _activeService.EstablishSecureChannel(keySet, securityLevel);
        }

        /// <inheritdoc />
        public bool IsSecureChannelEstablished => _activeService?.IsSecureChannelEstablished ?? false;

        /// <inheritdoc />
        public void Dispose()
        {
            Disconnect();
            _wsctService?.Dispose();
            _jsonService?.Dispose();
        }
    }
}