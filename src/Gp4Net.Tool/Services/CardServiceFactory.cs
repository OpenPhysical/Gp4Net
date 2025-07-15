using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.Tool.Services.CardCommunication;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services
{
    /// <summary>
    /// Factory that selects the appropriate card service based on reader name.
    /// Supports both physical readers (via WSCT) and virtual readers (via Lua scripts).
    /// </summary>
    [PublicAPI]
    public class CardServiceFactory : ICardService
    {
        private readonly WsctCardService _wsctService;
        private readonly LuaVirtualCardService _luaService;
        private readonly JsonLuaCardService _jsonLuaService;
        private ICardService? _activeService;

        public CardServiceFactory(WsctCardService wsctService, LuaVirtualCardService luaService, JsonLuaCardService jsonLuaService)
        {
            _wsctService = wsctService ?? throw new ArgumentNullException(nameof(wsctService));
            _luaService = luaService ?? throw new ArgumentNullException(nameof(luaService));
            _jsonLuaService = jsonLuaService ?? throw new ArgumentNullException(nameof(jsonLuaService));
        }

        /// <inheritdoc />
        public IReadOnlyList<string> GetReaders()
        {
            // Combine readers from all services
            var allReaders = new List<string>();
            
            // Add physical readers
            allReaders.AddRange(_wsctService.GetReaders());
            
            // Add Lua virtual readers
            allReaders.AddRange(_luaService.GetReaders());
            
            // Don't add JSON virtual readers to the discovery list
            // JSON readers must be explicitly specified
            
            return allReaders.AsReadOnly();
        }

        /// <inheritdoc />
        public bool Connect(string readerName)
        {
            // Disconnect any existing connection
            Disconnect();

            // Select appropriate service based on reader name
            if (readerName.StartsWith("lua:"))
            {
                _activeService = _luaService;
            }
            else if (readerName.StartsWith("json:"))
            {
                _activeService = _jsonLuaService;
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
            _luaService?.Dispose();
            _jsonLuaService?.Dispose();
        }
    }
}