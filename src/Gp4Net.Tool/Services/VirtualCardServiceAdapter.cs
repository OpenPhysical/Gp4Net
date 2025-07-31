// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Core;
using Gp4Net.Services;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Tool.Services
{
    /// <summary>
    /// Adapter that allows virtual card services to be used as smart card services in the CLI.
    /// Provides seamless integration between the card emulator and CLI tools.
    /// </summary>
    [PublicAPI]
    public class VirtualCardServiceAdapter : ISmartCardService
    {
        private readonly VirtualCardService _virtualCardService;
        private readonly ILogger<VirtualCardServiceAdapter> _logger;

        /// <summary>
        /// Initializes a new instance of the VirtualCardServiceAdapter class.
        /// </summary>
        /// <param name="virtualCardService">The virtual card service to adapt.</param>
        /// <param name="logger">The logger.</param>
        public VirtualCardServiceAdapter(
            VirtualCardService virtualCardService,
            ILogger<VirtualCardServiceAdapter> logger)
        {
            ArgumentNullException.ThrowIfNull(virtualCardService);
            ArgumentNullException.ThrowIfNull(logger);
            
            _virtualCardService = virtualCardService;
            _logger = logger;
        }

        /// <inheritdoc />
        public Result<string[], SmartCardError> ListReaders()
        {
            _logger.LogDebug("Listing virtual card readers");
            
            // Virtual card service provides a single "emulated" reader
            return new[] { "Virtual Card Emulator" };
        }

        /// <inheritdoc />
        public Result<(ICardChannel, CardProtocol), SmartCardError> ConnectToCard(
            string readerName, 
            CardProtocol preferredProtocol = CardProtocol.Any)
        {
            _logger.LogDebug("Connecting to virtual card on reader: {ReaderName}", readerName);
            
            if (readerName != "Virtual Card Emulator")
            {
                return SmartCardError.CommunicationError($"Virtual reader '{readerName}' not found");
            }

            try
            {
                var channel = new VirtualCardChannel(_virtualCardService, _logger);
                var protocol = CardProtocol.T1; // Virtual cards use T=1 protocol
                
                _logger.LogDebug("Successfully connected to virtual card");
                return (channel, protocol);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to connect to virtual card");
                return SmartCardError.CommunicationError($"Failed to connect to virtual card: {ex.Message}", ex);
            }
        }

        /// <inheritdoc />
        public Result<CommandResponse[], SmartCardError> SendCommands(ICardChannel channel, params IApduCommand[] commands)
        {
            if (channel is not VirtualCardChannel virtualChannel)
            {
                return SmartCardError.InvalidArgument("Channel must be a VirtualCardChannel");
            }

            _logger.LogDebug("Sending {CommandCount} commands to virtual card", commands.Length);
            
            try
            {
                return virtualChannel.SendCommands(commands);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send commands to virtual card");
                return SmartCardError.CommunicationError($"Failed to send commands: {ex.Message}", ex);
            }
        }
    }

    /// <summary>
    /// Virtual card channel implementation that forwards commands to the virtual card service.
    /// </summary>
    internal class VirtualCardChannel : ICardChannel
    {
        private readonly VirtualCardService _virtualCardService;
        private readonly ILogger _logger;
        private bool _disposed;

        public VirtualCardChannel(VirtualCardService virtualCardService, ILogger logger)
        {
            _virtualCardService = virtualCardService ?? throw new ArgumentNullException(nameof(virtualCardService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public Result<CommandResponse[], SmartCardError> SendCommands(params IApduCommand[] commands)
        {
            if (_disposed)
            {
                return SmartCardError.CommunicationError("Card channel has been disposed");
            }

            try
            {
                var responses = new CommandResponse[commands.Length];
                
                for (int i = 0; i < commands.Length; i++)
                {
                    var response = _virtualCardService.ProcessCommand(commands[i]);
                    responses[i] = response;
                    
                    _logger.LogDebug("Command {Index}: {Command} -> SW={SW:X4}", 
                        i + 1, commands[i].GetType().Name, response.StatusWord);
                }

                return responses;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing commands in virtual card");
                return SmartCardError.CommunicationError($"Virtual card error: {ex.Message}", ex);
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _logger.LogDebug("Disposing virtual card channel");
                _disposed = true;
            }
        }
    }
}