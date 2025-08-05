// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Core;
using Gp4Net.Services;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Hybrid card service that supports both real smart cards and virtual card emulators.
/// Routes requests to the appropriate service based on reader type.
/// </summary>
[PublicAPI]
public class HybridCardService : ICardService
{
    private readonly ICardService _realCardService;
    private readonly VirtualCardServiceAdapter _virtualCardService;
    private readonly ILogger<HybridCardService> _logger;

    /// <summary>
    /// Initializes a new instance of the HybridCardService class.
    /// </summary>
    /// <param name="realCardService">The real card service for physical readers.</param>
    /// <param name="virtualCardService">The virtual card service adapter.</param>
    /// <param name="logger">The logger.</param>
    public HybridCardService(
        ICardService realCardService,
        VirtualCardServiceAdapter virtualCardService,
        ILogger<HybridCardService> logger)
    {
        _realCardService = realCardService ?? throw new ArgumentNullException(nameof(realCardService));
        _virtualCardService = virtualCardService ?? throw new ArgumentNullException(nameof(virtualCardService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public IReadOnlyList<string> GetReaders()
    {
        _logger.LogDebug("Getting readers from both real and virtual card services");
            
        try
        {
            var realReaders = _realCardService.GetReaders();
            // Virtual card service adapter doesn't have ListReaders directly
            // It provides a single virtual reader
            var virtualReaders = new[] { "Virtual Card Emulator" };
                
            var allReaders = new List<string>();
            allReaders.AddRange(realReaders);
            allReaders.AddRange(virtualReaders);
                
            _logger.LogDebug("Found {RealCount} real readers and {VirtualCount} virtual readers", 
                realReaders.Count, virtualReaders.Length);
                
            return allReaders.AsReadOnly();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting hybrid reader list");
            // Return empty list rather than throwing to prevent CLI crashes
            return Array.Empty<string>();
        }
    }

    /// <inheritdoc />
    public bool Connect(string readerName)
    {
        ArgumentException.ThrowIfNullOrEmpty(readerName);
            
        _logger.LogDebug("Connecting to reader: {ReaderName}", readerName);
            
        if (IsVirtualReader(readerName))
        {
            _logger.LogDebug("Routing to virtual card service");
            // For virtual cards, we need to connect to the underlying virtual card service
            // Since VirtualCardServiceAdapter implements ISmartCardService, not ICardService,
            // we'll need to handle this differently
            _logger.LogDebug("Virtual card connection requested but not fully implemented");
            return false; // TODO: Implement virtual card connection through adapter
        }
        else
        {
            _logger.LogDebug("Routing to real card service");
            return _realCardService.Connect(readerName);
        }
    }

    /// <inheritdoc />
    public void Disconnect()
    {
        _logger.LogDebug("Disconnecting from all card services");
            
        try
        {
            _realCardService.Disconnect();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error disconnecting from real card service");
        }
            
        // Virtual cards don't maintain persistent connections in the same way
        // The adapter handles connection lifecycle internally
    }

    /// <inheritdoc />
    public bool IsConnected => _realCardService.IsConnected; // Virtual connections are always "connected" when available

    /// <inheritdoc />
    public byte[] GetAtr()
    {
        _logger.LogDebug("Getting ATR from current connection");
            
        // For now, delegate to real card service
        // Virtual card ATR would need context about which virtual reader is active
        return _realCardService.GetAtr();
    }

    /// <inheritdoc />
    public CardResponse SendCommand(byte[] command)
    {
        ArgumentNullException.ThrowIfNull(command);
            
        _logger.LogDebug("Sending command with {Length} bytes", command.Length);
            
        // For now, delegate to real card service
        // Virtual card routing would need connection state tracking
        return _realCardService.SendCommand(command);
    }

    /// <inheritdoc />
    public CardResponse SendCommand(IApduCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);
            
        _logger.LogDebug("Sending APDU command: INS={Ins:X2}", command.Ins);
            
        // For now, delegate to real card service
        // Virtual card routing would need connection state tracking
        return _realCardService.SendCommand(command);
    }

    /// <inheritdoc />
    public bool EstablishSecureChannel(byte[] keySet, byte securityLevel)
    {
        ArgumentNullException.ThrowIfNull(keySet);
            
        _logger.LogDebug("Establishing secure channel with security level {SecurityLevel:X2}", securityLevel);
            
        // For now, delegate to real card service
        // Virtual card routing would need connection state tracking
        return _realCardService.EstablishSecureChannel(keySet, securityLevel);
    }

    /// <inheritdoc />
    public bool IsSecureChannelEstablished => _realCardService.IsSecureChannelEstablished;

    /// <summary>
    /// Determines if a reader name refers to a virtual card emulator.
    /// </summary>
    /// <param name="readerName">The reader name to check.</param>
    /// <returns>True if the reader is virtual, false otherwise.</returns>
    private static bool IsVirtualReader(string readerName)
    {
        if (string.IsNullOrEmpty(readerName))
            return false;
                
        var normalized = readerName.ToLowerInvariant();
        return normalized.Contains("virtual") || 
               normalized.Contains("emulator") || 
               normalized.Contains("simulator");
    }

    /// <inheritdoc />
    public void Dispose()
    {
        try
        {
            _realCardService?.Dispose();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error disposing real card service");
        }
            
        // VirtualCardServiceAdapter doesn't implement IDisposable
    }
}