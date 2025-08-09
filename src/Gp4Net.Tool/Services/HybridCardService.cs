// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
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
    private string _currentReaderName;

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
            // Get virtual readers from the virtual card service
            var virtualReaders = _virtualCardService.GetVirtualReaders();
                
            var allReaders = new List<string>();
            allReaders.AddRange(realReaders);
            allReaders.AddRange(virtualReaders);
                
            _logger.LogDebug("Found {RealCount} real readers and {VirtualCount} virtual readers", 
                realReaders.Count, virtualReaders.Count);
                
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
            var success = _virtualCardService.Connect(readerName);
            if (success)
            {
                _currentReaderName = readerName;
            }
            return success;
        }
        else
        {
            _logger.LogDebug("Routing to real card service");
            var success = _realCardService.Connect(readerName);
            if (success)
            {
                _currentReaderName = readerName;
            }
            return success;
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
            
        try
        {
            _virtualCardService.Disconnect();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error disconnecting from virtual card service");
        }
            
        _currentReaderName = null;
    }

    /// <inheritdoc />
    public bool IsConnected
    {
        get
        {
            return _realCardService.IsConnected || _virtualCardService.IsConnected;
        }
    }

    /// <inheritdoc />
    public byte[] GetAtr()
    {
        _logger.LogDebug("Getting ATR from current connection");
            
        if (!string.IsNullOrEmpty(_currentReaderName) && IsVirtualReader(_currentReaderName))
        {
            return _virtualCardService.GetAtr();
        }
        else
        {
            return _realCardService.GetAtr();
        }
    }

    /// <inheritdoc />
    public CardResponse SendCommand(byte[] command)
    {
        ArgumentNullException.ThrowIfNull(command);
            
        _logger.LogDebug("Sending command with {Length} bytes", command.Length);
            
        if (!string.IsNullOrEmpty(_currentReaderName) && IsVirtualReader(_currentReaderName))
        {
            // Convert byte array to basic APDU command for virtual card
            var apduCommand = CreateApduCommandFromBytes(command);
            var response = _virtualCardService.ExecuteCommandAsync(apduCommand).GetAwaiter().GetResult();
            if (response.IsSuccess)
            {
                var cmdResponse = response.Value;
                return new CardResponse(cmdResponse.Data, cmdResponse.StatusWord);
            }
            else
            {
                // Return error as failed card response
                return new CardResponse(Array.Empty<byte>(), 0x6F00); // General error
            }
        }
        else
        {
            return _realCardService.SendCommand(command);
        }
    }

    /// <inheritdoc />
    public CardResponse SendCommand(IApduCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);
            
        _logger.LogDebug("Sending APDU command: INS={Ins:X2}", command.Ins);
            
        if (!string.IsNullOrEmpty(_currentReaderName) && IsVirtualReader(_currentReaderName))
        {
            var response = _virtualCardService.ExecuteCommandAsync(command).GetAwaiter().GetResult();
            if (response.IsSuccess)
            {
                var cmdResponse = response.Value;
                return new CardResponse(cmdResponse.Data, cmdResponse.StatusWord);
            }
            else
            {
                // Return error as failed card response
                return new CardResponse(Array.Empty<byte>(), 0x6F00); // General error
            }
        }
        else
        {
            return _realCardService.SendCommand(command);
        }
    }

    /// <inheritdoc />
    public bool EstablishSecureChannel(byte[] keySet, byte securityLevel)
    {
        ArgumentNullException.ThrowIfNull(keySet);
            
        _logger.LogDebug("Establishing secure channel with security level {SecurityLevel:X2}", securityLevel);
            
        if (!string.IsNullOrEmpty(_currentReaderName) && IsVirtualReader(_currentReaderName))
        {
            // Virtual cards use their own secure channel logic
            return _virtualCardService.EstablishSecureChannel(keySet, securityLevel);
        }
        else
        {
            return _realCardService.EstablishSecureChannel(keySet, securityLevel);
        }
    }

    /// <inheritdoc />
    public bool IsSecureChannelEstablished
    {
        get
        {
            if (!string.IsNullOrEmpty(_currentReaderName) && IsVirtualReader(_currentReaderName))
            {
                return _virtualCardService.IsSecureChannelEstablished;
            }
            else
            {
                return _realCardService.IsSecureChannelEstablished;
            }
        }
    }

    /// <summary>
    /// Determines if a reader name refers to a virtual card emulator.
    /// </summary>
    /// <param name="readerName">The reader name to check.</param>
    /// <returns>True if the reader is virtual, false otherwise.</returns>
    private static bool IsVirtualReader(string readerName)
    {
        if (string.IsNullOrEmpty(readerName))
        {
            return false;
        }

        var normalized = readerName.ToLowerInvariant();
        return normalized.Contains("virtual") || 
               normalized.Contains("emulator") || 
               normalized.Contains("simulator");
    }

    /// <summary>
    /// Creates a basic APDU command from raw bytes.
    /// </summary>
    /// <param name="command">The command bytes.</param>
    /// <returns>A basic APDU command.</returns>
    private static IApduCommand CreateApduCommandFromBytes(byte[] command)
    {
        if (command.Length < 4)
        {
            throw new ArgumentException("Command must be at least 4 bytes (CLA INS P1 P2)");
        }

        var cla = command[0];
        var ins = command[1];
        var p1 = command[2];
        var p2 = command[3];

        byte[] data = null;
        int? expectedLength = null;

        if (command.Length > 4)
        {
            // Simple parsing - assumes standard case 1-4 APDU structure
            if (command.Length == 5)
            {
                // Case 2s: CLA INS P1 P2 Le
                expectedLength = command[4] == 0 ? 256 : command[4];
            }
            else if (command.Length > 5)
            {
                // Case 3s or 4s: CLA INS P1 P2 Lc Data [Le]
                var lc = command[4];
                if (command.Length >= 5 + lc)
                {
                    data = command.Skip(5).Take(lc).ToArray();
                    if (command.Length == 5 + lc + 1)
                    {
                        // Case 4s: has Le
                        var le = command[5 + lc];
                        expectedLength = le == 0 ? 256 : le;
                    }
                }
            }
        }

        return new BasicApduCommand(cla, ins, p1, p2, data, expectedLength);
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
            
        try
        {
            _virtualCardService?.Dispose();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error disposing virtual card service");
        }
    }
}

/// <summary>
/// Basic APDU command implementation for byte array conversion.
/// </summary>
internal class BasicApduCommand : IApduCommand
{
    public byte Cla { get; }
    public byte Ins { get; }
    public byte P1 { get; }
    public byte P2 { get; }
    public byte[] Data { get; }
    public Maybe<int> ExpectedResponseLength { get; }
    public bool IsExtendedLength => false;

    public BasicApduCommand(byte cla, byte ins, byte p1, byte p2, byte[] data, int? expectedResponseLength)
    {
        Cla = cla;
        Ins = ins;
        P1 = p1;
        P2 = p2;
        Data = data;
        ExpectedResponseLength = expectedResponseLength.HasValue 
            ? Maybe<int>.From(expectedResponseLength.Value) 
            : Maybe<int>.None;
    }
}