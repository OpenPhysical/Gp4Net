// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Adapter that allows virtual card services to be used as smart card services in the CLI.
/// Provides seamless integration between the card emulator and CLI tools.
/// </summary>
[PublicAPI]
public class VirtualCardServiceAdapter : ISmartCardService
{
    private readonly VirtualCardService _virtualCardService;
    private readonly ILogger<VirtualCardServiceAdapter> _logger;
    private IPipelineContext _context;
    private bool _disposed;

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
        _context = ImmutablePipelineContext.Empty;
    }

    /// <inheritdoc />
    public IPipelineContext Context
    {
        get
        {
            return _context;
        }
    }

    /// <inheritdoc />
    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        IApduCommand command,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteCommandAsync(command, CommandOptions.Default, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<Result<CommandResponse, SmartCardError>> ExecuteCommandAsync(
        IApduCommand command,
        CommandOptions options,
        CancellationToken cancellationToken = default)
    {
        if (_disposed)
        {
            return SmartCardError.CommunicationError("Service has been disposed");
        }

        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(options);

        _logger.LogDebug("Executing command on virtual card: {Ins:X2}", command.Ins);

        try
        {
            // Execute synchronously since VirtualCardService is synchronous
            var result = await Task.Run(() => 
            {
                var response = _virtualCardService.ProcessCommand(command);
                return Result.Success<CommandResponse, SmartCardError>(response);
            }, cancellationToken);

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to execute command on virtual card");
            return SmartCardError.CommunicationError($"Failed to execute command: {ex.Message}", ex);
        }
    }

    /// <inheritdoc />
    public Result<ISmartCardService, SmartCardError> WithContext(IPipelineContext context)
    {
        // No null check - context parameter should never be null per NO NULLS rule
        return Result.Success<ISmartCardService, SmartCardError>(new VirtualCardServiceAdapter(_virtualCardService, _logger)
        {
            _context = context
        });
    }

    /// <inheritdoc />
    public Result<ISmartCardService, SmartCardError> WithContextValue<T>(string key, T value)
    {
        // No null check - key parameter should never be null per NO NULLS rule
        var newContext = _context.With(key, value);
        return WithContext(newContext);
    }

    /// <summary>
    /// Gets the list of virtual readers available.
    /// </summary>
    /// <returns>The list of virtual reader names.</returns>
    public IReadOnlyList<string> GetVirtualReaders()
    {
        return _virtualCardService.GetReaders();
    }

    /// <summary>
    /// Connects to a virtual reader.
    /// </summary>
    /// <param name="readerName">The virtual reader name.</param>
    /// <returns>True if connection succeeded, false otherwise.</returns>
    public bool Connect(string readerName)
    {
        return _virtualCardService.Connect(readerName);
    }

    /// <summary>
    /// Disconnects from the virtual reader.
    /// </summary>
    public void Disconnect()
    {
        _virtualCardService.Disconnect();
    }

    /// <summary>
    /// Gets whether the virtual card service is connected.
    /// </summary>
    public bool IsConnected => _virtualCardService.IsConnected;

    /// <summary>
    /// Gets the ATR from the virtual card.
    /// </summary>
    /// <returns>The ATR bytes or null if not connected.</returns>
    public byte[] GetAtr()
    {
        return _virtualCardService.GetAtr();
    }

    /// <summary>
    /// Establishes a secure channel with the virtual card.
    /// </summary>
    /// <param name="keySet">The key set bytes.</param>
    /// <param name="securityLevel">The security level.</param>
    /// <returns>True if successful, false otherwise.</returns>
    public bool EstablishSecureChannel(byte[] keySet, byte securityLevel)
    {
        return _virtualCardService.EstablishSecureChannel(keySet, securityLevel);
    }

    /// <summary>
    /// Gets whether a secure channel is established.
    /// </summary>
    public bool IsSecureChannelEstablished => _virtualCardService.IsSecureChannelEstablished;

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _virtualCardService?.Disconnect();
        _logger.LogDebug("Virtual card service adapter disposed");
    }
}