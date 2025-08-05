// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
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
    public IPipelineContext Context => _context;

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
    public ISmartCardService WithContext(IPipelineContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
            
        return new VirtualCardServiceAdapter(_virtualCardService, _logger)
        {
            _context = context
        };
    }

    /// <inheritdoc />
    public ISmartCardService WithContextValue<T>(string key, T value)
    {
        ArgumentNullException.ThrowIfNull(key);
            
        var newContext = _context.With(key, value);
        return WithContext(newContext);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _virtualCardService?.Disconnect();
        _logger.LogDebug("Virtual card service adapter disposed");
    }
}