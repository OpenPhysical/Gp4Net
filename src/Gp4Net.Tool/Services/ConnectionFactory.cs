// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Services;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Unified factory for creating card connections to both physical and virtual cards.
/// Consolidates VirtualCardConnectionService and PhysicalCardConnectionService into single entry point.
/// </summary>
/// <remarks>
/// This service provides a unified interface for card connections without fallback behavior.
/// Virtual card specifications must be in format "virtual:profile.json" where profile.json must exist.
/// Physical reader names are passed through to the physical card connection service.
/// All errors are explicit - no defaults or fallbacks are provided.
/// </remarks>
[PublicAPI]
public static class ConnectionFactory
{
    /// <summary>
    /// Creates a SmartCardService connection based on the connection specification.
    /// </summary>
    /// <param name="connectionSpec">
    /// Connection specification - either "virtual:profile.json" for virtual cards
    /// or a physical reader name for physical cards
    /// </param>
    /// <param name="logger">Logger for the SmartCardService</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>A SmartCardService connected to the specified card, or an error</returns>
    /// <remarks>
    /// Virtual card profiles must exist - no default cards are created.
    /// Physical readers must be available and accessible.
    /// This method provides a single entry point for all card connections.
    /// </remarks>
    public static Task<Result<ISmartCardService, SmartCardError>> CreateConnectionAsync(
        string connectionSpec,
        ILogger<SmartCardService> logger,
        CancellationToken cancellationToken = default
    )
    {
        return ValidateConnectionSpec(connectionSpec)
            .Bind(spec => DetermineConnectionType(spec)
                .Bind(connectionType => connectionType switch
                {
                    ConnectionType.Virtual => CreateVirtualConnection(spec, logger, cancellationToken),
                    ConnectionType.Physical => CreatePhysicalConnection(spec, logger, cancellationToken),
                    _ => Task.FromResult(Result.Failure<ISmartCardService, SmartCardError>(
                        SmartCardError.InvalidArgument($"Unknown connection type for: {spec}")
                    ))
                }));
    }

    /// <summary>
    /// Connection type enumeration for type-safe connection routing.
    /// </summary>
    private enum ConnectionType
    {
        Virtual,
        Physical
    }

    /// <summary>
    /// Validates the connection specification format.
    /// </summary>
    private static Result<string, SmartCardError> ValidateConnectionSpec(string connectionSpec)
    {
        return Maybe
            .From(connectionSpec)
            .Where(spec => !string.IsNullOrWhiteSpace(spec))
            .ToResult(SmartCardError.InvalidArgument("Connection specification is required"));
    }

    /// <summary>
    /// Determines the connection type from the specification.
    /// </summary>
    private static Result<ConnectionType, SmartCardError> DetermineConnectionType(string connectionSpec)
    {
        const string virtualPrefix = "virtual:";
        
        return connectionSpec.StartsWith(virtualPrefix, StringComparison.OrdinalIgnoreCase)
            ? Result.Success<ConnectionType, SmartCardError>(ConnectionType.Virtual)
            : Result.Success<ConnectionType, SmartCardError>(ConnectionType.Physical);
    }

    /// <summary>
    /// Creates a virtual card connection using VirtualCardConnectionService.
    /// </summary>
    private static Task<Result<ISmartCardService, SmartCardError>> CreateVirtualConnection(
        string virtualSpec,
        ILogger<SmartCardService> logger,
        CancellationToken cancellationToken
    )
    {
        return VirtualCardConnectionService.CreateServiceAsync(virtualSpec, logger, cancellationToken);
    }

    /// <summary>
    /// Creates a physical card connection using PhysicalCardConnectionService.
    /// </summary>
    private static Task<Result<ISmartCardService, SmartCardError>> CreatePhysicalConnection(
        string readerName,
        ILogger<SmartCardService> logger,
        CancellationToken cancellationToken
    )
    {
        return PhysicalCardConnectionService.CreateServiceAsync(readerName, logger, cancellationToken);
    }
}