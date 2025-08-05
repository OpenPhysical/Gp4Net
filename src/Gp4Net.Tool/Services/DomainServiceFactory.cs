using System;
using Gp4Net.Core.ServiceLifetime;
using Gp4Net.Domain.Protocol;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Factory interface for creating domain services with proper pipeline context.
/// </summary>
[PublicAPI]
public interface IDomainServiceFactory
{
    /// <summary>
    /// Creates a smart card service for the given card service.
    /// </summary>
    /// <param name="cardService">The card service to use for communication.</param>
    /// <returns>A configured smart card service with proper pipeline context.</returns>
    ISmartCardService CreateSmartCardService(ICardService cardService);

    /// <summary>
    /// Creates a GlobalPlatform service for the given card service.
    /// </summary>
    /// <param name="cardService">The card service to use for communication.</param>
    /// <returns>A configured GlobalPlatform service with proper pipeline context.</returns>
    IGlobalPlatformService CreateGlobalPlatformService(ICardService cardService);
}

/// <summary>
/// Factory implementation that creates domain services with proper functional context.
/// Ensures proper pipeline configuration and context flow.
/// </summary>
[PublicAPI]
public class DomainServiceFactory : IDomainServiceFactory, ISingletonService
{
    private readonly ICommandPipeline _pipeline;
    private readonly IApduTransportFactory _transportFactory;
    private readonly ISecureChannelManager _secureChannelManager;
    private readonly ILogger<DomainServiceFactory> _logger;

    /// <summary>
    /// Initializes a new instance of the DomainServiceFactory.
    /// </summary>
    public DomainServiceFactory(
        ICommandPipeline pipeline,
        IApduTransportFactory transportFactory,
        ISecureChannelManager secureChannelManager,
        ILogger<DomainServiceFactory> logger = null)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        ArgumentNullException.ThrowIfNull(transportFactory);
        ArgumentNullException.ThrowIfNull(secureChannelManager);
        _pipeline = pipeline;
        _transportFactory = transportFactory;
        _secureChannelManager = secureChannelManager;
        _logger = logger;
    }

    /// <inheritdoc/>
    public ISmartCardService CreateSmartCardService(ICardService cardService)
    {
        ArgumentNullException.ThrowIfNull(cardService);

        _logger?.LogDebug("Creating SmartCardService for card service");

        // Create the channel adapter that bridges ICardService to ICardChannel
        var channel = new CardServiceChannelAdapter(cardService, TransportProtocol.T0);
            
        // Create the appropriate transport
        var transport = _transportFactory.CreateTransport(TransportProtocol.T0);
            
        // Build immutable domain context with all required dependencies
        var context = new Gp4Net.Pipeline.ImmutablePipelineContext()
            .With("CardChannel", channel)
            .With("ApduTransport", transport)
            .With("TransportProtocol", TransportProtocol.T0);

        // Create the smart card service with pipeline, context, and transport
        var logger = _logger != null 
            ? new LoggerWrapper<SmartCardService>(_logger) 
            : null;
                
        return new SmartCardService(_pipeline, context, transport, logger);
    }

    /// <inheritdoc/>
    public IGlobalPlatformService CreateGlobalPlatformService(ICardService cardService)
    {
        ArgumentNullException.ThrowIfNull(cardService);

        _logger?.LogDebug("Creating GlobalPlatformService for card service");

        // First create the smart card service with proper context
        var smartCardService = CreateSmartCardService(cardService);

        // Then wrap it with GlobalPlatform functionality
        ILogger<GlobalPlatformService> logger = _logger != null 
            ? new LoggerWrapper<GlobalPlatformService>(_logger) 
            : NullLogger<GlobalPlatformService>.Instance;

        return new GlobalPlatformService(
            smartCardService, 
            _secureChannelManager,
            logger);
    }
}

/// <summary>
/// Logger wrapper to adapt ILogger interfaces.
/// </summary>
internal class LoggerWrapper<T> : ILogger<T>
{
    private readonly ILogger _innerLogger;

    public LoggerWrapper(ILogger innerLogger)
    {
        _innerLogger = innerLogger;
    }

    public IDisposable BeginScope<TState>(TState state) where TState : notnull => _innerLogger.BeginScope(state);
    public bool IsEnabled(LogLevel logLevel) => _innerLogger.IsEnabled(logLevel);
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
    {
        _innerLogger.Log(logLevel, eventId, state, exception, formatter);
    }
}