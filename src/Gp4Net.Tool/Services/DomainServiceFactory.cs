using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core.ServiceLifetime;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using static Gp4Net.Pipeline.CommandProcessing;

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

    /// <summary>
    /// Creates a card content retriever for comprehensive card listing functionality.
    /// </summary>
    /// <param name="cardService">The card service to use for communication.</param>
    /// <returns>A configured card content retriever with auto-detection capabilities.</returns>
    CardContentRetriever CreateCardContentRetriever(ICardService cardService);
}

/// <summary>
/// Factory implementation that creates domain services with proper functional context.
/// Ensures proper functional composition and explicit dependencies.
/// </summary>
[PublicAPI]
public class DomainServiceFactory : IDomainServiceFactory, ISingletonService
{
    private readonly IApduTransportFactory _transportFactory;
    private readonly ISecureChannelManager _secureChannelManager;
    private readonly ILogger<DomainServiceFactory> _logger;

    /// <summary>
    /// Initializes a new instance of the DomainServiceFactory.
    /// </summary>
    public DomainServiceFactory(
        IApduTransportFactory transportFactory,
        ISecureChannelManager secureChannelManager,
        ILogger<DomainServiceFactory> logger)
    {
        ArgumentNullException.ThrowIfNull(transportFactory);
        ArgumentNullException.ThrowIfNull(secureChannelManager);
        ArgumentNullException.ThrowIfNull(logger);
        _transportFactory = transportFactory;
        _secureChannelManager = secureChannelManager;
        _logger = logger;
    }

    /// <inheritdoc/>
    public ISmartCardService CreateSmartCardService(ICardService cardService)
    {
        ArgumentNullException.ThrowIfNull(cardService);

        _logger.LogDebug("Creating SmartCardService for card service");

        // Create the channel adapter that bridges ICardService to ICardChannel
        var channel = new CardServiceChannelAdapter(cardService, TransportProtocol.T0);
            
        // Create the appropriate transport
        var transport = _transportFactory.CreateTransport(TransportProtocol.T0);
            
        // Create the command environment with all explicit dependencies
        var logger = new LoggerWrapper<SmartCardService>(_logger);
        
        // Create secure channel service with functional composition
        var commandProcessor = new Gp4Net.Domain.Security.CommandSecurityProcessorAdapter();
        var responseProcessor = new Gp4Net.Domain.Security.ResponseSecurityProcessorAdapter();
        var secureChannelService = new Gp4Net.Domain.Security.SecureChannelService(commandProcessor, responseProcessor);
        
        var environment = new CommandEnvironment(
            channel,
            transport,
            Maybe<SecureChannelState>.None,
            secureChannelService,
            logger);
            
        // Create the command processor pipeline using pure function composition
        var processor = CommandProcessors.CreatePipeline(
            enableLogging: true,
            enableSecureChannel: true);
                
        return new SmartCardService(environment, processor, logger);
    }

    /// <inheritdoc/>
    public IGlobalPlatformService CreateGlobalPlatformService(ICardService cardService)
    {
        ArgumentNullException.ThrowIfNull(cardService);

        _logger.LogDebug("Creating GlobalPlatformService for card service");

        // First create the smart card service with proper functional context
        var smartCardService = CreateSmartCardService(cardService);

        // Then wrap it with GlobalPlatform functionality
        var logger = new LoggerWrapper<GlobalPlatformService>(_logger);

        return new GlobalPlatformService(
            smartCardService, 
            _secureChannelManager,
            logger);
    }

    /// <inheritdoc/>
    public CardContentRetriever CreateCardContentRetriever(ICardService cardService)
    {
        ArgumentNullException.ThrowIfNull(cardService);

        _logger.LogDebug("Creating CardContentRetriever for card service");

        // Create smart card service with proper functional context
        var smartCardService = CreateSmartCardService(cardService);
        
        // Create GlobalPlatform service for secure channel operations
        var globalPlatformService = CreateGlobalPlatformService(cardService);

        // Create logger for the retriever
        var logger = new LoggerWrapper<CardContentRetriever>(_logger);

        return new CardContentRetriever(smartCardService, globalPlatformService, logger);
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