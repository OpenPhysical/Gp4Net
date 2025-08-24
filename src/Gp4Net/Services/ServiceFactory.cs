using System;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
using Gp4Net.Pipeline;
// using Gp4Net.Pipeline.Middleware; - removed with old pipeline
using Gp4Net.Transport;
using Microsoft.Extensions.Logging.Abstractions;
using static Gp4Net.Pipeline.CommandProcessing;
using Gp4Net.Core;

namespace Gp4Net.Services;

/// <summary>
/// Functional service factory that composes services using pure functions
/// and dependency composition rather than complex dependency injection.
/// Demonstrates the functional architecture approach with explicit dependencies.
/// 
/// Example usage:
/// <code>
/// IApduTransport transport = new T0ApduTransport();
/// ISecureChannelManager secureChannelManager = new SecureChannelManager();
/// 
/// Result&lt;ServiceConfiguration, SmartCardError&gt; configResult = ServiceFactory.CreateServiceConfiguration(
///     cardChannel, transport, secureChannelManager);
/// 
/// Result&lt;IPipelineContext, SmartCardError&gt; contextResult = configResult.Bind(config =&gt; 
///     Result.Success&lt;IPipelineContext, SmartCardError&gt;(config.CreateServiceContext()));
/// 
/// // Use services through functional pipeline - no side effects
/// </code>
/// </summary>
public static class ServiceFactory
{
    /// <summary>
    /// Creates a functional GlobalPlatform service with all required dependencies.
    /// Uses functional composition to wire up the service graph.
    /// </summary>
    /// <param name="cardService">The card service for smart card communication.</param>
    /// <param name="secureChannelManager">The secure channel manager for cryptographic operations.</param>
    /// <returns>A fully configured functional GlobalPlatform service.</returns>
    public static Result<IGlobalPlatformService, SmartCardError> CreateGlobalPlatformService(
        ISmartCardService cardService,
        ISecureChannelManager secureChannelManager)
    {
        // No null checks - nulls should be converted to Result<T> at the boundary
        return Result.Success<IGlobalPlatformService, SmartCardError>(
            new GlobalPlatformService(cardService, secureChannelManager, NullLogger<GlobalPlatformService>.Instance));
    }

    /// <summary>
    /// Creates a smart card service with functional pipeline composition.
    /// Demonstrates how to build services with explicit dependency management.
    /// </summary>
    /// <param name="channel">The card channel for communication.</param>
    /// <param name="transport">The APDU transport for card communication.</param>
    /// <returns>A configured smart card service with functional pipeline.</returns>
    public static Result<ISmartCardService, SmartCardError> CreateSmartCardService(
        ICardChannel channel,
        IApduTransport transport)
    {
        // No null checks - nulls should be converted to Result<T> at the boundary
        
        // Create a logger (can be NullLogger if not provided)
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<SmartCardService>.Instance;
        
        // Create command environment
        var environment = new CommandEnvironment(
            channel,
            transport,
            Maybe<SecureChannelState>.None,
            logger);
            
        // Create command processor
        var processor = CommandProcessors.CreatePipeline(enableLogging: true, enableSecureChannel: true);
        
        return Result.Success<ISmartCardService, SmartCardError>(
            new SmartCardService(environment, processor, logger));
    }

    // CreateCommandPipeline method removed - using functional composition instead

    /// <summary>
    /// Creates an immutable pipeline context for command execution.
    /// Demonstrates functional context creation with proper immutability.
    /// </summary>
    /// <returns>An immutable pipeline context.</returns>
    public static Result<IPipelineContext, SmartCardError> CreatePipelineContext()
    {
        return Result.Success<IPipelineContext, SmartCardError>(
            ImmutablePipelineContext.Empty);
    }

    /// <summary>
    /// Creates a complete service graph for GlobalPlatform operations.
    /// This is the main factory method that demonstrates functional composition
    /// of the entire service dependency graph.
    /// </summary>
    /// <param name="channel">The card channel for communication.</param>
    /// <param name="transport">The APDU transport for card communication.</param>
    /// <param name="secureChannelManager">The secure channel manager for cryptographic operations.</param>
    /// <returns>A complete service configuration or error.</returns>
    public static Result<ServiceConfiguration, SmartCardError> CreateServiceConfiguration(
        ICardChannel channel,
        IApduTransport transport,
        ISecureChannelManager secureChannelManager)
    {
        // Create the smart card service first
        return CreateSmartCardService(channel, transport)
            .Bind(cardService => 
                // Then create the GlobalPlatform service
                CreateGlobalPlatformService(cardService, secureChannelManager)
                    .Map(gpService => 
                        // Return the complete service configuration
                        new ServiceConfiguration(cardService, gpService)));
    }
}

/// <summary>
/// Immutable configuration containing all required services.
/// Demonstrates functional service composition with explicit dependencies.
/// </summary>
public record ServiceConfiguration(
    ISmartCardService CardService,
    IGlobalPlatformService GlobalPlatformService)
{
    /// <summary>
    /// Creates a service context for command execution with all required services.
    /// </summary>
    /// <returns>A result containing the pipeline context or error.</returns>
    public Result<IPipelineContext, SmartCardError> CreateServiceContext()
    {
        return ServiceFactory.CreatePipelineContext()
            .Map(context => context
                .With("CardService", CardService)
                .With("GlobalPlatformService", GlobalPlatformService));
    }
}

// ServiceConfigurationError class removed - using Gp4Net.Core.SmartCardError instead