using System;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.Protocol;
using Gp4Net.Pipeline;
using Gp4Net.Pipeline.Middleware;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging.Abstractions;

namespace Gp4Net.Services;

/// <summary>
/// Functional service factory that composes services using pure functions
/// and dependency composition rather than complex dependency injection.
/// Demonstrates the functional architecture approach with explicit dependencies.
/// 
/// Example usage:
/// <code>
/// var transport = new T0ApduTransport();
/// var secureChannelManager = new SecureChannelManager();
/// 
/// var configResult = ServiceFactory.CreateServiceConfiguration(transport, secureChannelManager);
/// 
/// configResult.Match(
///     config => {
///         var context = config.CreateServiceContext();
///         // Use services through context...
///     },
///     error => Console.WriteLine($"Configuration failed: {error}")
/// );
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
    public static Result<IGlobalPlatformService, ServiceConfigurationError> CreateGlobalPlatformService(
        ISmartCardService cardService,
        ISecureChannelManager secureChannelManager)
    {
        if (cardService == null)
        {
            return Result.Failure<IGlobalPlatformService, ServiceConfigurationError>(
                ServiceConfigurationError.MissingDependency(nameof(cardService)));
        }

        if (secureChannelManager == null)
        {
            return Result.Failure<IGlobalPlatformService, ServiceConfigurationError>(
                ServiceConfigurationError.MissingDependency(nameof(secureChannelManager)));
        }

        return Result.Success<IGlobalPlatformService, ServiceConfigurationError>(
            new GlobalPlatformService(cardService, secureChannelManager, NullLogger<GlobalPlatformService>.Instance));
    }

    /// <summary>
    /// Creates a smart card service with functional pipeline composition.
    /// Demonstrates how to build services with explicit dependency management.
    /// </summary>
    /// <param name="transport">The APDU transport for card communication.</param>
    /// <returns>A configured smart card service with functional pipeline.</returns>
    public static Result<ISmartCardService, ServiceConfigurationError> CreateSmartCardService(
        IApduTransport transport)
    {
        if (transport == null)
        {
            return Result.Failure<ISmartCardService, ServiceConfigurationError>(
                ServiceConfigurationError.MissingDependency(nameof(transport)));
        }

        return CreateCommandPipeline(transport)
            .Bind(commandPipeline => CreatePipelineContext()
                .Map(context => (ISmartCardService)new SmartCardService(commandPipeline, context, transport)));
    }

    /// <summary>
    /// Creates a command pipeline with functional middleware composition.
    /// Uses builder pattern but with functional error handling.
    /// </summary>
    /// <param name="transport">The APDU transport for the terminal middleware.</param>
    /// <returns>A configured command pipeline or configuration error.</returns>
    public static Result<ICommandPipeline, ServiceConfigurationError> CreateCommandPipeline(IApduTransport transport)
    {
        try
        {
            // Create a basic pipeline with essential middleware
            var pipeline = CommandPipelineBuilder.Create()
                .Use(new TransportMiddleware(transport))  // Terminal middleware for actual transport
                .Build();

            return Result.Success<ICommandPipeline, ServiceConfigurationError>(pipeline);
        }
        catch (Exception ex)
        {
            return Result.Failure<ICommandPipeline, ServiceConfigurationError>(
                ServiceConfigurationError.ConfigurationFailure("Failed to create command pipeline", ex.Message));
        }
    }

    /// <summary>
    /// Creates an immutable pipeline context for command execution.
    /// Demonstrates functional context creation with proper immutability.
    /// </summary>
    /// <returns>An immutable pipeline context.</returns>
    public static Result<IPipelineContext, ServiceConfigurationError> CreatePipelineContext()
    {
        return Result.Success<IPipelineContext, ServiceConfigurationError>(
            ImmutablePipelineContext.Empty);
    }

    /// <summary>
    /// Creates a complete service graph for GlobalPlatform operations.
    /// This is the main factory method that demonstrates functional composition
    /// of the entire service dependency graph.
    /// </summary>
    /// <param name="transport">The APDU transport for card communication.</param>
    /// <param name="secureChannelManager">The secure channel manager for cryptographic operations.</param>
    /// <returns>A complete service configuration or error.</returns>
    public static Result<ServiceConfiguration, ServiceConfigurationError> CreateServiceConfiguration(
        IApduTransport transport,
        ISecureChannelManager secureChannelManager)
    {
        return CreateSmartCardService(transport)
            .Bind(cardService => 
                CreateGlobalPlatformService(cardService, secureChannelManager)
                    .Map(gpService => new ServiceConfiguration(cardService, gpService)));
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
    /// <returns>A pipeline context populated with service dependencies.</returns>
    public IPipelineContext CreateServiceContext()
    {
        return ServiceFactory.CreatePipelineContext()
            .Match(
                context => context
                    .With("CardService", CardService)
                    .With("GlobalPlatformService", GlobalPlatformService),
                error => throw new InvalidOperationException($"Failed to create service context: {error}"));
    }
}

/// <summary>
/// Represents errors that can occur during service configuration.
/// Uses functional error handling instead of exceptions.
/// </summary>
public record ServiceConfigurationError(string Message, string Details = null)
{
    public static ServiceConfigurationError MissingDependency(string dependencyName) =>
        new($"Missing required dependency: {dependencyName}");

    public static ServiceConfigurationError ConfigurationFailure(string reason, string details = null) =>
        new($"Service configuration failed: {reason}", details);

    public static ServiceConfigurationError InvalidConfiguration(string reason) =>
        new($"Invalid service configuration: {reason}");

    public override string ToString() => Details != null ? $"{Message} - {Details}" : Message;
}