using CSharpFunctionalExtensions;
using Gp4Net.Services;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Factory for creating domain service instances.
/// Creates instance-based services for dependency injection scenarios.
/// </summary>
[PublicAPI]
public class DomainServiceFactory : IDomainServiceFactory
{
    private readonly IKeysetResolver _keysetResolver;
    private readonly Maybe<ILogger<GlobalPlatformServiceInstance>> _logger;

    public DomainServiceFactory(
        IKeysetResolver keysetResolver,
        Maybe<ILogger<GlobalPlatformServiceInstance>> logger
    )
    {
        _keysetResolver = keysetResolver;
        _logger = logger;
    }

    /// <summary>
    /// Creates a GlobalPlatform service instance from an existing smart card service.
    /// </summary>
    /// <param name="cardService">The smart card service to wrap.</param>
    /// <returns>A configured GlobalPlatform service instance.</returns>
    public IGlobalPlatformService CreateGlobalPlatformService(ISmartCardService cardService)
    {
        var logger = _logger.GetValueOrDefault(
            new Microsoft.Extensions.Logging.Abstractions.NullLogger<GlobalPlatformServiceInstance>()
        );
        return new GlobalPlatformServiceInstance(cardService, _keysetResolver, logger);
    }
}