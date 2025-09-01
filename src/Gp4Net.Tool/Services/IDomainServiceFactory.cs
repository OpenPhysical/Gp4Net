using Gp4Net.Services;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Pure functional factory for domain services.
/// Eliminates imperative service creation patterns in commands.
/// </summary>
[PublicAPI]
public interface IDomainServiceFactory
{
    /// <summary>
    /// Creates a GlobalPlatform service from an existing smart card service.
    /// Pure function that returns configured service instance.
    /// </summary>
    /// <param name="cardService">The smart card service to wrap.</param>
    /// <returns>A configured GlobalPlatform service.</returns>
    IGlobalPlatformService CreateGlobalPlatformService(ISmartCardService cardService);
}
