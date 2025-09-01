using Gp4Net.Domain;
using Gp4Net.Services;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Immutable execution context with established secure channel.
/// Pure functional container for secure channel operations.
/// </summary>
[PublicAPI]
public sealed record SecureChannelExecutionContext(
    IGlobalPlatformService GlobalPlatformService,
    SecureChannelState SecureChannelState
);
