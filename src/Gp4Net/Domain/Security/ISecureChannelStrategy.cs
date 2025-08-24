using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Strategy interface for secure channel establishment.
/// Supports both trace replay and live execution modes with different implementations.
/// </summary>
[PublicAPI]
public interface ISecureChannelStrategy
{
    /// <summary>
    /// Establishes a secure channel with the specified security level.
    /// Implementation varies based on execution mode (trace replay vs live execution).
    /// </summary>
    /// <param name="securityLevel">The desired security level for the secure channel.</param>
    /// <param name="environment">The command execution environment.</param>
    /// <returns>Result containing the established secure channel state or an error.</returns>
    Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannel(
        SecurityLevel securityLevel,
        CommandProcessing.CommandEnvironment environment);
}