using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Services;

/// <summary>
/// Interface for managing secure channel lifecycle operations.
/// Provides functional secure channel establishment and state management.
/// </summary>
[PublicAPI]
public interface ISecureChannelManager
{
    /// <summary>
    /// Establishes a secure channel with the specified keyset and security level.
    /// </summary>
    /// <param name="keySet">The keyset to use for secure channel establishment.</param>
    /// <param name="securityLevel">The desired security level.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The established secure channel state or error.</returns>
    Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        IKeySet keySet,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Establishes a secure channel with the specified keyset name and security level.
    /// </summary>
    /// <param name="keysetName">The name of the keyset to resolve.</param>
    /// <param name="securityLevel">The desired security level.</param>
    /// <param name="keyVersion">The key version to use.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The established secure channel state or error.</returns>
    Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        string keysetName,
        SecurityLevel securityLevel,
        byte keyVersion = 0x01,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Gets the current secure channel state if one is active.
    /// </summary>
    /// <returns>The current secure channel state or None if no channel is active.</returns>
    Maybe<SecureChannelState> GetCurrentChannel();

    /// <summary>
    /// Closes the current secure channel if one is active.
    /// </summary>
    /// <returns>Success or error.</returns>
    UnitResult<SmartCardError> CloseChannel();
}
