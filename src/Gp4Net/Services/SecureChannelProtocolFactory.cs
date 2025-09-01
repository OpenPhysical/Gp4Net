using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Services;

/// <summary>
/// Factory implementation for creating secure channel protocol operations.
/// Provides functional protocol operation builders for SCP02 and SCP03.
/// </summary>
[PublicAPI]
public sealed class SecureChannelProtocolFactory : ISecureChannelProtocolFactory
{
    /// <inheritdoc />
    public Result<
        Func<SecurityLevel, CancellationToken, Task<Result<SecureChannelState, SmartCardError>>>,
        SmartCardError
    > CreateEstablishmentFunction(IKeySet keySet)
    {
        return keySet switch
        {
            Scp02KeySet _ => Result.Success<
                Func<
                    SecurityLevel,
                    CancellationToken,
                    Task<Result<SecureChannelState, SmartCardError>>
                >,
                SmartCardError
            >(
                (securityLevel, cancellationToken) =>
                    EstablishScp02Channel(securityLevel, cancellationToken)
            ),
            Scp03KeySet _ => Result.Success<
                Func<
                    SecurityLevel,
                    CancellationToken,
                    Task<Result<SecureChannelState, SmartCardError>>
                >,
                SmartCardError
            >(
                (securityLevel, cancellationToken) =>
                    EstablishScp03Channel(securityLevel, cancellationToken)
            ),
            _ => Result.Failure<
                Func<
                    SecurityLevel,
                    CancellationToken,
                    Task<Result<SecureChannelState, SmartCardError>>
                >,
                SmartCardError
            >(SmartCardError.InvalidArgument($"Unsupported keyset type: {keySet.GetType().Name}")),
        };
    }

    /// <summary>
    /// Establishes an SCP02 secure channel with the specified security level.
    /// </summary>
    private static Task<Result<SecureChannelState, SmartCardError>> EstablishScp02Channel(
        SecurityLevel securityLevel,
        CancellationToken cancellationToken
    )
    {
        // Create mock session keys for testing - this should be replaced with actual key derivation
        return Task.FromResult(
            CreateMockSessionKeys()
                .Bind(sessionKeys =>
                    SecureChannelState.Create(
                        sessionKeys,
                        securityLevel,
                        CryptoService.ScpVersion.Scp02,
                        new byte[8], // SCP02 uses 8-byte MAC chaining
                        0x00 // Default implementation parameter
                    )
                )
        );
    }

    /// <summary>
    /// Establishes an SCP03 secure channel with the specified security level.
    /// </summary>
    private static Task<Result<SecureChannelState, SmartCardError>> EstablishScp03Channel(
        SecurityLevel securityLevel,
        CancellationToken cancellationToken
    )
    {
        // Create mock session keys for testing - this should be replaced with actual key derivation
        return Task.FromResult(
            CreateMockSessionKeys()
                .Bind(sessionKeys =>
                    SecureChannelState.Create(
                        sessionKeys,
                        securityLevel,
                        CryptoService.ScpVersion.Scp03,
                        new byte[16], // SCP03 uses 16-byte MAC chaining
                        0x00 // Default implementation parameter
                    )
                )
        );
    }

    /// <summary>
    /// Creates mock session keys for testing purposes.
    /// This should be replaced with actual key derivation logic.
    /// </summary>
    private static Result<SessionKeys, SmartCardError> CreateMockSessionKeys()
    {
        return SessionKeys.Create(
            new byte[16], // Mock ENC key
            new byte[16], // Mock MAC key
            new byte[16] // Mock DEK key
        );
    }
}
