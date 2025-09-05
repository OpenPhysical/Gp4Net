using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Pure functional operations for secure channel establishment.
/// Provides functional composition for secure channel pipeline.
/// </summary>
[PublicAPI]
public static class SecureChannelOperations
{
    /// <summary>
    /// Establishes secure channel from a functional request structure.
    /// Pure function that converts request to secure channel operations.
    /// </summary>
    /// <param name="request">The secure channel request.</param>
    /// <param name="cardService">The smart card service.</param>
    /// <param name="keysetResolver">The keyset resolver.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A secure channel execution context or error.</returns>
    public static async Task<
        Result<SecureChannelExecutionContext, SmartCardError>
    > EstablishFromRequestAsync(
        SecureChannelRequest request,
        ISmartCardService cardService,
        IKeysetResolver keysetResolver,
        CancellationToken cancellationToken
    )
    {
        // Use static GlobalPlatformService methods directly
        // Establish secure channel based on request type
        return await request
            .ExplicitKeys.Match(
                explicitKeys =>
                    EstablishWithExplicitKeysAsync(
                        cardService,
                        explicitKeys,
                        request.KeyVersion,
                        cancellationToken
                    ),
                () =>
                    request.KeysetName.Match(
                        keysetName =>
                            EstablishWithKeysetAsync(
                                cardService,
                                keysetName,
                                request.KeyVersion,
                                cancellationToken
                            ),
                        () =>
                            EstablishWithDefaultKeysetAsync(
                                cardService,
                                request.KeyVersion,
                                cancellationToken
                            )
                    )
            )
            .Map(state => new SecureChannelExecutionContext(
                cardService, 
                state));
    }

    /// <summary>
    /// Establishes secure channel with explicit keys.
    /// </summary>
    private static async Task<Result<SecureChannelState, SmartCardError>> EstablishWithExplicitKeysAsync(
        ISmartCardService cardService,
        ExplicitKeys keys,
        byte keyVersion,
        CancellationToken cancellationToken
    )
    {
        // Create a key set from explicit keys
        var keySetResult = Scp03KeySet.Create(
            keys.EncryptionKey,
            keys.MacKey,
            keys.DataEncryptionKey,
            keyVersion);
        
        if (keySetResult.IsFailure)
        {
            return Result.Failure<SecureChannelState, SmartCardError>(
                SmartCardError.InvalidArgument($"Invalid key set: {keySetResult.Error}"));
        }
        
        // Use ScpService to establish secure channel
        var sessionResult = await ScpService.Establishment.EstablishAsync(
            cardService,
            keySetResult.Value,
            SecurityLevel.CMac,
            cancellationToken);
        
        return sessionResult.Map(session => session.State);
    }

    /// <summary>
    /// Establishes secure channel with named keyset.
    /// </summary>
    private static async Task<Result<SecureChannelState, SmartCardError>> EstablishWithKeysetAsync(
        ISmartCardService cardService,
        string keysetName,
        byte keyVersion,
        CancellationToken cancellationToken
    )
    {
        return await ResolveKeysetByName(keysetName, keyVersion)
            .Bind(keySet => ScpService.Establishment.EstablishAsync(
                cardService,
                keySet,
                SecurityLevel.CMac,
                cancellationToken))
            .Map(session => session.State);
    }

    /// <summary>
    /// Establishes secure channel with default keyset.
    /// </summary>
    private static Task<Result<SecureChannelState, SmartCardError>> EstablishWithDefaultKeysetAsync(
        ISmartCardService cardService,
        byte keyVersion,
        CancellationToken cancellationToken
    )
    {
        return EstablishWithKeysetAsync(
            cardService,
            "gp_test_keys",
            keyVersion,
            cancellationToken);
    }
    
    /// <summary>
    /// Resolves a keyset name to a concrete keyset implementation.
    /// Pure function that maps keyset names to key sets.
    /// </summary>
    private static Result<IKeySet, SmartCardError> ResolveKeysetByName(string keysetName, byte keyVersion)
    {
        return keysetName switch
        {
            "gp_test_keys" or "default" => 
                Scp03KeySet.Create(
                    GpTestKeys.GpTestKey,
                    GpTestKeys.GpTestKey,
                    GpTestKeys.GpTestKey,
                    keyVersion)
                .MapError(error => SmartCardError.InvalidArgument($"Invalid key set: {error}"))
                .Map(keySet => (IKeySet)keySet),
            _ => Result.Failure<IKeySet, SmartCardError>(
                SmartCardError.InvalidArgument($"Unknown keyset: {keysetName}"))
        };
    }
}
