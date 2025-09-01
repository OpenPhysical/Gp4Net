using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
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
        // Create GlobalPlatform service
        var globalPlatformService = new GlobalPlatformServiceInstance(
            cardService, 
            keysetResolver, 
            new Microsoft.Extensions.Logging.Abstractions.NullLogger<GlobalPlatformServiceInstance>()
        );

        // Establish secure channel based on request type
        return await request
            .ExplicitKeys.Match(
                explicitKeys =>
                    EstablishWithExplicitKeysAsync(
                        globalPlatformService,
                        explicitKeys,
                        request.KeyVersion,
                        cancellationToken
                    ),
                () =>
                    request.KeysetName.Match(
                        keysetName =>
                            EstablishWithKeysetAsync(
                                globalPlatformService,
                                keysetName,
                                request.KeyVersion,
                                cancellationToken
                            ),
                        () =>
                            EstablishWithDefaultKeysetAsync(
                                globalPlatformService,
                                request.KeyVersion,
                                cancellationToken
                            )
                    )
            )
            .Map(state => new SecureChannelExecutionContext(globalPlatformService, state));
    }

    /// <summary>
    /// Establishes secure channel with explicit keys.
    /// </summary>
    private static Task<Result<SecureChannelState, SmartCardError>> EstablishWithExplicitKeysAsync(
        IGlobalPlatformService service,
        ExplicitKeys keys,
        byte keyVersion,
        CancellationToken cancellationToken
    )
    {
        return service.EstablishSecureChannelAsync(
            Convert.ToHexString(keys.EncryptionKey),
            Convert.ToHexString(keys.MacKey),
            Convert.ToHexString(keys.DataEncryptionKey),
            keyVersion,
            cancellationToken: cancellationToken
        );
    }

    /// <summary>
    /// Establishes secure channel with named keyset.
    /// </summary>
    private static Task<Result<SecureChannelState, SmartCardError>> EstablishWithKeysetAsync(
        IGlobalPlatformService service,
        string keysetName,
        byte keyVersion,
        CancellationToken cancellationToken
    )
    {
        return service.EstablishSecureChannelAsync(
            keysetName,
            keyVersion: keyVersion,
            cancellationToken: cancellationToken
        );
    }

    /// <summary>
    /// Establishes secure channel with default keyset.
    /// </summary>
    private static Task<Result<SecureChannelState, SmartCardError>> EstablishWithDefaultKeysetAsync(
        IGlobalPlatformService service,
        byte keyVersion,
        CancellationToken cancellationToken
    )
    {
        return service.EstablishSecureChannelAsync(
            "gp_test_keys",
            keyVersion: keyVersion,
            cancellationToken: cancellationToken
        );
    }
}
