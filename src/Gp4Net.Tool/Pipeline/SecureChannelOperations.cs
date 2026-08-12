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
        ICardSessionCommands cardService,
        KeysetResolution keysetResolver,
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
                        request.ExplicitKeyVersion,
                        request.SecurityLevel,
                        cancellationToken
                    ),
                () =>
                    request.KeysetName.Match(
                        keysetName =>
                            EstablishWithKeysetAsync(
                                cardService,
                                keysetName,
                                request.ExplicitKeyVersion,
                                request.SecurityLevel,
                                cancellationToken
                            ),
                        () =>
                            EstablishWithDefaultKeysetAsync(
                                cardService,
                                request.ExplicitKeyVersion,
                                request.SecurityLevel,
                                cancellationToken
                            )
                    )
            )
            .Map(state => new SecureChannelExecutionContext(cardService, state));
    }

    /// <summary>
    /// Establishes secure channel with explicit keys.
    /// Uses protocol-agnostic RawKeyset to allow proper SCP negotiation.
    /// </summary>
    private static async Task<
        Result<SecureChannelState, SmartCardError>
    > EstablishWithExplicitKeysAsync(
        ICardSessionCommands cardService,
        ExplicitKeys keys,
        Maybe<byte> explicitKeyVersion,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken
    )
    {
        byte keyVersion = explicitKeyVersion.GetValueOrDefault(0x00);

        // Create protocol-agnostic keyset for proper negotiation
        var rawKeysetResult = RawKeyset.Create(
            keys.EncryptionKey,
            keys.MacKey,
            keys.DataEncryptionKey,
            keyVersion
        );

        if (rawKeysetResult.IsFailure)
        {
            return Result.Failure<SecureChannelState, SmartCardError>(
                SmartCardError.InvalidArgument($"Invalid key set: {rawKeysetResult.Error}")
            );
        }

        // Let ScpOperations negotiate the protocol based on card response
        var sessionResult = await ScpOperations.Establishment.EstablishAsync(
            cardService.SendCommandAsync,
            rawKeysetResult.Value,
            securityLevel,
            explicitKeyVersion,
            cancellationToken
        );

        return sessionResult.Map(session => session.State);
    }

    /// <summary>
    /// Establishes secure channel with named keyset.
    /// </summary>
    private static async Task<Result<SecureChannelState, SmartCardError>> EstablishWithKeysetAsync(
        ICardSessionCommands cardService,
        string keysetName,
        Maybe<byte> explicitKeyVersion,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken
    )
    {
        return await ResolveKeysetByName(keysetName, explicitKeyVersion.GetValueOrDefault(0x00))
            .Bind(rawKeyset =>
                ScpOperations.Establishment.EstablishAsync(
                    cardService.SendCommandAsync,
                    rawKeyset,
                    securityLevel,
                    explicitKeyVersion,
                    cancellationToken
                )
            )
            .Map(session => session.State);
    }

    /// <summary>
    /// Establishes secure channel with default keyset.
    /// </summary>
    private static Task<Result<SecureChannelState, SmartCardError>> EstablishWithDefaultKeysetAsync(
        ICardSessionCommands cardService,
        Maybe<byte> explicitKeyVersion,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken
    )
    {
        return EstablishWithKeysetAsync(
            cardService,
            "gp_test_keys",
            explicitKeyVersion,
            securityLevel,
            cancellationToken
        );
    }

    /// <summary>
    /// Resolves a keyset name to a protocol-agnostic keyset.
    /// Pure function that maps keyset names to raw key sets.
    /// The actual protocol will be negotiated during INITIALIZE UPDATE.
    /// </summary>
    private static Result<RawKeyset, SmartCardError> ResolveKeysetByName(
        string keysetName,
        byte keyVersion
    )
    {
        if (keysetName.Contains(':'))
        {
            string[] keys = keysetName.Split(':');
            if (keys.Length != 3)
                return SmartCardError.InvalidArgument("Explicit keyset must contain ENC:MAC:DEK.");
            return Result.Try(
                () =>
                    RawKeyset
                        .Create(
                            Convert.FromHexString(keys[0]),
                            Convert.FromHexString(keys[1]),
                            Convert.FromHexString(keys[2]),
                            keyVersion
                        )
                        .Value,
                _ => SmartCardError.InvalidArgument("Explicit keyset contains invalid hex keys.")
            );
        }

        return keysetName is "gp_test_keys" or "gp_test"
            ? GpTestKeys.CreateRawTestKeyset(keyVersion)
            : Result.Failure<RawKeyset, SmartCardError>(
                SmartCardError.InvalidArgument($"Unknown keyset: {keysetName}")
            );
    }
}
