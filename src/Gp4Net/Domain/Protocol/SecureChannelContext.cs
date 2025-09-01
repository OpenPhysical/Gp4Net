using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using static Gp4Net.Cryptography.CryptoService;
using Gp4Net.Core.Functional;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Immutable record containing the context information needed for secure channel establishment.
/// Stores authentication data required for completing the authentication process.
/// Pure functional design with validation in factory method.
/// </summary>
/// <param name="HostChallenge">The host challenge used in INITIALIZE UPDATE (8 bytes).</param>
/// <param name="InitializeUpdateResponse">The INITIALIZE UPDATE response.</param>
/// <param name="SessionKeys">The derived session keys.</param>
/// <param name="ScpVersion">The protocol version.</param>
/// <param name="KeySet">The key set used for authentication.</param>
[PublicAPI]
public record SecureChannelContext(
    byte[] HostChallenge,
    InitializeUpdateResponse InitializeUpdateResponse,
    SessionKeys SessionKeys,
    ScpVersion ScpVersion,
    IKeySet KeySet
)
{
    /// <summary>
    /// Creates a SecureChannelContext with functional validation.
    /// </summary>
    /// <param name="hostChallenge">The host challenge (8 bytes).</param>
    /// <param name="initializeUpdateResponse">The INITIALIZE UPDATE response.</param>
    /// <param name="sessionKeys">The derived session keys.</param>
    /// <param name="scpVersion">The protocol version.</param>
    /// <param name="keySet">The key set used for authentication.</param>
    /// <returns>A result containing the context or an error.</returns>
    public static Result<SecureChannelContext, SmartCardError> Create(
        byte[] hostChallenge,
        InitializeUpdateResponse initializeUpdateResponse,
        SessionKeys sessionKeys,
        ScpVersion scpVersion,
        IKeySet keySet
    )
    {
        return ValidateHostChallenge(hostChallenge)
            .Bind(_ => ValidateInitializeUpdateResponse(initializeUpdateResponse))
            .Bind(_ => ValidateSessionKeys(sessionKeys))
            .Bind(_ => ValidateKeySet(keySet))
            .ToResult()
            .Map(_ => new SecureChannelContext(
                (byte[])hostChallenge.Clone(), // Defensive copy for immutability
                initializeUpdateResponse,
                sessionKeys,
                scpVersion,
                keySet
            ));
    }

    private static UnitResult<SmartCardError> ValidateHostChallenge(byte[] hostChallenge)
    {
        return Maybe<byte[]>
            .From(hostChallenge)
            .Match(
                challenge =>
                    challenge.Length == 8
                        ? UnitResult.Success<SmartCardError>()
                        : SmartCardError.InvalidArgument(
                            $"Host challenge must be 8 bytes, got {challenge.Length}"
                        ),
                () => SmartCardError.InvalidArgument("Host challenge cannot be null")
            );
    }

    private static UnitResult<SmartCardError> ValidateInitializeUpdateResponse(
        InitializeUpdateResponse response
    )
    {
        return Maybe<InitializeUpdateResponse>
            .From(response)
            .Match(
                _ => UnitResult.Success<SmartCardError>(),
                () => SmartCardError.InvalidArgument("Initialize update response cannot be null")
            );
    }

    private static UnitResult<SmartCardError> ValidateSessionKeys(SessionKeys sessionKeys)
    {
        return Maybe<SessionKeys>
            .From(sessionKeys)
            .Match(
                _ => UnitResult.Success<SmartCardError>(),
                () => SmartCardError.InvalidArgument("Session keys cannot be null")
            );
    }

    private static UnitResult<SmartCardError> ValidateKeySet(IKeySet keySet)
    {
        return Maybe<IKeySet>
            .From(keySet)
            .Match(
                _ => UnitResult.Success<SmartCardError>(),
                () => SmartCardError.InvalidArgument("Key set cannot be null")
            );
    }
}
