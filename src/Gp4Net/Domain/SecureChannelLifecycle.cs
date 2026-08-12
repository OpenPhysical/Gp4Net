using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Org.BouncyCastle.Security;
using static Gp4Net.Cryptography.CryptoOperations;

namespace Gp4Net.Domain;

/// <summary>
/// Represents the lifecycle phases of a secure channel.
/// Follows GlobalPlatform specification state transitions.
/// </summary>
public enum SecureChannelPhase
{
    /// <summary>
    /// No secure channel initiated.
    /// </summary>
    NotInitiated,

    /// <summary>
    /// After INITIALIZE UPDATE command.
    /// </summary>
    Initiated,

    /// <summary>
    /// After successful EXTERNAL AUTHENTICATE command.
    /// </summary>
    Authenticated,

    /// <summary>
    /// After a security error occurred.
    /// </summary>
    Aborted,

    /// <summary>
    /// After explicit termination or session end.
    /// </summary>
    Terminated,
}

/// <summary>
/// Data captured during INITIALIZE UPDATE command.
/// </summary>
public record InitializeUpdateData(
    byte[] HostChallenge,
    byte[] CardChallenge,
    ushort SequenceCounter,
    byte[] CardCryptogram,
    ScpVersion ProtocolVersion
)
{
    /// <summary>
    /// Validates the initialize update data.
    /// </summary>
    public Result<InitializeUpdateData, SmartCardError> Validate()
    {
        return HostChallenge.Length == 8
            ? CardChallenge.Length == 6
                ? CardCryptogram.Length == 8
                    ? Result.Success<InitializeUpdateData, SmartCardError>(this)
                    : Result.Failure<InitializeUpdateData, SmartCardError>(
                        new InvalidLengthError("CardCryptogram", 8, CardCryptogram.Length)
                    )
                : Result.Failure<InitializeUpdateData, SmartCardError>(
                    new InvalidLengthError("CardChallenge", 6, CardChallenge.Length)
                )
            : Result.Failure<InitializeUpdateData, SmartCardError>(
                new InvalidLengthError("HostChallenge", 8, HostChallenge.Length)
            );
    }
}

/// <summary>
/// State after successful authentication.
/// </summary>
public record AuthenticatedState(
    SessionKeys Keys,
    SecurityLevel Level,
    byte[] InitialMacChaining,
    ScpImplementation Implementation
)
{
    /// <summary>
    /// Validates the authenticated state.
    /// </summary>
    public Result<AuthenticatedState, SmartCardError> Validate()
    {
        return Keys != null
            ? InitialMacChaining.Length == 8
                ? Result.Success<AuthenticatedState, SmartCardError>(this)
                : Result.Failure<AuthenticatedState, SmartCardError>(
                    new InvalidLengthError("InitialMacChaining", 8, InitialMacChaining.Length)
                )
            : Result.Failure<AuthenticatedState, SmartCardError>(
                new NullParameterError(nameof(Keys))
            );
    }
}

/// <summary>
/// Reason for secure channel termination.
/// </summary>
public record TerminationReason(string Reason, Maybe<ushort> StatusWord = default);

/// <summary>
/// Immutable representation of secure channel lifecycle state.
/// Tracks the complete state transitions per GlobalPlatform specification.
/// </summary>
public record SecureChannelLifecycle(
    SecureChannelPhase Phase,
    Maybe<InitializeUpdateData> InitData,
    Maybe<AuthenticatedState> AuthState,
    Maybe<TerminationReason> TerminationInfo
)
{
    /// <summary>
    /// Creates an initial state with no secure channel.
    /// </summary>
    public static SecureChannelLifecycle NotInitiated =>
        new(SecureChannelPhase.NotInitiated, Maybe.None, Maybe.None, Maybe.None);

    /// <summary>
    /// Checks if the secure channel is in a usable state for secure messaging.
    /// </summary>
    public bool IsAuthenticated => Phase == SecureChannelPhase.Authenticated && AuthState.HasValue;

    /// <summary>
    /// Checks if the secure channel can be initiated.
    /// </summary>
    public bool CanInitiate =>
        Phase is SecureChannelPhase.NotInitiated or SecureChannelPhase.Terminated;

    /// <summary>
    /// Checks if the secure channel can be authenticated.
    /// </summary>
    public bool CanAuthenticate => Phase == SecureChannelPhase.Initiated && InitData.HasValue;

    /// <summary>
    /// Gets the current security level if authenticated.
    /// </summary>
    public Maybe<SecurityLevel> CurrentSecurityLevel =>
        IsAuthenticated ? AuthState.Map(state => state.Level) : Maybe<SecurityLevel>.None;

    /// <summary>
    /// Gets the session keys if authenticated.
    /// </summary>
    public Maybe<SessionKeys> SessionKeys =>
        IsAuthenticated ? AuthState.Map(state => state.Keys) : Maybe<SessionKeys>.None;
}

/// <summary>
/// State transition functions for secure channel lifecycle.
/// All functions return new instances, maintaining immutability.
/// </summary>
public static class SecureChannelLifecycleTransitions
{
    /// <summary>
    /// Transitions to initiated state after INITIALIZE UPDATE.
    /// </summary>
    public static Result<SecureChannelLifecycle, SmartCardError> InitiateChannel(
        this SecureChannelLifecycle current,
        InitializeUpdateData initData
    )
    {
        if (!current.CanInitiate)
            return Result.Failure<SecureChannelLifecycle, SmartCardError>(
                new AuthenticationFailedError($"Cannot initiate from phase {current.Phase}")
            );

        return initData
            .Validate()
            .Map(_ => new SecureChannelLifecycle(
                Phase: SecureChannelPhase.Initiated,
                InitData: Maybe.From(initData),
                AuthState: Maybe.None,
                TerminationInfo: Maybe.None
            ));
    }

    /// <summary>
    /// Transitions to authenticated state after EXTERNAL AUTHENTICATE.
    /// Per GP spec E.3.2: The MAC from EXTERNAL AUTHENTICATE becomes the initial chaining value.
    /// </summary>
    public static Result<SecureChannelLifecycle, SmartCardError> AuthenticateChannel(
        this SecureChannelLifecycle current,
        SessionKeys keys,
        SecurityLevel level,
        byte[] externalAuthMac,
        ScpImplementation implementation
    )
    {
        if (!current.CanAuthenticate)
            return Result.Failure<SecureChannelLifecycle, SmartCardError>(
                new AuthenticationFailedError($"Cannot authenticate from phase {current.Phase}")
            );

        var authState = new AuthenticatedState(keys, level, externalAuthMac, implementation);

        return authState
            .Validate()
            .Map(_ =>
                current with
                {
                    Phase = SecureChannelPhase.Authenticated,
                    AuthState = Maybe.From(authState),
                }
            );
    }

    /// <summary>
    /// Transitions to aborted state after a security error.
    /// </summary>
    public static SecureChannelLifecycle AbortChannel(
        this SecureChannelLifecycle current,
        string reason,
        Maybe<ushort> statusWord = default
    )
    {
        return current with
        {
            Phase = SecureChannelPhase.Aborted,
            TerminationInfo = Maybe.From(new TerminationReason(reason, statusWord)),
        };
    }

    /// <summary>
    /// Transitions to terminated state.
    /// </summary>
    public static SecureChannelLifecycle TerminateChannel(
        this SecureChannelLifecycle current,
        string reason
    )
    {
        return current with
        {
            Phase = SecureChannelPhase.Terminated,
            TerminationInfo = Maybe.From(new TerminationReason(reason)),
        };
    }

    /// <summary>
    /// Creates a new SecureChannelState from authenticated lifecycle.
    /// This bridges to the existing SecureChannelState for compatibility.
    /// </summary>
    public static Result<SecureChannelState, SmartCardError> ToSecureChannelState(
        this SecureChannelLifecycle lifecycle
    )
    {
        if (!lifecycle.IsAuthenticated)
            return Result.Failure<SecureChannelState, SmartCardError>(
                new AuthenticationFailedError("Secure channel not authenticated")
            );

        return lifecycle
            .AuthState.ToResult((SmartCardError)new MissingDataError("AuthenticationState"))
            .Bind(authState =>
                lifecycle
                    .InitData.ToResult((SmartCardError)new MissingDataError("InitializationData"))
                    .Bind(initData =>
                        MacChainingState
                            .Create(
                                authState.InitialMacChaining,
                                initData.ProtocolVersion,
                                (byte)authState.Implementation
                            )
                            .Map(macChaining => new SecureChannelState(
                                SessionKeys: authState.Keys,
                                SecurityLevel: authState.Level,
                                ProtocolVersion: initData.ProtocolVersion,
                                MacChaining: macChaining,
                                EncryptionCounter: 0,
                                SessionId: GenerateSecureSessionId(),
                                ImplementationParameter: (byte)authState.Implementation,
                                LastStrippedCommand: ImmutableArray<byte>.Empty
                            ))
                    )
            );
    }

    /// <summary>
    /// Generates a cryptographically secure session identifier.
    /// Per GlobalPlatform specification, session IDs are used to uniquely identify
    /// secure channel sessions and prevent replay attacks.
    /// </summary>
    /// <returns>An 8-byte cryptographically secure session ID.</returns>
    private static ImmutableArray<byte> GenerateSecureSessionId()
    {
        // Generate 8 bytes of cryptographically secure random data
        // This follows the pattern used in SecureChannelState.Create()
        byte[] sessionId = new byte[8];
        var secureRandom = new SecureRandom();
        secureRandom.NextBytes(sessionId);

        return [.. sessionId];
    }
}
