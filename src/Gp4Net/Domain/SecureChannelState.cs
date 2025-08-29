using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Org.BouncyCastle.Security;

namespace Gp4Net.Domain;

/// <summary>
/// Immutable state representing an active secure channel session.
/// All operations return new instances rather than mutating existing state.
/// </summary>
[PublicAPI]
public record SecureChannelState(
    SessionKeys SessionKeys,
    SecurityLevel SecurityLevel,
    ScpVersion ProtocolVersion,
    MacChainingState MacChaining,
    uint EncryptionCounter,
    ImmutableArray<byte> SessionId
)
{
    /// <summary>
    /// Creates a new secure channel state with the encryption counter incremented.
    /// Used for R-ENC operations where each encryption operation must use a unique counter.
    /// </summary>
    public SecureChannelState IncrementEncryptionCounter()
    {
        return this with { EncryptionCounter = EncryptionCounter + 1 };
    }

    /// <summary>
    /// Creates a new secure channel state with an updated MAC chaining state.
    /// Used after MAC calculations to maintain proper chaining for subsequent operations.
    /// </summary>
    public Result<SecureChannelState, SmartCardError> UpdateMacChaining(MacChainingState newMacChaining)
    {
        return Maybe<MacChainingState>.From(newMacChaining).Match(
            Some: macChaining => Result.Success<SecureChannelState, SmartCardError>(
                this with { MacChaining = macChaining }),
            None: () => SmartCardError.InvalidArgument("MAC chaining state cannot be null"));
    }

    /// <summary>
    /// Creates a new secure channel state with an updated MAC chaining value.
    /// Used after MAC calculations to maintain proper chaining for subsequent operations.
    /// </summary>
    public Result<SecureChannelState, SmartCardError> UpdateMacChainingValue(byte[] newMacChainingValue)
    {
        return Maybe<byte[]>.From(newMacChainingValue).Match(
            Some: macValue => MacChainingState.Create(macValue, ProtocolVersion, 0x00)
                .Bind(newMacChaining => Result.Success<SecureChannelState, SmartCardError>(
                    this with { MacChaining = newMacChaining })),
            None: () => SmartCardError.InvalidArgument("MAC chaining value cannot be null"));
    }

    /// <summary>
    /// Creates a new secure channel state with both updated MAC chaining state and incremented counter.
    /// Convenience method for operations that affect both values.
    /// </summary>
    public Result<SecureChannelState, SmartCardError> UpdateCounterAndMac(uint newCounter, MacChainingState newMacChaining)
    {
        return Maybe<MacChainingState>.From(newMacChaining).Match(
            Some: macChaining => Result.Success<SecureChannelState, SmartCardError>(
                this with
                {
                    EncryptionCounter = newCounter,
                    MacChaining = macChaining
                }),
            None: () => SmartCardError.InvalidArgument("MAC chaining state cannot be null"));
    }

    /// <summary>
    /// Gets whether this session supports command MAC (C-MAC).
    /// </summary>
    public bool HasCommandMac
    {
        get
        {
            return SecurityLevel.HasCMac();
        }
    }

    /// <summary>
    /// Gets whether this session supports command encryption (C-ENC).
    /// </summary>
    public bool HasCommandEncryption
    {
        get
        {
            return SecurityLevel.HasCEncryption();
        }
    }

    /// <summary>
    /// Gets whether this session supports response MAC (R-MAC).
    /// </summary>
    public bool HasResponseMac
    {
        get
        {
            return SecurityLevel.HasRMac();
        }
    }

    /// <summary>
    /// Gets whether this session supports response encryption (R-ENC).
    /// </summary>
    public bool HasResponseEncryption
    {
        get
        {
            return SecurityLevel.HasREncryption();
        }
    }

    /// <summary>
    /// Gets whether this is an SCP03 session.
    /// </summary>
    public bool IsScp03
    {
        get
        {
            return ProtocolVersion == ScpVersion.Scp03;
        }
    }

    /// <summary>
    /// Gets whether this is an SCP02 session.
    /// </summary>
    public bool IsScp02
    {
        get
        {
            return ProtocolVersion == ScpVersion.Scp02;
        }
    }

    /// <summary>
    /// Gets the current MAC chaining value for chaining MAC calculations.
    /// </summary>
    public byte[] MacChainingValue
    {
        get
        {
            return MacChaining.ToArray();
        }
    }

    /// <summary>
    /// Creates a new secure channel state for the specified protocol and security level.
    /// </summary>
    /// <param name="sessionKeys">The derived session keys.</param>
    /// <param name="securityLevel">The security level to establish.</param>
    /// <param name="protocolVersion">The protocol version (0x02 or 0x03).</param>
    /// <param name="initialMacChainingValue">The initial MAC chaining value.</param>
    /// <param name="implementationParameter">The implementation parameter (i-value) for SCP02.</param>
    /// <returns>A result containing the new secure channel state or an error.</returns>
    public static Result<SecureChannelState, SmartCardError> Create(
        SessionKeys sessionKeys,
        SecurityLevel securityLevel,
        ScpVersion protocolVersion,
        byte[] initialMacChainingValue,
        byte implementationParameter)
    {
        return Maybe<SessionKeys>.From(sessionKeys).Match(
            Some: keys => Maybe<byte[]>.From(initialMacChainingValue).Match(
                Some: macValue => CreateInternal(keys, securityLevel, protocolVersion, macValue, implementationParameter),
                None: () => SmartCardError.InvalidArgument("Initial MAC chaining value cannot be null")),
            None: () => SmartCardError.InvalidArgument("Session keys cannot be null"));
    }

    private static Result<SecureChannelState, SmartCardError> CreateInternal(
        SessionKeys sessionKeys,
        SecurityLevel securityLevel,
        ScpVersion protocolVersion,
        byte[] initialMacChainingValue,
        byte implementationParameter)
    {
        if (protocolVersion != ScpVersion.Scp02 && protocolVersion != ScpVersion.Scp03)
        {
            return SmartCardError.InvalidArgument($"Unsupported protocol version: 0x{protocolVersion:X2}");
        }

        // Create the MAC chaining state
        Result<MacChainingState, SmartCardError> macChainingResult = MacChainingState.Create(
            initialMacChainingValue,
            protocolVersion,
            implementationParameter);

        if (macChainingResult.IsFailure)
        {
            return macChainingResult.Error;
        }

        // Generate cryptographically secure session ID
        byte[] sessionId = new byte[8];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.NextBytes(sessionId);

        return Result.Success<SecureChannelState, SmartCardError>(
            new SecureChannelState(
                sessionKeys,
                securityLevel,
                protocolVersion,
                macChainingResult.Value,
                0, // Start with counter = 0 per GP specification
                [.. sessionId]
            ));
    }

    /// <summary>
    /// Validates that the secure channel state is consistent and valid.
    /// </summary>
    /// <returns>A result indicating success or describing validation errors.</returns>
    public Result<SecureChannelState, SmartCardError> Validate()
    {
        return Maybe<SessionKeys>.From(SessionKeys).Match(
            Some: keys => Maybe<MacChainingState>.From(MacChaining).Match(
                Some: macChaining => ValidateInternal(),
                None: () => SmartCardError.InvalidData("MAC chaining state cannot be null")),
            None: () => SmartCardError.InvalidData("Session keys are null"));
    }

    private Result<SecureChannelState, SmartCardError> ValidateInternal()
    {
        if (ProtocolVersion != ScpVersion.Scp02 && ProtocolVersion != ScpVersion.Scp03)
        {
            return SmartCardError.InvalidData($"Invalid protocol version: 0x{ProtocolVersion:X2}");
        }

        // Encryption counter starts at 0 and increments with each encryption operation
        // No validation needed for counter value

        // Validate security level combinations
        if (HasResponseEncryption && !HasResponseMac)
        {
            return SmartCardError.InvalidData("R-ENC requires R-MAC to be enabled");
        }

        return Result.Success<SecureChannelState, SmartCardError>(this);
    }
}