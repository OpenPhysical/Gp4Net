using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Immutable state representing an active secure channel session.
/// All operations return new instances rather than mutating existing state.
/// </summary>
[PublicAPI]
public record SecureChannelState(
    SessionKeys SessionKeys,
    SecurityLevel SecurityLevel,
    byte ProtocolVersion,
    MacChainingState MacChaining,
    uint EncryptionCounter,
    ImmutableArray<byte> SessionId
)
{
    /// <summary>
    /// Creates a new secure channel state with the encryption counter incremented.
    /// Used for R-ENC operations where each encryption operation must use a unique counter.
    /// </summary>
    public SecureChannelState IncrementEncryptionCounter() =>
        this with { EncryptionCounter = EncryptionCounter + 1 };

    /// <summary>
    /// Creates a new secure channel state with an updated MAC chaining state.
    /// Used after MAC calculations to maintain proper chaining for subsequent operations.
    /// </summary>
    public Result<SecureChannelState, SmartCardError> UpdateMacChaining(MacChainingState newMacChaining)
    {
        if (newMacChaining == null)
        {
            return SmartCardError.InvalidArgument("MAC chaining state cannot be null");
        }

        return Result.Success<SecureChannelState, SmartCardError>(
            this with { MacChaining = newMacChaining });
    }

    /// <summary>
    /// Creates a new secure channel state with both updated MAC chaining state and incremented counter.
    /// Convenience method for operations that affect both values.
    /// </summary>
    public Result<SecureChannelState, SmartCardError> UpdateCounterAndMac(uint newCounter, MacChainingState newMacChaining)
    {
        if (newMacChaining == null)
        {
            return SmartCardError.InvalidArgument("MAC chaining state cannot be null");
        }

        return Result.Success<SecureChannelState, SmartCardError>(
            this with 
            { 
                EncryptionCounter = newCounter,
                MacChaining = newMacChaining 
            });
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
            return ProtocolVersion == 0x03;
        }
    }

    /// <summary>
    /// Gets whether this is an SCP02 session.
    /// </summary>
    public bool IsScp02
    {
        get
        {
            return ProtocolVersion == 0x02;
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
        byte protocolVersion,
        byte[] initialMacChainingValue,
        byte implementationParameter)
    {
        if (sessionKeys == null)
        {
            return SmartCardError.InvalidArgument("Session keys cannot be null");
        }

        if (protocolVersion != 0x02 && protocolVersion != 0x03)
        {
            return SmartCardError.InvalidArgument($"Unsupported protocol version: 0x{protocolVersion:X2}");
        }

        if (initialMacChainingValue == null)
        {
            return SmartCardError.InvalidArgument("Initial MAC chaining value cannot be null");
        }

        // Create the MAC chaining state
        var macChainingResult = MacChainingState.Create(
            initialMacChainingValue, 
            protocolVersion, 
            implementationParameter);
            
        if (macChainingResult.IsFailure)
        {
            return macChainingResult.Error;
        }

        // Generate cryptographically secure session ID
        var sessionId = new byte[8];
        using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
        {
            rng.GetBytes(sessionId);
        }

        return Result.Success<SecureChannelState, SmartCardError>(
            new SecureChannelState(
                sessionKeys,
                securityLevel,
                protocolVersion,
                macChainingResult.Value,
                0, // Start with counter = 0 per GP specification
                ImmutableArray.Create(sessionId)
            ));
    }

    /// <summary>
    /// Validates that the secure channel state is consistent and valid.
    /// </summary>
    /// <returns>A result indicating success or describing validation errors.</returns>
    public Result<SecureChannelState, SmartCardError> Validate()
    {
        if (SessionKeys == null)
        {
            return SmartCardError.InvalidData("Session keys are null");
        }

        if (ProtocolVersion != 0x02 && ProtocolVersion != 0x03)
        {
            return SmartCardError.InvalidData($"Invalid protocol version: 0x{ProtocolVersion:X2}");
        }

        if (MacChaining == null)
        {
            return SmartCardError.InvalidData("MAC chaining state cannot be null");
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