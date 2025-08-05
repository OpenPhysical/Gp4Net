using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Functional secure channel service that provides pure functions for secure messaging operations.
/// All methods are stateless and return new state instances rather than mutating existing state.
/// </summary>
[PublicAPI]
public interface ISecureChannelService
{
    /// <summary>
    /// Establishes a new secure channel with the specified parameters.
    /// This is a pure function that creates initial secure channel state.
    /// </summary>
    /// <param name="sessionKeys">The derived session keys to use.</param>
    /// <param name="securityLevel">The security level to establish.</param>
    /// <param name="protocolVersion">The protocol version (0x02 or 0x03).</param>
    /// <param name="initialMacChainingValue">The initial MAC chaining value.</param>
    /// <param name="implementationParameter">The implementation parameter (i-value) for SCP02.</param>
    /// <returns>A result containing the new secure channel state or an error.</returns>
    Result<SecureChannelState, SmartCardError> EstablishChannel(
        SessionKeys sessionKeys,
        SecurityLevel securityLevel,
        byte protocolVersion,
        byte[] initialMacChainingValue,
        byte implementationParameter = 0x00);

    /// <summary>
    /// Wraps an APDU command with secure messaging (C-MAC and/or C-ENC).
    /// Returns both the wrapped command and the updated secure channel state.
    /// </summary>
    /// <param name="command">The command to wrap with secure messaging.</param>
    /// <param name="state">The current secure channel state.</param>
    /// <returns>A result containing the wrapped command data and updated state, or an error.</returns>
    Result<(byte[] wrappedCommand, SecureChannelState newState), SmartCardError> WrapCommand(
        IApduCommand command,
        SecureChannelState state);

    /// <summary>
    /// Unwraps a response APDU that may contain secure messaging (R-MAC and/or R-ENC).
    /// Returns both the unwrapped response and the updated secure channel state.
    /// </summary>
    /// <param name="response">The response to unwrap (including status word).</param>
    /// <param name="state">The current secure channel state.</param>
    /// <returns>A result containing the unwrapped response data and updated state, or an error.</returns>
    Result<(byte[] unwrappedResponse, SecureChannelState newState), SmartCardError> UnwrapResponse(
        byte[] response,
        SecureChannelState state);

    /// <summary>
    /// Validates that a secure channel state is compatible with the specified operation.
    /// This is a pure validation function with no side effects.
    /// </summary>
    /// <param name="state">The secure channel state to validate.</param>
    /// <param name="operationType">The type of operation being performed.</param>
    /// <returns>A result indicating whether the state is valid for the operation.</returns>
    Result<SecureChannelState, SmartCardError> ValidateStateForOperation(
        SecureChannelState state,
        SecureChannelOperation operationType);
}

/// <summary>
/// Enumeration of secure channel operation types for validation.
/// </summary>
[PublicAPI]
public enum SecureChannelOperation
{
    /// <summary>
    /// Command wrapping operation (requires C-MAC/C-ENC capabilities).
    /// </summary>
    CommandWrapping,

    /// <summary>
    /// Response unwrapping operation (requires R-MAC/R-ENC capabilities).
    /// </summary>
    ResponseUnwrapping,

    /// <summary>
    /// General secure messaging operation.
    /// </summary>
    SecureMessaging
}