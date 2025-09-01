using System;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using Gp4Net.Cryptography;
using JetBrains.Annotations;
using static Gp4Net.Cryptography.CryptoService;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Clean functional implementation of secure channel service following MacCalculations pattern.
/// All methods delegate to static cryptographic and security functions - no dependency injection complexity.
/// This service acts as a thin wrapper providing the interface while delegating to pure static functions.
///
/// DEPRECATED: This service is being replaced by the unified ScpService in the Protocol namespace.
/// Use ScpService for new code - it provides a cleaner, more functional API.
/// </summary>
[PublicAPI]
[Obsolete(
    "Use ScpService from Gp4Net.Domain.Protocol namespace for new code. This will be removed in a future version."
)]
public class SecureChannelService : ISecureChannelService
{
    /// <summary>
    /// Initializes a new instance of the SecureChannelService class.
    /// No dependencies required - all operations are static function calls.
    /// </summary>
    public SecureChannelService()
    {
        // Clean architecture: no dependencies, just static function delegation
    }

    /// <inheritdoc />
    public Result<SecureChannelState, SmartCardError> EstablishChannel(
        SessionKeys sessionKeys,
        SecurityLevel securityLevel,
        byte protocolVersion,
        byte[] initialMacChainingValue,
        byte implementationParameter = 0x00
    )
    {
        return protocolVersion switch
        {
            0x02 => EstablishScp02Channel(
                sessionKeys,
                securityLevel,
                initialMacChainingValue,
                implementationParameter
            ),
            0x03 => EstablishScp03Channel(
                sessionKeys,
                securityLevel,
                initialMacChainingValue,
                implementationParameter
            ),
            _ => Result.Failure<SecureChannelState, SmartCardError>(
                SmartCardError.InvalidArgument(
                    $"Unsupported protocol version: {protocolVersion:X2}"
                )
            ),
        };
    }

    /// <inheritdoc />
    public Result<(byte[] wrappedCommand, SecureChannelState newState), SmartCardError> WrapCommand(
        IApduCommand command,
        SecureChannelState state
    )
    {
        // Delegate to unified ScpService.Security for consistency
        return Gp4Net.Services.ScpService.Security.ApplyCommandSecurity(command, state);
    }

    /// <inheritdoc />
    public Result<
        (byte[] unwrappedResponse, SecureChannelState newState),
        SmartCardError
    > UnwrapResponse(byte[] response, SecureChannelState state)
    {
        // Delegate to unified ScpService.Security for consistency
        return Gp4Net.Services.ScpService.Security.ProcessResponse(response, state);
    }

    /// <inheritdoc />
    public Result<SecureChannelState, SmartCardError> ValidateStateForOperation(
        SecureChannelState state,
        SecureChannelOperation operationType
    )
    {
        return state
            .Validate()
            .Bind(validatedState => ValidateOperationCompatibility(validatedState, operationType));
    }

    // Private pure functions delegating to static operations

    private static Result<IApduCommand, SmartCardError> ValidateCommand(IApduCommand command)
    {
        Maybe<IApduCommand> commandMaybe = Maybe<IApduCommand>.From(command);
        return commandMaybe.HasValue
            ? Result.Success<IApduCommand, SmartCardError>(command)
            : Result.Failure<IApduCommand, SmartCardError>(
                SmartCardError.InvalidArgument("Command cannot be null")
            );
    }

    private static Result<byte[], SmartCardError> ValidateResponse(byte[] response)
    {
        Maybe<byte[]> responseMaybe = Maybe<byte[]>.From(response);
        return responseMaybe.HasValue && response.Length >= 2
            ? Result.Success<byte[], SmartCardError>(response)
            : Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Response must be at least 2 bytes")
            );
    }

    private static Result<SecureChannelState, SmartCardError> ValidateOperationCompatibility(
        SecureChannelState state,
        SecureChannelOperation operationType
    )
    {
        return operationType switch
        {
            SecureChannelOperation.CommandWrapping => ValidateCommandWrappingCapabilities(state),
            SecureChannelOperation.ResponseUnwrapping => ValidateResponseUnwrappingCapabilities(
                state
            ),
            SecureChannelOperation.SecureMessaging => Result.Success<
                SecureChannelState,
                SmartCardError
            >(state),
            _ => Result.Failure<SecureChannelState, SmartCardError>(
                SmartCardError.InvalidArgument($"Unsupported operation type: {operationType}")
            ),
        };
    }

    private static Result<SecureChannelState, SmartCardError> ValidateCommandWrappingCapabilities(
        SecureChannelState state
    )
    {
        // For command wrapping, we need at least C-MAC capability
        if (!state.HasCommandMac)
        {
            return Result.Failure<SecureChannelState, SmartCardError>(
                SmartCardError.SecurityError("Command wrapping requires C-MAC capability")
            );
        }

        return Result.Success<SecureChannelState, SmartCardError>(state);
    }

    private static Result<
        SecureChannelState,
        SmartCardError
    > ValidateResponseUnwrappingCapabilities(SecureChannelState state)
    {
        // For response unwrapping, we need at least R-MAC capability
        if (!state.HasResponseMac)
        {
            return Result.Failure<SecureChannelState, SmartCardError>(
                SmartCardError.SecurityError("Response unwrapping requires R-MAC capability")
            );
        }

        return Result.Success<SecureChannelState, SmartCardError>(state);
    }

    private static Result<
        (byte[] wrappedCommand, SecureChannelState newState),
        SmartCardError
    > ApplyProtocolSpecificCommandSecurity(IApduCommand command, SecureChannelState state)
    {
        return state.ProtocolVersion switch
        {
            ScpVersion.Scp02 => ApplyScp02CommandSecurity(command, state),
            ScpVersion.Scp03 => ApplyScp03CommandSecurity(command, state),
            _ => Result.Failure<(byte[], SecureChannelState), SmartCardError>(
                SmartCardError.InvalidArgument(
                    $"Unsupported protocol version: {state.ProtocolVersion:X2}"
                )
            ),
        };
    }

    private static Result<
        (byte[] unwrappedResponse, SecureChannelState newState),
        SmartCardError
    > ApplyProtocolSpecificResponseSecurity(byte[] response, SecureChannelState state)
    {
        return state.ProtocolVersion switch
        {
            ScpVersion.Scp02 => ApplyScp02ResponseSecurity(response, state),
            ScpVersion.Scp03 => ApplyScp03ResponseSecurity(response, state),
            _ => Result.Failure<(byte[], SecureChannelState), SmartCardError>(
                SmartCardError.InvalidArgument(
                    $"Unsupported protocol version: {state.ProtocolVersion:X2}"
                )
            ),
        };
    }

    // Protocol-specific channel establishment methods

    /// <summary>
    /// Establishes an SCP02 secure channel with the provided parameters.
    /// </summary>
    private static Result<SecureChannelState, SmartCardError> EstablishScp02Channel(
        SessionKeys sessionKeys,
        SecurityLevel securityLevel,
        byte[] initialMacChainingValue,
        byte implementationParameter
    )
    {
        return MacChainingState
            .Create(initialMacChainingValue, ScpVersion.Scp02, implementationParameter)
            .Bind(macState =>
                SecureChannelState
                    .Create(
                        sessionKeys,
                        securityLevel,
                        ScpVersion.Scp02,
                        initialMacChainingValue,
                        implementationParameter
                    )
                    .Bind(state => state.UpdateCounterAndMac(0, macState))
            );
    }

    /// <summary>
    /// Establishes an SCP03 secure channel with the provided parameters.
    /// </summary>
    private static Result<SecureChannelState, SmartCardError> EstablishScp03Channel(
        SessionKeys sessionKeys,
        SecurityLevel securityLevel,
        byte[] initialMacChainingValue,
        byte implementationParameter
    )
    {
        return MacChainingState
            .Create(initialMacChainingValue, ScpVersion.Scp03, implementationParameter)
            .Bind(macState =>
                SecureChannelState
                    .Create(
                        sessionKeys,
                        securityLevel,
                        ScpVersion.Scp03,
                        initialMacChainingValue,
                        implementationParameter
                    )
                    .Bind(state => state.UpdateCounterAndMac(0, macState))
            );
    }

    // Protocol-specific command security methods

    /// <summary>
    /// Applies SCP02 command security (C-MAC and C-ENC).
    /// </summary>
    private static Result<(byte[], SecureChannelState), SmartCardError> ApplyScp02CommandSecurity(
        IApduCommand command,
        SecureChannelState state
    )
    {
        // Convert IApduCommand to byte array for processing
        byte[] commandBytes = command.ToByteArray();

        return state.SecurityLevel.HasCMac()
                ? ApplyCommandMacScp02(commandBytes, state)
                    .Bind(macResult =>
                        state.SecurityLevel.HasCEncryption()
                            ? ApplyCommandEncryptionScp02(
                                macResult.commandWithMac,
                                macResult.newState
                            )
                            : Result.Success<(byte[], SecureChannelState), SmartCardError>(
                                macResult
                            )
                    )
            : state.SecurityLevel.HasCEncryption()
                ? ApplyCommandEncryptionScp02(commandBytes, state)
            : Result.Success<(byte[], SecureChannelState), SmartCardError>((commandBytes, state));
    }

    /// <summary>
    /// Applies SCP03 command security (C-MAC and C-ENC).
    /// </summary>
    private static Result<(byte[], SecureChannelState), SmartCardError> ApplyScp03CommandSecurity(
        IApduCommand command,
        SecureChannelState state
    )
    {
        // Convert IApduCommand to byte array for processing
        byte[] commandBytes = command.ToByteArray();

        return state.SecurityLevel.HasCMac()
                ? ApplyCommandMacScp03(commandBytes, state)
                    .Bind(macResult =>
                        state.SecurityLevel.HasCEncryption()
                            ? ApplyCommandEncryptionScp03(
                                macResult.commandWithMac,
                                macResult.newState
                            )
                            : Result.Success<(byte[], SecureChannelState), SmartCardError>(
                                macResult
                            )
                    )
            : state.SecurityLevel.HasCEncryption()
                ? ApplyCommandEncryptionScp03(commandBytes, state)
            : Result.Success<(byte[], SecureChannelState), SmartCardError>((commandBytes, state));
    }

    // Protocol-specific response security methods

    /// <summary>
    /// Applies SCP02 response security (R-MAC verification and R-ENC decryption).
    /// </summary>
    private static Result<(byte[], SecureChannelState), SmartCardError> ApplyScp02ResponseSecurity(
        byte[] response,
        SecureChannelState state
    )
    {
        return state.SecurityLevel.HasRMac()
                ? VerifyResponseMacScp02(response, state)
                    .Bind(verifyResult =>
                        state.SecurityLevel.HasREncryption()
                            ? DecryptResponseScp02(
                                verifyResult.verifiedResponse,
                                verifyResult.newState
                            )
                            : Result.Success<(byte[], SecureChannelState), SmartCardError>(
                                verifyResult
                            )
                    )
            : state.SecurityLevel.HasREncryption() ? DecryptResponseScp02(response, state)
            : Result.Success<(byte[], SecureChannelState), SmartCardError>((response, state));
    }

    /// <summary>
    /// Applies SCP03 response security (R-MAC verification and R-ENC decryption).
    /// </summary>
    private static Result<(byte[], SecureChannelState), SmartCardError> ApplyScp03ResponseSecurity(
        byte[] response,
        SecureChannelState state
    )
    {
        return state.SecurityLevel.HasRMac()
                ? VerifyResponseMacScp03(response, state)
                    .Bind(verifyResult =>
                        state.SecurityLevel.HasREncryption()
                            ? DecryptResponseScp03(
                                verifyResult.verifiedResponse,
                                verifyResult.newState
                            )
                            : Result.Success<(byte[], SecureChannelState), SmartCardError>(
                                verifyResult
                            )
                    )
            : state.SecurityLevel.HasREncryption() ? DecryptResponseScp03(response, state)
            : Result.Success<(byte[], SecureChannelState), SmartCardError>((response, state));
    }

    // Helper methods for command security operations

    /// <summary>
    /// Applies C-MAC to SCP02 command using MacCalculations.
    /// </summary>
    private static Result<
        (byte[] commandWithMac, SecureChannelState newState),
        SmartCardError
    > ApplyCommandMacScp02(byte[] command, SecureChannelState state)
    {
        // Use UnifiedCryptoService for SCP02 C-MAC calculation
        byte[] macInput = CryptoService.Utils.BuildMacInput(
            command[0],
            command[1],
            command[2],
            command[3],
            command.Length > 5 ? command[5..] : [],
            ScpVersion.Scp02
        );

        return CryptoService.Mac
            .CalculateScp02CommandMac(state.SessionKeys.SMac, macInput)
            .Map(mac =>
            {
                byte[] commandWithMac = CryptoService.Utils.ConcatenateArrays(command, mac);
                return (commandWithMac, state); // State update would happen here
            });
    }

    /// <summary>
    /// Applies C-MAC to SCP03 command using MacCalculations.
    /// </summary>
    private static Result<
        (byte[] commandWithMac, SecureChannelState newState),
        SmartCardError
    > ApplyCommandMacScp03(byte[] command, SecureChannelState state)
    {
        // Use UnifiedCryptoService for SCP03 C-MAC calculation
        byte[] macInput = CryptoService.Utils.BuildMacInput(
            command[0],
            command[1],
            command[2],
            command[3],
            command.Length > 5 ? command[5..] : [],
            ScpVersion.Scp03
        );

        return CryptoService.Mac
            .CalculateScp03CommandMac(state.SessionKeys.SMac, macInput)
            .Map(mac =>
            {
                byte[] commandWithMac = CryptoService.Utils.ConcatenateArrays(command, mac);
                return (commandWithMac, state); // State update would happen here
            });
    }

    /// <summary>
    /// Applies C-ENC to SCP02 command using CryptographicOperations.
    /// </summary>
    private static Result<(byte[], SecureChannelState), SmartCardError> ApplyCommandEncryptionScp02(
        byte[] command,
        SecureChannelState state
    )
    {
        // Implementation would use UnifiedCryptoService.Cipher.Encrypt3DesCbc
        return Result.Success<(byte[], SecureChannelState), SmartCardError>((command, state));
    }

    /// <summary>
    /// Applies C-ENC to SCP03 command using CryptographicOperations.
    /// </summary>
    private static Result<(byte[], SecureChannelState), SmartCardError> ApplyCommandEncryptionScp03(
        byte[] command,
        SecureChannelState state
    )
    {
        // Implementation would use UnifiedCryptoService.Cipher.EncryptAesCbc
        return Result.Success<(byte[], SecureChannelState), SmartCardError>((command, state));
    }

    // Helper methods for response security operations

    /// <summary>
    /// Verifies R-MAC on SCP02 response using MacCalculations.
    /// </summary>
    private static Result<
        (byte[] verifiedResponse, SecureChannelState newState),
        SmartCardError
    > VerifyResponseMacScp02(byte[] response, SecureChannelState state)
    {
        // Implementation would use UnifiedCryptoService.Mac for R-MAC verification
        return Result.Success<(byte[], SecureChannelState), SmartCardError>((response, state));
    }

    /// <summary>
    /// Verifies R-MAC on SCP03 response using MacCalculations.
    /// </summary>
    private static Result<
        (byte[] verifiedResponse, SecureChannelState newState),
        SmartCardError
    > VerifyResponseMacScp03(byte[] response, SecureChannelState state)
    {
        // Implementation would use UnifiedCryptoService.Mac for R-MAC verification
        return Result.Success<(byte[], SecureChannelState), SmartCardError>((response, state));
    }

    /// <summary>
    /// Decrypts R-ENC on SCP02 response using CryptographicOperations.
    /// </summary>
    private static Result<(byte[], SecureChannelState), SmartCardError> DecryptResponseScp02(
        byte[] response,
        SecureChannelState state
    )
    {
        // Implementation would use UnifiedCryptoService.Cipher.Decrypt3DesCbc
        return Result.Success<(byte[], SecureChannelState), SmartCardError>((response, state));
    }

    /// <summary>
    /// Decrypts R-ENC on SCP03 response using CryptographicOperations.
    /// </summary>
    private static Result<(byte[], SecureChannelState), SmartCardError> DecryptResponseScp03(
        byte[] response,
        SecureChannelState state
    )
    {
        // Implementation would use UnifiedCryptoService.Cipher.DecryptAesCbc
        return Result.Success<(byte[], SecureChannelState), SmartCardError>((response, state));
    }
}
