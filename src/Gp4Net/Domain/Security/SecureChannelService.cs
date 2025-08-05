using System;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Pure functional implementation of secure channel service.
/// All methods are stateless and have no side effects.
/// </summary>
[PublicAPI]
public class SecureChannelService : ISecureChannelService
{
    private readonly ICommandSecurityProcessor _commandProcessor;
    private readonly IResponseSecurityProcessor _responseProcessor;

    /// <summary>
    /// Initializes a new instance of the FunctionalSecureChannelService class.
    /// </summary>
    /// <param name="commandProcessor">The command security processor.</param>
    /// <param name="responseProcessor">The response security processor.</param>
    public SecureChannelService(
        ICommandSecurityProcessor commandProcessor,
        IResponseSecurityProcessor responseProcessor)
    {
        _commandProcessor = commandProcessor ?? throw new ArgumentNullException(nameof(commandProcessor));
        _responseProcessor = responseProcessor ?? throw new ArgumentNullException(nameof(responseProcessor));
    }

    /// <inheritdoc />
    public Result<SecureChannelState, SmartCardError> EstablishChannel(
        SessionKeys sessionKeys,
        SecurityLevel securityLevel,
        byte protocolVersion,
        byte[] initialMacChainingValue,
        byte implementationParameter = 0x00)
    {
        return SecureChannelState.Create(sessionKeys, securityLevel, protocolVersion, initialMacChainingValue, implementationParameter)
            .Bind(state => state.Validate());
    }

    /// <inheritdoc />
    public Result<(byte[] wrappedCommand, SecureChannelState newState), SmartCardError> WrapCommand(
        IApduCommand command,
        SecureChannelState state)
    {
        return ValidateCommand(command)
            .Bind(_ => ValidateStateForOperation(state, SecureChannelOperation.CommandWrapping))
            .Bind(validatedState => ApplyCommandSecurity(command, validatedState));
    }

    /// <inheritdoc />
    public Result<(byte[] unwrappedResponse, SecureChannelState newState), SmartCardError> UnwrapResponse(
        byte[] response,
        SecureChannelState state)
    {
        return ValidateResponse(response)
            .Bind(_ => ValidateStateForOperation(state, SecureChannelOperation.ResponseUnwrapping))
            .Bind(validatedState => ApplyResponseSecurity(response, validatedState));
    }

    /// <inheritdoc />
    public Result<SecureChannelState, SmartCardError> ValidateStateForOperation(
        SecureChannelState state,
        SecureChannelOperation operationType)
    {
        return state.Validate()
            .Bind(validatedState => ValidateOperationCompatibility(validatedState, operationType));
    }

    // Private pure functions for implementation

    private static Result<IApduCommand, SmartCardError> ValidateCommand(IApduCommand command)
    {
        if (command == null)
            return SmartCardError.InvalidArgument("Command cannot be null");

        return Result.Success<IApduCommand, SmartCardError>(command);
    }

    private static Result<byte[], SmartCardError> ValidateResponse(byte[] response)
    {
        if (response == null)
            return SmartCardError.InvalidArgument("Response cannot be null");

        if (response.Length < 2)
            return SmartCardError.InvalidData("Response must contain at least status word");

        return Result.Success<byte[], SmartCardError>(response);
    }

    private static Result<SecureChannelState, SmartCardError> ValidateOperationCompatibility(
        SecureChannelState state,
        SecureChannelOperation operationType)
    {
        return operationType switch
        {
            SecureChannelOperation.CommandWrapping => ValidateCommandWrappingCapabilities(state),
            SecureChannelOperation.ResponseUnwrapping => ValidateResponseUnwrappingCapabilities(state),
            SecureChannelOperation.SecureMessaging => Result.Success<SecureChannelState, SmartCardError>(state),
            _ => SmartCardError.InvalidArgument($"Unknown operation type: {operationType}")
        };
    }

    private static Result<SecureChannelState, SmartCardError> ValidateCommandWrappingCapabilities(SecureChannelState state)
    {
        // For command wrapping, we need at least C-MAC capability
        if (!state.HasCommandMac)
            return SmartCardError.InvalidArgument("Command wrapping requires C-MAC capability");

        return Result.Success<SecureChannelState, SmartCardError>(state);
    }

    private static Result<SecureChannelState, SmartCardError> ValidateResponseUnwrappingCapabilities(SecureChannelState state)
    {
        // For response unwrapping, we need at least R-MAC capability
        if (!state.HasResponseMac)
            return SmartCardError.InvalidArgument("Response unwrapping requires R-MAC capability");

        return Result.Success<SecureChannelState, SmartCardError>(state);
    }

    private Result<(byte[] wrappedCommand, SecureChannelState newState), SmartCardError> ApplyCommandSecurity(
        IApduCommand command,
        SecureChannelState state)
    {
        return _commandProcessor.ApplyCommandSecurity(
            command,
            state.SecurityLevel,
            state.SessionKeys,
            ImmutableArray.Create(state.MacChaining.ToArray()),
            state.EncryptionCounter,
            state.ProtocolVersion
        );
    }

    private Result<(byte[] unwrappedResponse, SecureChannelState newState), SmartCardError> ApplyResponseSecurity(
        byte[] response,
        SecureChannelState state)
    {
        return _responseProcessor.ApplyResponseSecurity(
            response,
            state.SecurityLevel,
            state.SessionKeys,
            ImmutableArray.Create(state.MacChaining.ToArray()),
            state.EncryptionCounter,
            state.ProtocolVersion
        );
    }
}

/// <summary>
/// Interface for functional command security processing.
/// </summary>
[PublicAPI]
public interface ICommandSecurityProcessor
{
    /// <summary>
    /// Applies command security (C-MAC and/or C-ENC) to an APDU command.
    /// Returns the secured command and updated state.
    /// </summary>
    Result<(byte[] securedCommand, SecureChannelState newState), SmartCardError> ApplyCommandSecurity(
        IApduCommand command,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter,
        byte protocolVersion);
}

/// <summary>
/// Interface for functional response security processing.
/// </summary>
[PublicAPI]
public interface IResponseSecurityProcessor
{
    /// <summary>
    /// Applies response security processing (R-MAC and/or R-ENC) to a response.
    /// Returns the processed response and updated state.
    /// </summary>
    Result<(byte[] processedResponse, SecureChannelState newState), SmartCardError> ApplyResponseSecurity(
        byte[] response,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter,
        byte protocolVersion);
}
