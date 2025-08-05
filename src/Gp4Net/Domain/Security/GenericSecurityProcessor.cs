using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Transport;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Generic security processor that works with any SCP protocol.
/// Demonstrates the functional architecture with protocol selection at compile time.
/// </summary>
/// <typeparam name="TProtocol">The SCP protocol implementation to use.</typeparam>
[PublicAPI]
public static class GenericSecurityProcessor<TProtocol> where TProtocol : IScpProtocol<TProtocol>
{
    /// <summary>
    /// Applies command security using the specified protocol.
    /// </summary>
    /// <param name="command">The command to secure.</param>
    /// <param name="securityLevel">The security level to apply.</param>
    /// <param name="sessionKeys">The session keys.</param>
    /// <param name="macChainingValue">The current MAC chaining value.</param>
    /// <param name="encryptionCounter">The current encryption counter.</param>
    /// <returns>The secured command and updated state.</returns>
    public static Result<(byte[] securedCommand, SecureChannelState newState), SmartCardError> ApplyCommandSecurity(
        IApduCommand command,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter)
    {
        return SecurityValidation.ValidateCommandInputs(command, sessionKeys, macChainingValue)
            .Bind(_ => macChainingValue.Length != TProtocol.ChainingValueSize
                ? SmartCardError.InvalidArgument($"MAC chaining value must be {TProtocol.ChainingValueSize} bytes for {typeof(TProtocol).Name}")
                : Result.Success<IApduCommand, SmartCardError>(command))
            .Bind(_ => BuildCommandApdu(command))
            .Bind(commandBytes => ScpProtocolOperations.ApplyCommandSecurity<TProtocol>(
                commandBytes,
                securityLevel,
                sessionKeys,
                macChainingValue.ToArray(),
                encryptionCounter))
            .Bind(result => CreateNewState(result, securityLevel, sessionKeys, encryptionCounter));
    }

    /// <summary>
    /// Applies response security using the specified protocol.
    /// </summary>
    /// <param name="response">The response to secure/verify.</param>
    /// <param name="securityLevel">The security level to apply.</param>
    /// <param name="sessionKeys">The session keys.</param>
    /// <param name="macChainingValue">The current MAC chaining value.</param>
    /// <param name="encryptionCounter">The current encryption counter.</param>
    /// <returns>The processed response and updated state.</returns>
    public static Result<(byte[] processedResponse, SecureChannelState newState), SmartCardError> ApplyResponseSecurity(
        byte[] response,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter)
    {
        return SecurityValidation.ValidateResponseInputs(response, sessionKeys, macChainingValue)
            .Bind(_ => macChainingValue.Length != TProtocol.ChainingValueSize
                ? SmartCardError.InvalidArgument($"MAC chaining value must be {TProtocol.ChainingValueSize} bytes for {typeof(TProtocol).Name}")
                : Result.Success<byte[], SmartCardError>(response))
            .Bind(_ => ScpProtocolOperations.ApplyResponseSecurity<TProtocol>(
                response,
                securityLevel,
                sessionKeys,
                macChainingValue.ToArray(),
                encryptionCounter))
            .Bind(result => CreateNewStateFromResponse(result, securityLevel, sessionKeys, encryptionCounter));
    }

    /// <summary>
    /// Processes an INITIALIZE UPDATE response and creates a secure channel context.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge that was sent.</param>
    /// <param name="keySet">The key set for session key derivation.</param>
    /// <param name="implementationParameter">The implementation parameter (SCP02 i-parameter, unused for SCP03).</param>
    /// <returns>A secure channel context.</returns>
    public static Result<SecureChannelContext, SmartCardError> ProcessInitializeUpdate(
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        IKeySet keySet,
        byte implementationParameter)
    {
        return ScpProtocolOperations.ProcessInitializeUpdate<TProtocol>(response, hostChallenge, keySet, implementationParameter);
    }

    /// <summary>
    /// Creates an EXTERNAL AUTHENTICATE command.
    /// </summary>
    /// <param name="context">The secure channel context.</param>
    /// <param name="securityLevel">The requested security level.</param>
    /// <returns>The EXTERNAL AUTHENTICATE command.</returns>
    public static Result<ExternalAuthenticateCommand, SmartCardError> CreateExternalAuthenticate(
        SecureChannelContext context,
        SecurityLevel securityLevel)
    {
        return ScpProtocolOperations.CreateExternalAuthenticate<TProtocol>(context, securityLevel);
    }

    /// <summary>
    /// Establishes a secure channel with the specified parameters.
    /// </summary>
    /// <param name="sessionKeys">The session keys.</param>
    /// <param name="securityLevel">The security level.</param>
    /// <param name="implementationParameter">The implementation parameter.</param>
    /// <returns>The initial secure channel state.</returns>
    public static Result<SecureChannelState, SmartCardError> EstablishSecureChannel(
        SessionKeys sessionKeys,
        SecurityLevel securityLevel,
        byte implementationParameter = 0x00)
    {
        var initialMacChaining = new byte[TProtocol.ChainingValueSize];
        return SecureChannelState.Create(
            sessionKeys,
            securityLevel,
            TProtocol.ProtocolVersion,
            initialMacChaining,
            implementationParameter);
    }

    // Private helper methods


    private static Result<byte[], SmartCardError> BuildCommandApdu(IApduCommand command)
    {
        return ScpCommonOperations.BuildApdu(
            command.Cla,
            command.Ins,
            command.P1,
            command.P2,
            command.Data,
            command.ExpectedResponseLength.HasValue ? (byte)command.ExpectedResponseLength.Value : null);
    }

    private static Result<(byte[], SecureChannelState), SmartCardError> CreateNewState(
        (byte[] securedCommand, byte[] newChainingValue) result,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        uint encryptionCounter)
    {
        var (securedCommand, newChainingValue) = result;
        
        // Create MAC chaining state
        return MacChainingState.Create(newChainingValue, TProtocol.ProtocolVersion, 0x00)
            .Bind(macState => SecureChannelState.Create(
                sessionKeys,
                securityLevel,
                TProtocol.ProtocolVersion,
                newChainingValue,
                0x00)
                .Bind(state => state.UpdateCounterAndMac(encryptionCounter + 1, macState))
                .Map(updatedState => (securedCommand, updatedState)));
    }

    private static Result<(byte[], SecureChannelState), SmartCardError> CreateNewStateFromResponse(
        (byte[] processedResponse, byte[] chainingValue) result,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        uint encryptionCounter)
    {
        var (processedResponse, chainingValue) = result;
        
        // For responses, chaining value doesn't change (R-MAC doesn't update chaining)
        return MacChainingState.Create(chainingValue, TProtocol.ProtocolVersion, 0x00)
            .Bind(macState => SecureChannelState.Create(
                sessionKeys,
                securityLevel,
                TProtocol.ProtocolVersion,
                chainingValue,
                0x00)
                .Bind(state => state.UpdateCounterAndMac(encryptionCounter, macState))
                .Map(updatedState => (processedResponse, updatedState)));
    }
}

/// <summary>
/// Type aliases for specific protocol processors.
/// </summary>
[PublicAPI]
public static class Scp02SecurityProcessor
{
    /// <summary>
    /// Applies SCP02 command security.
    /// </summary>
    public static Result<(byte[] securedCommand, SecureChannelState newState), SmartCardError> ApplyCommandSecurity(
        IApduCommand command,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter) =>
        GenericSecurityProcessor<Scp02ProtocolImpl>.ApplyCommandSecurity(
            command, securityLevel, sessionKeys, macChainingValue, encryptionCounter);

    /// <summary>
    /// Applies SCP02 response security.
    /// </summary>
    public static Result<(byte[] processedResponse, SecureChannelState newState), SmartCardError> ApplyResponseSecurity(
        byte[] response,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter) =>
        GenericSecurityProcessor<Scp02ProtocolImpl>.ApplyResponseSecurity(
            response, securityLevel, sessionKeys, macChainingValue, encryptionCounter);

    /// <summary>
    /// Processes SCP02 INITIALIZE UPDATE.
    /// </summary>
    public static Result<SecureChannelContext, SmartCardError> ProcessInitializeUpdate(
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        IKeySet keySet,
        byte implementationParameter) =>
        GenericSecurityProcessor<Scp02ProtocolImpl>.ProcessInitializeUpdate(response, hostChallenge, keySet, implementationParameter);
}

/// <summary>
/// Type aliases for SCP03 protocol operations.
/// </summary>
[PublicAPI]
public static class Scp03SecurityProcessor
{
    /// <summary>
    /// Applies SCP03 command security.
    /// </summary>
    public static Result<(byte[] securedCommand, SecureChannelState newState), SmartCardError> ApplyCommandSecurity(
        IApduCommand command,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter) =>
        GenericSecurityProcessor<Scp03ProtocolImpl>.ApplyCommandSecurity(
            command, securityLevel, sessionKeys, macChainingValue, encryptionCounter);

    /// <summary>
    /// Applies SCP03 response security.
    /// </summary>
    public static Result<(byte[] processedResponse, SecureChannelState newState), SmartCardError> ApplyResponseSecurity(
        byte[] response,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys,
        ImmutableArray<byte> macChainingValue,
        uint encryptionCounter) =>
        GenericSecurityProcessor<Scp03ProtocolImpl>.ApplyResponseSecurity(
            response, securityLevel, sessionKeys, macChainingValue, encryptionCounter);

    /// <summary>
    /// Processes SCP03 INITIALIZE UPDATE.
    /// </summary>
    public static Result<SecureChannelContext, SmartCardError> ProcessInitializeUpdate(
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        IKeySet keySet,
        byte implementationParameter) =>
        GenericSecurityProcessor<Scp03ProtocolImpl>.ProcessInitializeUpdate(response, hostChallenge, keySet, implementationParameter);
}