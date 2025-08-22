using System;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
using Gp4Net.Transport;
using Gp4Net.Pipeline;

namespace Gp4Net.Domain.Modules;

/// <summary>
/// Pure functional module for establishing GlobalPlatform secure channels.
/// Handles SCP02 and SCP03 protocol flows.
/// </summary>
public static class SecureChannelEstablishment
{
    /// <summary>
    /// Establishes a secure channel with the card.
    /// </summary>
    /// <param name="keySet">The key set to use for authentication.</param>
    /// <param name="securityLevel">The desired security level.</param>
    /// <param name="executeCommand">Function to execute APDU commands.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The established secure channel state or an error.</returns>
    public static async Task<Result<SecureChannelState, SmartCardError>> EstablishAsync(
        IKeySet keySet,
        SecurityLevel securityLevel,
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        // Generate host challenge
        byte[] hostChallenge = CryptographyHelpers.GenerateHostChallenge();

        // Send INITIALIZE UPDATE
        Result<InitializeUpdateResponse, SmartCardError> initUpdateResult = 
            await SendInitializeUpdateAsync(keySet, hostChallenge, executeCommand, cancellationToken);
        
        if (initUpdateResult.IsFailure)
        {
            return Result.Failure<SecureChannelState, SmartCardError>(initUpdateResult.Error);
        }

        InitializeUpdateResponse initResponse = initUpdateResult.Value;

        // Determine protocol and create appropriate handler
        Result<ISecureChannelProtocol, SmartCardError> protocolResult = 
            CreateProtocol(initResponse.ScpId, keySet);
        
        if (protocolResult.IsFailure)
        {
            return Result.Failure<SecureChannelState, SmartCardError>(protocolResult.Error);
        }

        ISecureChannelProtocol protocol = protocolResult.Value;

        // Process INITIALIZE UPDATE response
        Result<SecureChannelContext, SmartCardError> contextResult = 
            protocol.ProcessInitializeUpdateResponse(initResponse, hostChallenge);
        
        if (contextResult.IsFailure)
        {
            return Result.Failure<SecureChannelState, SmartCardError>(contextResult.Error);
        }

        SecureChannelContext context = contextResult.Value;

        // Send EXTERNAL AUTHENTICATE
        Result<bool, SmartCardError> authResult = await SendExternalAuthenticateAsync(
            protocol,
            context,
            securityLevel,
            executeCommand,
            cancellationToken);
        
        if (authResult.IsFailure)
        {
            return Result.Failure<SecureChannelState, SmartCardError>(authResult.Error);
        }

        // Create secure channel state
        return CreateSecureChannelState(protocol, context, securityLevel);
    }

    /// <summary>
    /// Sends INITIALIZE UPDATE command and parses the response.
    /// </summary>
    private static async Task<Result<InitializeUpdateResponse, SmartCardError>> SendInitializeUpdateAsync(
        IKeySet keySet,
        byte[] hostChallenge,
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken)
    {
        Result<InitializeUpdateCommand, SmartCardError> cmdResult = 
            CommandFactory.CreateInitializeUpdateCommand(keySet.KeyVersion, keySet.KeyId, hostChallenge);
        
        if (cmdResult.IsFailure)
        {
            return Result.Failure<InitializeUpdateResponse, SmartCardError>(cmdResult.Error);
        }

        Result<CommandResponse, SmartCardError> response = 
            await executeCommand(cmdResult.Value, cancellationToken);
        
        if (response.IsFailure)
        {
            return Result.Failure<InitializeUpdateResponse, SmartCardError>(response.Error);
        }

        return ResponseParser.ParseInitializeUpdateResponse(response.Value);
    }

    /// <summary>
    /// Creates the appropriate secure channel protocol handler.
    /// </summary>
    private static Result<ISecureChannelProtocol, SmartCardError> CreateProtocol(
        byte scpId,
        IKeySet keySet)
    {
        return scpId switch
        {
            0x02 => keySet is Scp02KeySet scp02Keys
                ? Result.Success<ISecureChannelProtocol, SmartCardError>(
                    new Scp02Protocol(
                        keySet,
                        new KeyDerivationService(
                            Microsoft.Extensions.Logging.Abstractions.NullLogger<KeyDerivationService>.Instance),
                        Microsoft.Extensions.Logging.Abstractions.NullLogger<Scp02Protocol>.Instance))
                : Result.Failure<ISecureChannelProtocol, SmartCardError>(
                    SmartCardError.InvalidArgument("SCP02 requires Scp02KeySet")),
            
            0x03 => keySet is Scp03KeySet scp03Keys
                ? Result.Success<ISecureChannelProtocol, SmartCardError>(
                    new Scp03Protocol(
                        keySet,
                        new KeyDerivationService(
                            Microsoft.Extensions.Logging.Abstractions.NullLogger<KeyDerivationService>.Instance),
                        Microsoft.Extensions.Logging.Abstractions.NullLogger<Scp03Protocol>.Instance))
                : Result.Failure<ISecureChannelProtocol, SmartCardError>(
                    SmartCardError.InvalidArgument("SCP03 requires Scp03KeySet")),
            
            _ => Result.Failure<ISecureChannelProtocol, SmartCardError>(
                SmartCardError.Unsupported($"Unsupported SCP version: {scpId:X2}"))
        };
    }

    /// <summary>
    /// Sends EXTERNAL AUTHENTICATE command.
    /// </summary>
    private static async Task<Result<bool, SmartCardError>> SendExternalAuthenticateAsync(
        ISecureChannelProtocol protocol,
        SecureChannelContext context,
        SecurityLevel securityLevel,
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken)
    {
        // Create EXTERNAL AUTHENTICATE command
        Result<ExternalAuthenticateCommand, SmartCardError> authCmdResult = 
            protocol.CreateExternalAuthenticateCommand(context, securityLevel);
        
        if (authCmdResult.IsFailure)
        {
            return Result.Failure<bool, SmartCardError>(authCmdResult.Error);
        }

        // Send command
        Result<CommandResponse, SmartCardError> response = 
            await executeCommand(authCmdResult.Value, cancellationToken);
        
        if (response.IsFailure)
        {
            return Result.Failure<bool, SmartCardError>(response.Error);
        }

        if (!response.Value.IsSuccess)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.AuthenticationFailed(
                    $"EXTERNAL AUTHENTICATE failed with SW: {response.Value.StatusWord:X4}"));
        }

        return Result.Success<bool, SmartCardError>(true);
    }

    /// <summary>
    /// Creates the secure channel state after successful authentication.
    /// </summary>
    private static Result<SecureChannelState, SmartCardError> CreateSecureChannelState(
        ISecureChannelProtocol protocol,
        SecureChannelContext context,
        SecurityLevel securityLevel)
    {
        // Determine implementation parameter (SCP02 specific; 0 for SCP03)
        byte implementationParameter = context.ProtocolVersion == 0x02
            ? context.InitializeUpdateResponse.ScpParameter
            : (byte)0x00;

        // Create zero-initialized MAC chaining state sized per protocol (8 for SCP02, 16 for SCP03)
        Result<MacChainingState, SmartCardError> macChainingResult = MacChainingState.CreateZeroInitialized(
            protocolVersion: context.ProtocolVersion,
            implementationParameter: implementationParameter);
        
        if (macChainingResult.IsFailure)
        {
            return Result.Failure<SecureChannelState, SmartCardError>(macChainingResult.Error);
        }

        // Generate 8-byte session ID
        var sessionIdBytes = new byte[8];
        var secureRandom = new Org.BouncyCastle.Security.SecureRandom();
        secureRandom.NextBytes(sessionIdBytes);

        return Result.Success<SecureChannelState, SmartCardError>(
            new SecureChannelState(
                SessionKeys: context.SessionKeys,
                SecurityLevel: securityLevel,
                ProtocolVersion: context.ProtocolVersion,
                MacChaining: macChainingResult.Value,
                EncryptionCounter: 0,
                SessionId: [..sessionIdBytes]));
    }

    /// <summary>
    /// Attempts to establish a secure channel with automatic key discovery.
    /// Useful when the correct key set is unknown.
    /// </summary>
    /// <param name="securityLevel">The desired security level.</param>
    /// <param name="executeCommand">Function to execute APDU commands.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The established secure channel state or an error.</returns>
    public static async Task<Result<SecureChannelState, SmartCardError>> EstablishWithAutoDiscoveryAsync(
        SecurityLevel securityLevel,
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        // Try to discover the working key set
        Result<(IKeySet KeySet, byte ProtocolVersion), SmartCardError> discoveryResult = 
            await CardDiscovery.DiscoverKeySetAsync(executeCommand, null, cancellationToken);
        
        if (discoveryResult.IsFailure)
        {
            return Result.Failure<SecureChannelState, SmartCardError>(discoveryResult.Error);
        }

        (IKeySet keySet, byte _) = discoveryResult.Value;

        // Establish secure channel with discovered key set
        return await EstablishAsync(keySet, securityLevel, executeCommand, cancellationToken);
    }
}
