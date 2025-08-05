using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Protocol;

/// <summary>
/// Interface for SCP protocol services using C# 11 static virtual members.
/// Provides type-safe, compile-time polymorphism for protocol-specific operations.
/// </summary>
/// <typeparam name="TSelf">The implementing type (CRTP pattern).</typeparam>
[PublicAPI]
public interface IScpProtocolService<TSelf> where TSelf : IScpProtocolService<TSelf>
{
    /// <summary>
    /// The protocol version identifier (0x02 for SCP02, 0x03 for SCP03).
    /// </summary>
    static abstract byte ProtocolVersion { get; }
    
    /// <summary>
    /// The size of the MAC in bytes (typically 8 for truncated MAC).
    /// </summary>
    static abstract int MacSize { get; }
    
    /// <summary>
    /// The size of the MAC chaining value in bytes (8 for SCP02, 16 for SCP03).
    /// </summary>
    static abstract int ChainingValueSize { get; }
    
    // Protocol-specific operations that must be implemented by each protocol
    
    /// <summary>
    /// Calculates command MAC (C-MAC) over the provided command.
    /// </summary>
    /// <param name="command">The command APDU to calculate MAC over.</param>
    /// <param name="macKey">The MAC key (S-MAC for session, static MAC for authentication).</param>
    /// <param name="chainingValue">The current MAC chaining value.</param>
    /// <returns>The calculated MAC bytes (truncated to MacSize).</returns>
    static abstract Result<byte[], SmartCardError> CalculateCommandMac(
        byte[] command, 
        byte[] macKey, 
        byte[] chainingValue);
    
    /// <summary>
    /// Calculates response MAC (R-MAC) over the provided response.
    /// </summary>
    /// <param name="response">The response data including status word.</param>
    /// <param name="rMacKey">The R-MAC key (S-RMAC).</param>
    /// <param name="chainingValue">The current MAC chaining value.</param>
    /// <returns>The calculated R-MAC bytes (truncated to MacSize).</returns>
    static abstract Result<byte[], SmartCardError> CalculateResponseMac(
        byte[] response,
        byte[] rMacKey,
        byte[] chainingValue);
    
    /// <summary>
    /// Calculates the initial MAC chaining value from the EXTERNAL AUTHENTICATE command.
    /// This becomes the starting chaining value for all subsequent MAC operations.
    /// </summary>
    /// <param name="command">The EXTERNAL AUTHENTICATE command.</param>
    /// <param name="macKey">The MAC key used for the command.</param>
    /// <returns>The full MAC that becomes the initial chaining value.</returns>
    static abstract Result<byte[], SmartCardError> CalculateInitialMacChainingValue(
        ExternalAuthenticateCommand command,
        byte[] macKey);

    /// <summary>
    /// Updates the MAC chaining state after a C-MAC calculation.
    /// </summary>
    /// <param name="current">The current MAC chaining state.</param>
    /// <param name="commandData">The command data that was MAC'd.</param>
    /// <param name="macKey">The MAC key.</param>
    /// <returns>The updated MAC chaining state.</returns>
    static abstract Result<Security.MacChainingState, SmartCardError> UpdateChainingAfterCMac(
        Security.MacChainingState current,
        byte[] commandData,
        byte[] macKey);

    /// <summary>
    /// Updates the MAC chaining state after an R-MAC calculation.
    /// Per GlobalPlatform Card Specification v2.3.1 Section 6.2.5:
    /// "The MAC chaining value shall be updated with the full MAC only after 
    /// each C-MAC generation on an APDU command."
    /// R-MAC generation does not update the chaining value.
    /// </summary>
    /// <param name="current">The current MAC chaining state.</param>
    /// <param name="responseData">The response data that was MAC'd.</param>
    /// <param name="rmacKey">The R-MAC key.</param>
    /// <returns>The MAC chaining state (unchanged for SCP03).</returns>
    static abstract Result<Security.MacChainingState, SmartCardError> UpdateChainingAfterRMac(
        Security.MacChainingState current,
        byte[] responseData,
        byte[] rmacKey);
    
    /// <summary>
    /// Applies command security (C-MAC and/or C-ENC) to a command.
    /// </summary>
    /// <param name="command">The original command APDU.</param>
    /// <param name="securityLevel">The security level specifying which security to apply.</param>
    /// <param name="sessionKeys">The session keys.</param>
    /// <param name="chainingValue">The current MAC chaining value.</param>
    /// <returns>The secured command and updated MAC chaining value.</returns>
    static abstract Result<(byte[] securedCommand, byte[] newChainingValue), SmartCardError> ApplyCommandSecurity(
        byte[] command,
        SecurityLevel securityLevel,  
        SessionKeys sessionKeys,
        byte[] chainingValue);
    
    /// <summary>
    /// Applies response security (R-MAC and/or R-ENC) to a response.
    /// </summary>
    /// <param name="response">The original response data including status word.</param>
    /// <param name="securityLevel">The security level specifying which security to apply.</param>
    /// <param name="sessionKeys">The session keys.</param>
    /// <param name="chainingValue">The current MAC chaining value.</param>
    /// <param name="encryptionCounter">The current encryption counter (for SCP03).</param>
    /// <returns>The secured response and updated MAC chaining value.</returns>
    static abstract Result<(byte[] securedResponse, byte[] newChainingValue), SmartCardError> ApplyResponseSecurity(
        byte[] response,
        SecurityLevel securityLevel,
        SessionKeys sessionKeys, 
        byte[] chainingValue,
        uint encryptionCounter = 0);
    
    // Common operations that can be shared between protocols (with default implementations)
    
    /// <summary>
    /// Processes an INITIALIZE UPDATE response and creates a secure channel context.
    /// Default implementation provides common validation logic.
    /// </summary>
    /// <param name="response">The INITIALIZE UPDATE response.</param>
    /// <param name="hostChallenge">The host challenge that was sent.</param>
    /// <param name="keySet">The key set to use for session key derivation.</param>
    /// <returns>A secure channel context for further protocol operations.</returns>
    static virtual Result<SecureChannelContext, SmartCardError> ProcessInitializeUpdate(
        InitializeUpdateResponse response,
        byte[] hostChallenge,
        IKeySet keySet)
    {
        // Default implementation with common validation
        // Specific protocols can override if needed
        
        if (response == null)
        {
            return SmartCardError.InvalidArgument("Response cannot be null");
        }

        if (hostChallenge == null || hostChallenge.Length != 8)
        {
            return SmartCardError.InvalidArgument("Host challenge must be 8 bytes");
        }

        if (keySet == null)
        {
            return SmartCardError.InvalidArgument("Key set cannot be null");
        }

        if (response.ScpId != TSelf.ProtocolVersion)
        {
            return SmartCardError.InvalidResponse(
                $"Expected {TSelf.ProtocolVersion:X2} but received {response.ScpId:X2}");
        }

        // Protocol-specific implementations should override this method
        // to add their own key derivation and cryptogram verification logic
        return SmartCardError.UnexpectedError("ProcessInitializeUpdate must be implemented by protocol");
    }
    
    /// <summary>
    /// Creates an EXTERNAL AUTHENTICATE command for the specified security level.
    /// Default implementation provides common command structure logic.
    /// </summary>
    /// <param name="context">The secure channel context from INITIALIZE UPDATE.</param>
    /// <param name="securityLevel">The requested security level.</param>
    /// <returns>The EXTERNAL AUTHENTICATE command with cryptogram and MAC.</returns>
    static virtual Result<ExternalAuthenticateCommand, SmartCardError> CreateExternalAuthenticate(
        SecureChannelContext context,
        SecurityLevel securityLevel)
    {
        if (context == null)
        {
            return SmartCardError.InvalidArgument("Context cannot be null");
        }

        // Protocol-specific implementations should override this method
        // to add their own cryptogram and MAC calculation logic
        return SmartCardError.UnexpectedError("CreateExternalAuthenticate must be implemented by protocol");
    }
}