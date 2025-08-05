using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Protocol;
using JetBrains.Annotations;

namespace Gp4Net.Domain.Security;

/// <summary>
/// Provides functional MAC operations for secure channel protocols.
/// All methods are pure functions that return new state without side effects.
/// </summary>
[PublicAPI]
public static class MacOperations
{
    /// <summary>
    /// Calculates C-MAC and updates the MAC chaining state.
    /// </summary>
    /// <typeparam name="TProtocol">The protocol service type.</typeparam>
    /// <param name="commandData">The command data to MAC.</param>
    /// <param name="macKey">The MAC key (S-MAC).</param>
    /// <param name="chainingState">The current MAC chaining state.</param>
    /// <returns>The calculated MAC and updated chaining state.</returns>
    public static Result<(byte[] mac, MacChainingState newState), SmartCardError> 
        CalculateCMac<TProtocol>(
            byte[] commandData,
            byte[] macKey,
            MacChainingState chainingState) 
        where TProtocol : IScpProtocolService<TProtocol>
    {
        if (commandData == null)
        {
            return SmartCardError.InvalidArgument("Command data cannot be null");
        }

        if (macKey == null)
        {
            return SmartCardError.InvalidArgument("MAC key cannot be null");
        }

        if (chainingState == null)
        {
            return SmartCardError.InvalidArgument("Chaining state cannot be null");
        }

        // Calculate the MAC
        return TProtocol.CalculateCommandMac(commandData, macKey, chainingState.ToArray())
            .Bind(mac => 
                // Update the chaining state
                TProtocol.UpdateChainingAfterCMac(chainingState, commandData, macKey)
                    .Map(newState => (mac, newState)));
    }

    /// <summary>
    /// Calculates R-MAC without updating the MAC chaining state (per specification).
    /// </summary>
    /// <typeparam name="TProtocol">The protocol service type.</typeparam>
    /// <param name="responseData">The response data to MAC.</param>
    /// <param name="rmacKey">The R-MAC key (S-RMAC).</param>
    /// <param name="chainingState">The current MAC chaining state.</param>
    /// <returns>The calculated R-MAC and the same chaining state.</returns>
    public static Result<(byte[] mac, MacChainingState unchangedState), SmartCardError>
        CalculateRMac<TProtocol>(
            byte[] responseData,
            byte[] rmacKey,
            MacChainingState chainingState)
        where TProtocol : IScpProtocolService<TProtocol>
    {
        if (responseData == null)
        {
            return SmartCardError.InvalidArgument("Response data cannot be null");
        }

        if (rmacKey == null)
        {
            return SmartCardError.InvalidArgument("R-MAC key cannot be null");
        }

        if (chainingState == null)
        {
            return SmartCardError.InvalidArgument("Chaining state cannot be null");
        }

        // Calculate the R-MAC
        return TProtocol.CalculateResponseMac(responseData, rmacKey, chainingState.ToArray())
            .Bind(mac =>
                // Check if chaining should be updated (protocol/implementation specific)
                TProtocol.UpdateChainingAfterRMac(chainingState, responseData, rmacKey)
                    .Map(newState => (mac, newState)));
    }

    /// <summary>
    /// Creates an initial MAC chaining state from protocol and implementation parameters.
    /// </summary>
    /// <param name="protocolVersion">The protocol version (SCP02 or SCP03).</param>
    /// <param name="implementationParameter">The implementation parameter (i-value).</param>
    /// <param name="initialValue">Optional initial chaining value. If null, creates zero-initialized.</param>
    /// <returns>A Result containing the initial MAC chaining state.</returns>
    public static Result<MacChainingState, SmartCardError> CreateInitialChainingState(
        byte protocolVersion,
        byte implementationParameter = 0x00,
        byte[] initialValue = null)
    {
        if (initialValue != null)
        {
            return MacChainingState.Create(initialValue, protocolVersion, implementationParameter);
        }

        return MacChainingState.CreateZeroInitialized(protocolVersion, implementationParameter);
    }

    /// <summary>
    /// Dispatches MAC calculation to the appropriate protocol implementation based on protocol version.
    /// </summary>
    /// <param name="protocolVersion">The protocol version.</param>
    /// <param name="commandData">The command data to MAC.</param>
    /// <param name="macKey">The MAC key.</param>
    /// <param name="chainingState">The current MAC chaining state.</param>
    /// <returns>The calculated MAC and updated chaining state.</returns>
    public static Result<(byte[] mac, MacChainingState newState), SmartCardError> 
        CalculateCMacForProtocol(
            byte protocolVersion,
            byte[] commandData,
            byte[] macKey,
            MacChainingState chainingState)
    {
        return protocolVersion switch
        {
            ProtocolIdentifiers.Scp03 => CalculateCMac<Scp03ProtocolService>(commandData, macKey, chainingState),
            ProtocolIdentifiers.Scp02 => CalculateCMac<Scp02ProtocolService>(commandData, macKey, chainingState),
            _ => SmartCardError.InvalidArgument($"Unsupported protocol version: 0x{protocolVersion:X2}")
        };
    }

    /// <summary>
    /// Dispatches R-MAC calculation to the appropriate protocol implementation.
    /// </summary>
    /// <param name="protocolVersion">The protocol version.</param>
    /// <param name="responseData">The response data to MAC.</param>
    /// <param name="rmacKey">The R-MAC key.</param>
    /// <param name="chainingState">The current MAC chaining state.</param>
    /// <returns>The calculated R-MAC and potentially updated chaining state.</returns>
    public static Result<(byte[] mac, MacChainingState newState), SmartCardError>
        CalculateRMacForProtocol(
            byte protocolVersion,
            byte[] responseData,
            byte[] rmacKey,
            MacChainingState chainingState)
    {
        return protocolVersion switch
        {
            ProtocolIdentifiers.Scp03 => CalculateRMac<Scp03ProtocolService>(responseData, rmacKey, chainingState),
            ProtocolIdentifiers.Scp02 => CalculateRMac<Scp02ProtocolService>(responseData, rmacKey, chainingState),
            _ => SmartCardError.InvalidArgument($"Unsupported protocol version: 0x{protocolVersion:X2}")
        };
    }
}