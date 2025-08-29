using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Security;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Extension methods for CardState to support SCP03-specific operations.
/// </summary>
[PublicAPI]
public static class Scp03CardStateExtensions
{
    /// <summary>
    /// Updates the MAC chaining value for SCP03.
    /// </summary>
    public static CardState WithMacChaining(this CardState state, byte[] macChaining)
    {
        // Complete implementation: Update card state with new MAC chaining value
        // Using functional approach to return new state with updated chaining value
        return state with 
        { 
            SecureChannel = state.SecureChannel.Map(sc => 
            {
                Result<MacChainingState, SmartCardError> macChainingResult = MacChainingState.Create(macChaining, sc.ProtocolVersion, 0x00);
                return macChainingResult.Match(
                    macChain => sc with { MacChaining = macChain },
                    _ => sc);
            })
        };
    }
}