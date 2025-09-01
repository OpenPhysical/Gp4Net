using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Applications;

/// <summary>
/// Represents a GlobalPlatform application capable of processing APDU commands.
/// Each application is responsible for its own command processing according to GP specifications.
/// Reference: GlobalPlatform Card Specification v2.3.1 Section 6.4
/// </summary>
[PublicAPI]
public interface IApplication
{
    /// <summary>
    /// Application Identifier (AID) - immutable.
    /// Reference: GP Card Specification v2.3.1 Section 5.1.1
    /// </summary>
    ImmutableArray<byte> Aid { get; }
    
    /// <summary>
    /// Application name for identification.
    /// </summary>
    string Name { get; }
    
    /// <summary>
    /// Current lifecycle state per GP Card Specification Table 11-1.
    /// </summary>
    LifecycleState LifecycleState { get; }
    
    /// <summary>
    /// Application privileges per GP Card Specification Table 8-1.
    /// </summary>
    ApplicationPrivileges Privileges { get; }
    
    /// <summary>
    /// Associated Security Domain AID.
    /// Reference: GP Card Specification v2.3.1 Section 6.4.2
    /// </summary>
    ImmutableArray<byte> AssociatedSecurityDomainAid { get; }
    
    /// <summary>
    /// Processes an APDU command in the context of this application.
    /// Returns updated application instance and APDU response.
    /// Reference: GP Card Specification v2.3.1 Section 11
    /// </summary>
    /// <param name="command">APDU command to process</param>
    /// <param name="cardState">Current card state (for secure channel, etc.)</param>
    /// <param name="rngContext">RNG context for cryptographic operations</param>
    /// <returns>Updated application and APDU response, or error</returns>
    Result<(IApplication UpdatedApplication, ApduResponse Response), SmartCardError> ProcessCommand(
        byte[] command,
        CardState cardState,
        IRngContext rngContext);
    
    /// <summary>
    /// Validates whether this application can process the given instruction.
    /// Used for APDU routing validation.
    /// </summary>
    /// <param name="instruction">INS byte from APDU</param>
    /// <returns>True if application supports this instruction</returns>
    bool SupportsInstruction(byte instruction);
    
    /// <summary>
    /// Gets required privileges for the given instruction.
    /// Used for access control validation per GP Card Specification Table 11-2.
    /// </summary>
    /// <param name="instruction">INS byte from APDU</param>
    /// <returns>Required privileges, or None if instruction not supported</returns>
    Maybe<ApplicationPrivileges> GetRequiredPrivileges(byte instruction);
    
    /// <summary>
    /// Updates application lifecycle state.
    /// Returns new application instance or error if transition invalid.
    /// Reference: GP Card Specification v2.3.1 Section 11.4
    /// </summary>
    /// <param name="newState">Target lifecycle state</param>
    /// <returns>Updated application or error</returns>
    Result<IApplication, SmartCardError> WithLifecycleState(LifecycleState newState);
    
    /// <summary>
    /// Creates a new instance with updated privileges.
    /// Used for privilege management operations.
    /// </summary>
    /// <param name="newPrivileges">Updated privileges</param>
    /// <returns>New application instance</returns>
    IApplication WithPrivileges(ApplicationPrivileges newPrivileges);
}