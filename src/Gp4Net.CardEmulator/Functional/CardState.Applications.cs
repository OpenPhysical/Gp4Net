using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Applications;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Extension to CardState for application-based functionality.
/// </summary>
public partial record CardState
{
    /// <summary>
    /// Application registry for application-based command routing.
    /// When present, commands are routed through applications instead of the legacy switch statement.
    /// </summary>
    public Maybe<ApplicationRegistry> ApplicationRegistry { get; init; } = Maybe<ApplicationRegistry>.None;
    
    /// <summary>
    /// Checks if the card has a secure channel established.
    /// Convenience property for applications to check security status.
    /// </summary>
    public bool HasSecureChannel => IsSecureChannelEstablished;
}