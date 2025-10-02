namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Extension to CardState for application-based functionality.
/// </summary>
public partial record CardState
{
    /// <summary>
    /// Checks if the card has a secure channel established.
    /// Convenience property for applications to check security status.
    /// </summary>
    public bool HasSecureChannel => IsSecureChannelEstablished;
}
