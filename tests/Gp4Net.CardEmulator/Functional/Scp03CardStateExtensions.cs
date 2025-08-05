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
        // This would need to be implemented in the actual CardState class
        // For now, we return the state as-is
        return state;
    }
}