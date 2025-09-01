namespace Gp4Net.CardEmulator.Functional;

public static partial class ScpEnforcer
{
    /// <summary>
    /// Represents command security validation context.
    /// </summary>
    public record CommandSecurityContext(
        byte Instruction,
        byte[] FullCommand,
        CardState CardState,
        SecurityLevelRequirements SecurityRequirements
    );
}
