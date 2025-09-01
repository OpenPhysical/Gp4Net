namespace Gp4Net.CardEmulator.Functional;

public static partial class ScpEnforcer
{
    /// <summary>
    /// Represents security level requirements for a command per GP Appendix E.
    /// </summary>
    public record SecurityLevelRequirements(
        bool RequiresSecureChannel,
        bool RequiresCommandMac,
        bool RequiresCommandEncryption,
        bool RequiresResponseMac,
        bool RequiresResponseEncryption
    );
}
