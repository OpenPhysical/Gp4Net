namespace Gp4Net.Pipeline;

/// <summary>
/// Well-known context keys for command execution context.
/// </summary>
public static class ContextKeys
{
    /// <summary>
    /// The current secure channel session.
    /// </summary>
    public const string SecureChannelSession = "SecureChannelSession";

    /// <summary>
    /// The ISD (Issuer Security Domain) AID.
    /// </summary>
    public const string IssuerSecurityDomainAid = "IsdAid";

    /// <summary>
    /// The currently selected application AID.
    /// </summary>
    public const string SelectedApplicationAid = "SelectedAid";

    /// <summary>
    /// The card ATR (Answer To Reset).
    /// </summary>
    public const string CardAtr = "CardAtr";

    /// <summary>
    /// The current security level.
    /// </summary>
    public const string SecurityLevel = "SecurityLevel";

    /// <summary>
    /// The SCP (Secure Channel Protocol) version.
    /// </summary>
    public const string ScpVersion = "ScpVersion";

    /// <summary>
    /// Card capabilities information.
    /// </summary>
    public const string CardCapabilities = "CardCapabilities";

    /// <summary>
    /// The current key set being used.
    /// </summary>
    public const string KeySet = "KeySet";

    /// <summary>
    /// Command execution metadata (timing, retries, etc).
    /// </summary>
    public const string CommandMetadata = "CommandMetadata";

    /// <summary>
    /// Key for the card protocol.
    /// </summary>
    public const string CardProtocol = "CARD_PROTOCOL";

    /// <summary>
    /// The card challenge from INITIALIZE UPDATE.
    /// </summary>
    public const string CardChallenge = "CardChallenge";

    /// <summary>
    /// The secure channel protocol being used.
    /// </summary>
    public const string SecureChannelProtocol = "SecureChannelProtocol";

    /// <summary>
    /// Card production lifecycle data.
    /// </summary>
    public const string CardProductionLifeCycleData = "CardProductionLifeCycleData";

    /// <summary>
    /// General card data.
    /// </summary>
    public const string CardData = "CardData";

    /// <summary>
    /// Key information template.
    /// </summary>
    public const string KeyInformationTemplate = "KeyInformationTemplate";

    /// <summary>
    /// The selected AID (alias for SelectedApplicationAid).
    /// </summary>
    public const string SelectedAid = "SelectedAid";
}
