namespace Gp4Net.Pipeline;

/// <summary>
/// Well-known context keys for command execution context.
/// </summary>
public static class ContextKeys
{
    /// <summary>
    /// The current secure channel session.
    /// </summary>
    public const string SECURE_CHANNEL_SESSION = "SecureChannelSession";

    /// <summary>
    /// The ISD (Issuer Security Domain) AID.
    /// </summary>
    public const string ISSUER_SECURITY_DOMAIN_AID = "IsdAid";

    /// <summary>
    /// The currently selected application AID.
    /// </summary>
    public const string SELECTED_APPLICATION_AID = "SelectedAid";

    /// <summary>
    /// The card ATR (Answer To Reset).
    /// </summary>
    public const string CARD_ATR = "CardAtr";

    /// <summary>
    /// The current security level.
    /// </summary>
    public const string SECURITY_LEVEL = "SecurityLevel";

    /// <summary>
    /// The SCP (Secure Channel Protocol) version.
    /// </summary>
    public const string SCP_VERSION = "ScpVersion";

    /// <summary>
    /// Card capabilities information.
    /// </summary>
    public const string CARD_CAPABILITIES = "CardCapabilities";

    /// <summary>
    /// The current key set being used.
    /// </summary>
    public const string KEY_SET = "KeySet";

    /// <summary>
    /// Command execution metadata (timing, retries, etc).
    /// </summary>
    public const string COMMAND_METADATA = "CommandMetadata";

    /// <summary>
    /// Key for the card protocol.
    /// </summary>
    public const string CARD_PROTOCOL = "CARD_PROTOCOL";

    /// <summary>
    /// The card challenge from INITIALIZE UPDATE.
    /// </summary>
    public const string CARD_CHALLENGE = "CardChallenge";

    /// <summary>
    /// The secure channel protocol being used.
    /// </summary>
    public const string SECURE_CHANNEL_PROTOCOL = "SecureChannelProtocol";

    /// <summary>
    /// Card production lifecycle data.
    /// </summary>
    public const string CARD_PRODUCTION_LIFE_CYCLE_DATA = "CardProductionLifeCycleData";

    /// <summary>
    /// General card data.
    /// </summary>
    public const string CARD_DATA = "CardData";

    /// <summary>
    /// Key information template.
    /// </summary>
    public const string KEY_INFORMATION_TEMPLATE = "KeyInformationTemplate";

    /// <summary>
    /// The selected AID (alias for SelectedApplicationAid).
    /// </summary>
    public const string SELECTED_AID = "SelectedAid";
}
