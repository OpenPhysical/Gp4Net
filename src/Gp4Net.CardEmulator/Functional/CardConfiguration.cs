using System.Collections.Immutable;
using System.IO;
using System.Reflection;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Profiles;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Supported GlobalPlatform instructions with type safety.
/// </summary>
[PublicAPI]
public record SupportedInstructions(
    bool Select,
    bool InitializeUpdate,
    bool ExternalAuthenticate,
    bool GetData,
    bool GetStatus,
    bool Install,
    bool Load,
    bool Delete,
    bool PutKey,
    bool StoreData,
    bool ManageChannel
)
{
    /// <summary>
    /// Standard GP instruction set.
    /// </summary>
    public static SupportedInstructions Standard =>
        new(
            Select: true,
            InitializeUpdate: true,
            ExternalAuthenticate: true,
            GetData: true,
            GetStatus: true,
            Install: true,
            Load: true,
            Delete: true,
            PutKey: true,
            StoreData: true,
            ManageChannel: false
        );

    /// <summary>
    /// Checks if a specific instruction is supported.
    /// </summary>
    public bool IsSupported(byte instruction) =>
        instruction switch
        {
            Apdu.Instructions.SELECT => Select,
            Ins.INITIALIZE_UPDATE => InitializeUpdate,
            Apdu.Instructions.EXTERNAL_AUTHENTICATE => ExternalAuthenticate,
            Apdu.Instructions.GET_DATA => GetData,
            Ins.GET_STATUS => GetStatus,
            Ins.INSTALL => Install,
            Ins.LOAD => Load,
            Ins.DELETE => Delete,
            Ins.PUT_KEY => PutKey,
            Ins.STORE_DATA => StoreData,
            Apdu.Instructions.MANAGE_CHANNEL => ManageChannel,
            _ => false,
        };
}

/// <summary>
/// Immutable configuration defining a card's capabilities and default data.
/// Different card types are represented by different configurations.
/// </summary>
[PublicAPI]
public record CardConfiguration(
    byte[] Atr,
    byte[] IsdAid,
    ImmutableDictionary<byte, IKeySet> StaticKeys,
    ImmutableDictionary<ushort, byte[]> DefaultDataObjects,
    SupportedInstructions SupportedInstructions,
    string CardType,
    byte DefaultScpVersion,
    ScpImplementation DefaultScpImplementation,
    ImmutableList<string> SupportedAlgorithms
)
{
    /// <summary>
    /// Creates a configuration for emulated NXP P71 cards using the JSON profile.
    /// </summary>
    public static Result<CardConfiguration, SmartCardError> P71()
    {
        var profilePath = Path.Combine(
            Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".",
            "Profiles",
            "p71_card_1.json"
        );

        return CardProfileLoader.LoadFromFile(profilePath);
    }

    /// <summary>
    /// Creates a dual-protocol card configuration from JSON profile.
    /// </summary>
    public static Result<CardConfiguration, SmartCardError> DualProtocol()
    {
        var profilePath = Path.Combine(
            Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".",
            "Profiles",
            "dual_protocol_card.json"
        );

        return CardProfileLoader.LoadFromFile(profilePath);
    }

    /// <summary>
    /// Creates an SCP03-first card configuration from JSON profile.
    /// </summary>
    public static Result<CardConfiguration, SmartCardError> Scp03First()
    {
        var profilePath = Path.Combine(
            Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".",
            "Profiles",
            "scp03_card.json"
        );

        return CardProfileLoader.LoadFromFile(profilePath);
    }

    /// <summary>
    /// Creates a new configuration with an additional data object.
    /// </summary>
    public CardConfiguration WithDataObject(ushort tag, byte[] data) =>
        this with
        {
            DefaultDataObjects = DefaultDataObjects.SetItem(tag, data),
        };

    /// <summary>
    /// Creates a new configuration with updated SCP defaults.
    /// </summary>
    public CardConfiguration WithScpDefaults(byte version, ScpImplementation implementation) =>
        this with
        {
            DefaultScpVersion = version,
            DefaultScpImplementation = implementation,
        };

    /// <summary>
    /// Creates a new configuration with an additional key set at specified version.
    /// </summary>
    public CardConfiguration WithKeySet(byte version, IKeySet keySet) =>
        this with
        {
            StaticKeys = StaticKeys.SetItem(version, keySet),
        };

    /// <summary>
    /// Creates a new configuration with updated ATR.
    /// </summary>
    public CardConfiguration WithAtr(byte[] atr) => this with { Atr = atr };

    /// <summary>
    /// Creates a new configuration with updated ISD AID.
    /// </summary>
    public CardConfiguration WithIsdAid(byte[] isdAid) => this with { IsdAid = isdAid };

    /// <summary>
    /// Creates SCP02 key sets using GlobalPlatform Test Keys.
    /// </summary>
    /// <summary>
    /// Creates standard SCP02 test keys for basic testing.
    /// </summary>
    private static ImmutableDictionary<byte, IKeySet> CreateScp02TestKeys() =>
        GpTestKeys
            .CreateScp02TestKeySet(0x01)
            .Map(static keySet => ImmutableDictionary.Create<byte, IKeySet>().Add(0x01, keySet))
            .Match(
                static success => success,
                static error => ImmutableDictionary<byte, IKeySet>.Empty
            );

    /// <summary>
    /// Creates standard SCP03 test keys for basic testing.
    /// </summary>
    private static ImmutableDictionary<byte, IKeySet> CreateScp03TestKeys() =>
        GpTestKeys
            .CreateScp03TestKeySet(0x01)
            .Map(keySet => ImmutableDictionary.Create<byte, IKeySet>().Add(0x01, keySet))
            .Match(success => success, error => ImmutableDictionary<byte, IKeySet>.Empty);
}
