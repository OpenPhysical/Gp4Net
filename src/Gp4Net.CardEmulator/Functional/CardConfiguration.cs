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
    bool SetStatus,
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
            SetStatus: true,
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
            Ins.SET_STATUS => SetStatus,
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
    public static Result<CardConfiguration, SmartCardError> P71() =>
        LoadBundledProfile("p71_card_1.json");

    /// <summary>Creates a P71 configuration whose declared default protocol is SCP03.</summary>
    public static Result<CardConfiguration, SmartCardError> P71Scp03() =>
        LoadBundledProfile("p71_card_2.json");

    private static Result<CardConfiguration, SmartCardError> LoadBundledProfile(string fileName)
    {
        var profilePath = Path.Combine(
            Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".",
            "Profiles",
            fileName
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
}
