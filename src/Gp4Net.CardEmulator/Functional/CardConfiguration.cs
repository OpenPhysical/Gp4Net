using System;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.DataObjects;
using Gp4Net.Domain.Keys;
using Gp4Net.Constants;
using Gp4Net.Services;
using Gp4Net.Services.GlobalPlatform;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.CardEmulator.Functional;

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
    ImmutableList<byte> SupportedInstructions,
    string CardType,
    byte DefaultScpVersion,
    ScpImplementation DefaultScpImplementation,
    ImmutableList<string> SupportedAlgorithms
)
{
    /// <summary>
    /// Creates a configuration for NXP P71 cards based on public specifications.
    /// This provides a programmatic configuration complementing the JSON profiles.
    /// JSON profiles are preferred for complex scenarios, this method for simple testing.
    /// </summary>
    public static CardConfiguration P71() =>
        new(
            Atr: Apdu.WellKnownIdentifiers.NxpP71Atr,
            IsdAid: Apdu.WellKnownIdentifiers.StandardGpIsdAid,
            StaticKeys: CreateP71Keys(),
            DefaultDataObjects: CreateP71DataObjects(),
            SupportedInstructions: CreateP71SupportedInstructions(),
            CardType: "NXP P71",
            DefaultScpVersion: Constants.Constants.GlobalPlatform.Protocols.Scp02,
            DefaultScpImplementation: ScpImplementation.Scp02I15,
            SupportedAlgorithms: CardConfigurationAlgorithms.CreateStandardAlgorithms()
        );

    /// <summary>
    /// Creates a generic JavaCard configuration for testing.
    /// </summary>
    public static CardConfiguration Generic() =>
        new(
            Atr: Apdu.WellKnownIdentifiers.GenericJavaCardAtr,
            IsdAid: Apdu.WellKnownIdentifiers.StandardGpIsdAid,
            StaticKeys: CreateScp02TestKeys(),
            DefaultDataObjects: CreateGenericDataObjects(),
            SupportedInstructions: CreateStandardGpInstructions(),
            CardType: "Generic JavaCard",
            DefaultScpVersion: Constants.Constants.GlobalPlatform.Protocols.Scp02,
            DefaultScpImplementation: ScpImplementation.Scp02I15,
            SupportedAlgorithms: CardConfigurationAlgorithms.CreateStandardAlgorithms()
        );

    /// <summary>
    /// Creates a minimal JavaCard configuration supporting only SELECT and GET DATA commands.
    /// Used for testing instruction validation and unsupported command handling.
    /// </summary>
    public static CardConfiguration Minimal() =>
        new(
            Atr: Apdu.WellKnownIdentifiers.GenericJavaCardAtr,
            IsdAid: Apdu.WellKnownIdentifiers.StandardGpIsdAid,
            StaticKeys: CreateScp02TestKeys(),
            DefaultDataObjects: CreateGenericDataObjects(),
            SupportedInstructions: CreateMinimalInstructions(),
            CardType: "Minimal JavaCard",
            DefaultScpVersion: Constants.Constants.GlobalPlatform.Protocols.Scp02,
            DefaultScpImplementation: ScpImplementation.Scp02I15,
            SupportedAlgorithms: CardConfigurationAlgorithms.CreateMinimalAlgorithms()
        );

    /// <summary>
    /// Creates a dual-protocol card configuration supporting both SCP02 and SCP03.
    /// Defaults to SCP02 i=15 but supports SCP03 i=70 as well.
    /// </summary>
    public static CardConfiguration DualProtocol() =>
        new(
            Atr: Convert.FromHexString("3BD518FF8191FE1FC38073C821100A"),
            IsdAid: Constants.Constants.GlobalPlatform.Aids.IsdDefault,
            StaticKeys: CreateDualProtocolKeys(),
            DefaultDataObjects: CreateDualProtocolDataObjects().Value,
            SupportedInstructions: CreateStandardGpInstructions(),
            CardType: "Dual Protocol (SCP02/SCP03)",
            DefaultScpVersion: Constants.Constants.GlobalPlatform.Protocols.Scp02, // Default to SCP02 for compatibility
            DefaultScpImplementation: ScpImplementation.Scp02I15,
            SupportedAlgorithms: CardConfigurationAlgorithms.CreateDualProtocolAlgorithms()
        );

    /// <summary>
    /// Creates an SCP03-first card configuration.
    /// Defaults to SCP03 i=70 but supports SCP02 fallback.
    /// </summary>
    public static CardConfiguration Scp03First() =>
        new(
            Atr: Convert.FromHexString("3BD518FF8191FE1FC38073C821100A"),
            IsdAid: Constants.Constants.GlobalPlatform.Aids.IsdDefault,
            StaticKeys: CreateDualProtocolKeys(),
            DefaultDataObjects: CreateScp03DataObjects().Value,
            SupportedInstructions: CreateStandardGpInstructions(),
            CardType: "SCP03-First Card",
            DefaultScpVersion: Constants.Constants.GlobalPlatform.Protocols.Scp03, // Default to SCP03
            DefaultScpImplementation: ScpImplementation.Scp03I70,
            SupportedAlgorithms: CardConfigurationAlgorithms.CreateScp03Algorithms()
        );

    /// <summary>
    /// Creates a new configuration with an additional data object.
    /// </summary>
    public CardConfiguration WithDataObject(ushort tag, byte[] data) =>
        this with
        {
            DefaultDataObjects = DefaultDataObjects.SetItem(tag, data),
        };

    /// <summary>
    /// Creates a new configuration with additional supported instruction.
    /// </summary>
    public CardConfiguration WithInstruction(byte instruction) =>
        this with
        {
            SupportedInstructions = SupportedInstructions.Contains(instruction)
                ? SupportedInstructions
                : SupportedInstructions.Add(instruction),
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

    // NOTE: This complements JSON profiles. Programmatic configs are used for simple testing
    // scenarios where JSON parsing overhead is unnecessary. JSON profiles provide comprehensive
    // card metadata and complex configurations. Both serve different architectural purposes.
    private static ImmutableDictionary<byte, IKeySet> CreateP71Keys()
    {
        // Use centralized test keys from GpTestKeys for consistency
        return GpTestKeys.CreateScp02TestKeySet(0x01)
            .Bind(keySet01 =>
                GpTestKeys.CreateScp02TestKeySet(0xFF)
                    .Map(keySetFF =>
                        ImmutableDictionary
                            .Create<byte, IKeySet>()
                            .Add(0x01, (IKeySet)keySet01)
                            .Add(0xFF, (IKeySet)keySetFF)
                    )
            )
            .Match(
                success => success,
                error => ImmutableDictionary.Create<byte, IKeySet>() // Return empty on error
            );
    }


    private static ImmutableDictionary<ushort, byte[]> CreateP71DataObjects()
    {
        // Define P71 card capabilities (SCP02 only)
        var supportedScp02 = ImmutableList.Create(
            ScpImplementation.Scp02I15, // 0x15
            ScpImplementation.Scp02I04, // 0x04
            ScpImplementation.Scp02I1A  // 0x1A
        );

        var supportedScp03 = ImmutableList<ScpImplementation>.Empty;

        var keyTypes = ImmutableList.Create(
            new KeyTypeAndLength(0x80, 0x10), // DES
            new KeyTypeAndLength(0x81, 0x10), // DES-ECB
            new KeyTypeAndLength(0x82, 0x10)  // DES-MAC
        );

        // Create key information template for P71
        var keyInfoTemplate = new KeyInfoTemplate
        {
            KeyVersionNumber = Maybe<byte>.From((byte)0x01),
            KeyIdentifier = Maybe<byte>.From((byte)0x00),
            KeyTypesAndLengths = keyTypes.ToImmutableArray()
        };

        // Create security domain info
        var securityDomainInfo = new SecurityDomainInfo
        {
            Oid = Aids.IsdDefault,
            ImageData = Convert.FromHexString("A000000151535343"),
            LifeCycleData = Convert.FromHexString("03"),
        };

        return DataGeneration
            .BuildCardCapabilities(supportedScp02, supportedScp03, keyTypes)
            .Bind(cardCap =>
                KeyInfoTemplateCodec
                    .Encode(keyInfoTemplate)
                    .Bind(keyInfo =>
                        SecurityDomainInfoCodec
                            .Encode(securityDomainInfo)
                            .Map(secDomain =>
                                CreateDataObjectsDictionary(cardCap, keyInfo, secDomain)
                            )
                    )
            )
            .Match(
                success => success,
                error => ImmutableDictionary.Create<ushort, byte[]>() // Return empty on error
            );
    }

    // NOTE: Programmatic data objects provide minimal test data for unit testing.
    // JSON profiles contain comprehensive card metadata including production CPLC data.
    // These serve complementary purposes: simple testing vs. realistic card simulation.
    private static ImmutableDictionary<ushort, byte[]> CreateDataObjectsDictionary(
        byte[] cardCapabilities,
        byte[] keyInfo,
        byte[] securityDomain
    )
    {
        return ImmutableDictionary
            .Create<ushort, byte[]>()
            // CPLC Data (Card Production Life Cycle)
            .Add(
                0x9F7F,
                Convert.FromHexString(
                    "4790D3214700000000002345558919204839000000000000000018649535383931390000000000000000"
                )
            )
            // Card Capabilities - legacy format for 0x67
            .Add(
                0x0067,
                Convert.FromHexString(
                    "6728A00D800103810500102060708201078103E5BEC082031E030083010284010285017B86010C87017B"
                )
            )
            // Card Capabilities - using codec for 0x66
            .Add(0x0066, cardCapabilities)
            // Key Information Template - using codec
            .Add(0x00E0, keyInfo)
            // Security Domain Info - using codec
            .Add(0x00C1, securityDomain)
            // Key Diversification Data
            .Add(0x00CF, Convert.FromHexString("CF0A03700000000000000000"));
    }

    private static ImmutableList<byte> CreateP71SupportedInstructions()
    {
        return ImmutableList.Create<byte>(
            Constants.Constants.GlobalPlatform.Ins.Select, // SELECT
            Constants.Constants.GlobalPlatform.Ins.InitializeUpdate, // INITIALIZE UPDATE
            Constants.Constants.GlobalPlatform.Ins.ExternalAuthenticate, // EXTERNAL AUTHENTICATE
            Constants.Constants.GlobalPlatform.Ins.GetData, // GET DATA
            Constants.Constants.GlobalPlatform.Ins.GetStatus, // GET STATUS
            Constants.Constants.GlobalPlatform.Ins.Install, // INSTALL
            Constants.Constants.GlobalPlatform.Ins.Load, // LOAD
            Constants.Constants.GlobalPlatform.Ins.Delete, // DELETE
            Constants.Constants.GlobalPlatform.Ins.PutKey, // PUT KEY
            Constants.Constants.GlobalPlatform.Ins.StoreData, // STORE DATA
            0xFE // P71 IDENTIFY (proprietary)
        );
    }

    /// <summary>
    /// Creates SCP02 key sets using GlobalPlatform Test Keys.
    /// Per GP 2.3.1 Section 11.1.1: These are the standard test keys for SCP02 protocol testing.
    /// </summary>
    public static ImmutableDictionary<byte, IKeySet> CreateScp02TestKeys()
    {
        // Use centralized test keys from GpTestKeys for consistency
        return GpTestKeys.CreateScp02TestKeySet(0x01)
            .Map(keySet => ImmutableDictionary.Create<byte, IKeySet>().Add(0x01, (IKeySet)keySet))
            .GetValueOrDefault(ImmutableDictionary<byte, IKeySet>.Empty);
    }

    /// <summary>
    /// Creates SCP03 key sets using the same GlobalPlatform Test Keys.
    /// Per GP 2.3.1 Section 11.1.1: Same key material as SCP02 but in SCP03 key set format.
    /// </summary>
    public static ImmutableDictionary<byte, IKeySet> CreateScp03TestKeys()
    {
        // Use centralized test keys from GpTestKeys for consistency
        return GpTestKeys.CreateScp03TestKeySet(0x01)
            .Map(keySet => ImmutableDictionary.Create<byte, IKeySet>().Add(0x01, (IKeySet)keySet))
            .GetValueOrDefault(ImmutableDictionary<byte, IKeySet>.Empty);
    }

    /// <summary>
    /// Creates dual-protocol key sets supporting both SCP02 and SCP03 with GlobalPlatform Test Keys.
    /// Per GP 2.3.1 Section 11.1.1: Provides proper type safety for both protocols using same key material.
    /// </summary>
    public static ImmutableDictionary<byte, IKeySet> CreateDualProtocolTestKeys()
    {
        // Use centralized test keys from GpTestKeys for both protocols
        return GpTestKeys.CreateScp02TestKeySet(0x01)
            .Bind(scp02KeySet =>
                GpTestKeys.CreateScp03TestKeySet(0x02)
                    .Map(scp03KeySet =>
                        ImmutableDictionary
                            .Create<byte, IKeySet>()
                            .Add(0x01, (IKeySet)scp02KeySet)
                            .Add(0x02, (IKeySet)scp03KeySet)
                    )
            )
            .GetValueOrDefault(ImmutableDictionary<byte, IKeySet>.Empty);
    }

    public static ImmutableDictionary<ushort, byte[]> CreateGenericDataObjects()
    {
        return ImmutableDictionary
            .Create<ushort, byte[]>()
            // Basic card data
            .Add(0x0066, [0x66, 0x04, 0x01, 0x00, 0x00, 0x00])
            // Basic capabilities
            .Add(0x0067, [0x67, 0x04, 0x81, 0x01, 0x00, 0x01]);
    }

    public static ImmutableList<byte> CreateStandardGpInstructions()
    {
        return ImmutableList.Create<byte>(
            Constants.Constants.GlobalPlatform.Ins.Select, // SELECT
            Constants.Constants.GlobalPlatform.Ins.InitializeUpdate, // INITIALIZE UPDATE
            Constants.Constants.GlobalPlatform.Ins.ExternalAuthenticate, // EXTERNAL AUTHENTICATE
            Constants.Constants.GlobalPlatform.Ins.GetData, // GET DATA
            Constants.Constants.GlobalPlatform.Ins.GetStatus, // GET STATUS
            Constants.Constants.GlobalPlatform.Ins.Install, // INSTALL
            Constants.Constants.GlobalPlatform.Ins.Load, // LOAD
            Constants.Constants.GlobalPlatform.Ins.Delete, // DELETE
            Constants.Constants.GlobalPlatform.Ins.PutKey // PUT KEY
        );
    }

    /// <summary>
    /// Creates a minimal instruction set supporting only SELECT and GET DATA commands.
    /// Used for testing instruction validation and unsupported command handling.
    /// </summary>

    public static ImmutableList<byte> CreateMinimalInstructions()
    {
        // Minimal instruction set for basic GlobalPlatform compliance
        // SELECT (0xA4) is required by ISO 7816 for applet selection
        // GET DATA (0xCA) is required for card information retrieval
        return ImmutableList.Create<byte>(
            Constants.Constants.GlobalPlatform.Ins.Select, // SELECT - ISO 7816 required for all smart cards
            Constants.Constants.GlobalPlatform.Ins.GetData  // GET DATA - Basic card information retrieval
        );
    }

    /// <summary>
    /// Creates keys for dual-protocol support (both SCP02 and SCP03).
    /// </summary>
    private static ImmutableDictionary<byte, IKeySet> CreateDualProtocolKeys()
    {
        // Use the new dual protocol method which follows functional programming patterns
        return CreateDualProtocolTestKeys();
    }

    /// <summary>
    /// Creates data objects for dual-protocol cards.
    /// </summary>
    // NOTE: Programmatic dual-protocol configuration provides deterministic test data.
    // JSON profiles would require dynamic parsing and validation. This programmatic
    // approach ensures consistent test behavior and eliminates JSON parsing dependencies.
    private static Result<ImmutableDictionary<ushort, byte[]>, SmartCardError> CreateDualProtocolDataObjects()
    {
        // Define dual-protocol card capabilities (both SCP02 and SCP03)
        var supportedScp02 = ImmutableList.Create(
            ScpImplementation.Scp02I15, // 0x15
            ScpImplementation.Scp02I04, // 0x04
            ScpImplementation.Scp02I55  // 0x55
        );

        var supportedScp03 = ImmutableList.Create(
            ScpImplementation.Scp03I70  // 0x70
        );

        var keyTypes = ImmutableList.Create(
            new KeyTypeAndLength(0x80, 0x10), // DES for SCP02
            new KeyTypeAndLength(0x88, 0x10), // AES-128 for SCP03
            new KeyTypeAndLength(0x88, 0x20)  // AES-256 for SCP03
        );

        // Create key information template for dual protocol
        var keyInfoTemplate = new KeyInfoTemplate
        {
            KeyVersionNumber = Maybe<byte>.From((byte)0x01),
            KeyIdentifier = Maybe<byte>.From((byte)0x00),
            KeyTypesAndLengths = keyTypes.ToImmutableArray()
        };

        // Create security domain info
        var securityDomainInfo = new SecurityDomainInfo
        {
            Oid = Aids.IsdDefault,
            ImageData = Convert.FromHexString("A000000151535343"),
            LifeCycleData = Convert.FromHexString("03"),
        };

        // Use functional composition with service calls
        return DataGeneration
            .BuildCardCapabilities(supportedScp02, supportedScp03, keyTypes)
            .Bind(cardCapabilitiesBytes =>
                KeyInfoTemplateCodec
                    .Encode(keyInfoTemplate)
                    .Bind(keyInfoBytes =>
                        SecurityDomainInfoCodec
                            .Encode(securityDomainInfo)
                            .Map(securityDomainBytes =>
                                ImmutableDictionary
                                    .Create<ushort, byte[]>()
                                    .Add(0x0066, cardCapabilitiesBytes)      // Card capabilities using service
                                    .Add(0x00E0, keyInfoBytes)               // Key info template using codec
                                    .Add(0x00C1, securityDomainBytes)       // Security domain data using codec
                            )
                    )
            );
    }

    /// <summary>
    /// Creates data objects optimized for SCP03-first cards.
    /// </summary>
    private static Result<ImmutableDictionary<ushort, byte[]>, SmartCardError> CreateScp03DataObjects()
    {
        // Define SCP03-first card capabilities
        var supportedScp03 = ImmutableList.Create(
            ScpImplementation.Scp03I70, // 0x70
            ScpImplementation.Scp03I60, // 0x60
            ScpImplementation.Scp03I10  // 0x10
        );

        var supportedScp02 = ImmutableList.Create(
            ScpImplementation.Scp02I15  // 0x15 fallback
        );

        var keyTypes = ImmutableList.Create(
            new KeyTypeAndLength(0x88, 0x20), // AES-256 primary
            new KeyTypeAndLength(0x88, 0x10), // AES-128 fallback
            new KeyTypeAndLength(0x80, 0x10)  // DES for SCP02
        );

        // Create key information template for SCP03
        var keyInfoTemplate = new KeyInfoTemplate
        {
            KeyVersionNumber = Maybe<byte>.From((byte)0x11), // Different version for SCP03
            KeyIdentifier = Maybe<byte>.From((byte)0x01),
            KeyTypesAndLengths = keyTypes.ToImmutableArray()
        };

        // Create security domain info for SCP03
        var securityDomainInfo = new SecurityDomainInfo
        {
            Oid = Aids.IsdDefault,
            ImageData = Convert.FromHexString("A000000151535343"),
            LifeCycleData = Convert.FromHexString("03"),
        };

        // Use functional composition with service calls
        return DataGeneration
            .BuildCardCapabilities(supportedScp02, supportedScp03, keyTypes)
            .Bind(cardCapabilitiesBytes =>
                KeyInfoTemplateCodec
                    .Encode(keyInfoTemplate)
                    .Bind(keyInfoBytes =>
                        SecurityDomainInfoCodec
                            .Encode(securityDomainInfo)
                            .Map(securityDomainBytes =>
                                ImmutableDictionary
                                    .Create<ushort, byte[]>()
                                    .Add(0x0066, cardCapabilitiesBytes)      // Card capabilities using service
                                    .Add(0x00E0, keyInfoBytes)               // Key info template using codec
                                    .Add(0x00C1, securityDomainBytes)       // Security domain data using codec
                            )
                    )
            );
    }
}
