using System;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.DataObjects;
using JetBrains.Annotations;

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
    Gp4Net.Domain.Protocol.ScpImplementation DefaultScpImplementation
)
{
    /// <summary>
    /// Creates a configuration for NXP P71 cards based on public specifications.
    /// </summary>
    public static CardConfiguration P71() => new(
        Atr: Convert.FromHexString("3BD518FF8191FE1FC38073C821100A"),
        IsdAid: Convert.FromHexString("A000000151000000"),
        StaticKeys: CreateP71Keys(),
        DefaultDataObjects: CreateP71DataObjects(),
        SupportedInstructions: CreateP71SupportedInstructions(),
        CardType: "NXP P71",
        DefaultScpVersion: 0x02,
        DefaultScpImplementation: Gp4Net.Domain.Protocol.ScpImplementation.Scp02I15
    );

    /// <summary>
    /// Creates a generic JavaCard configuration for testing.
    /// </summary>
    public static CardConfiguration Generic() => new(
        Atr: Convert.FromHexString("3B00"),
        IsdAid: Convert.FromHexString("A000000151000000"),
        StaticKeys: CreateScp02TestKeys(),
        DefaultDataObjects: CreateGenericDataObjects(),
        SupportedInstructions: CreateStandardGpInstructions(),
        CardType: "Generic JavaCard",
        DefaultScpVersion: 0x02,
        DefaultScpImplementation: Gp4Net.Domain.Protocol.ScpImplementation.Scp02I15
    );

    /// <summary>
    /// Creates a minimal JavaCard configuration supporting only SELECT and GET DATA commands.
    /// Used for testing instruction validation and unsupported command handling.
    /// </summary>
    public static CardConfiguration Minimal() => new(
        Atr: Convert.FromHexString("3B00"),
        IsdAid: Convert.FromHexString("A000000151000000"),
        StaticKeys: CreateScp02TestKeys(),
        DefaultDataObjects: CreateGenericDataObjects(),
        SupportedInstructions: CreateMinimalInstructions(),
        CardType: "Minimal JavaCard",
        DefaultScpVersion: 0x02,
        DefaultScpImplementation: Gp4Net.Domain.Protocol.ScpImplementation.Scp02I15
    );

    /// <summary>
    /// Creates a dual-protocol card configuration supporting both SCP02 and SCP03.
    /// Defaults to SCP02 i=15 but supports SCP03 i=70 as well.
    /// </summary>
    public static CardConfiguration DualProtocol() => new(
        Atr: Convert.FromHexString("3BD518FF8191FE1FC38073C821100A"),
        IsdAid: Convert.FromHexString("A000000151000000"),
        StaticKeys: CreateDualProtocolKeys(),
        DefaultDataObjects: CreateDualProtocolDataObjects(),
        SupportedInstructions: CreateStandardGpInstructions(),
        CardType: "Dual Protocol (SCP02/SCP03)",
        DefaultScpVersion: 0x02, // Default to SCP02 for compatibility
        DefaultScpImplementation: Gp4Net.Domain.Protocol.ScpImplementation.Scp02I15
    );

    /// <summary>
    /// Creates an SCP03-first card configuration.
    /// Defaults to SCP03 i=70 but supports SCP02 fallback.
    /// </summary>
    public static CardConfiguration Scp03First() => new(
        Atr: Convert.FromHexString("3BD518FF8191FE1FC38073C821100A"),
        IsdAid: Convert.FromHexString("A000000151000000"),
        StaticKeys: CreateDualProtocolKeys(),
        DefaultDataObjects: CreateScp03DataObjects(),
        SupportedInstructions: CreateStandardGpInstructions(),
        CardType: "SCP03-First Card",
        DefaultScpVersion: 0x03, // Default to SCP03
        DefaultScpImplementation: Gp4Net.Domain.Protocol.ScpImplementation.Scp03I70
    );

    /// <summary>
    /// Creates a new configuration with an additional data object.
    /// </summary>
    public CardConfiguration WithDataObject(ushort tag, byte[] data) => this with
    {
        DefaultDataObjects = DefaultDataObjects.SetItem(tag, data)
    };

    /// <summary>
    /// Creates a new configuration with additional supported instruction.
    /// </summary>
    public CardConfiguration WithInstruction(byte instruction) => this with
    {
        SupportedInstructions = SupportedInstructions.Contains(instruction) 
            ? SupportedInstructions 
            : SupportedInstructions.Add(instruction)
    };

    /// <summary>
    /// Creates a new configuration with updated SCP defaults.
    /// </summary>
    public CardConfiguration WithScpDefaults(byte version, Gp4Net.Domain.Protocol.ScpImplementation implementation) => this with
    {
        DefaultScpVersion = version,
        DefaultScpImplementation = implementation
    };

    /// <summary>
    /// Creates a new configuration with an additional key set at specified version.
    /// </summary>
    public CardConfiguration WithKeySet(byte version, IKeySet keySet) => this with
    {
        StaticKeys = StaticKeys.SetItem(version, keySet)
    };

    /// <summary>
    /// Creates a new configuration with updated ATR.
    /// </summary>
    public CardConfiguration WithAtr(byte[] atr) => this with
    {
        Atr = atr
    };

    /// <summary>
    /// Creates a new configuration with updated ISD AID.
    /// </summary>
    public CardConfiguration WithIsdAid(byte[] isdAid) => this with
    {
        IsdAid = isdAid
    };

    private static ImmutableDictionary<byte, IKeySet> CreateP71Keys()
    {
        // Default P71 test keys from public documentation
        var testKeys = new byte[] 
        { 
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F 
        };

        return ImmutableDictionary.Create<byte, IKeySet>()
            .Add(0x01, Scp02KeySet.Create(testKeys, testKeys, testKeys, 0x01).Match(
                onSuccess: keySet => keySet,
                onFailure: error => throw new InvalidOperationException($"Failed to create Scp02KeySet: {error.Message}")))
            .Add(0xFF, Scp02KeySet.Create(testKeys, testKeys, testKeys, 0xFF).Match(
                onSuccess: keySet => keySet,
                onFailure: error => throw new InvalidOperationException($"Failed to create Scp02KeySet: {error.Message}"))); // Factory keys
    }

    private static ImmutableDictionary<ushort, byte[]> CreateP71DataObjects()
    {
        // Create card capabilities for P71 (SCP02 only)
        var cardCapabilities = new CardCapabilities
        {
            CardRecognitionData = Convert.FromHexString("42"),
            CardManagementTypeAndVersion = [0x02, 0x00],
            CardIdentificationScheme = 0x00,
            SecureChannelProtocols =
            {
                new SecureChannelProtocol
                {
                    Protocol = 0x02,
                    Implementations =
                    {
                        new Gp4Net.Domain.DataObjects.ScpImplementationSpecifier { Implementation = 0x15, KeyTypes = { 0x80, 0x10 } },
                        new Gp4Net.Domain.DataObjects.ScpImplementationSpecifier { Implementation = 0x04, KeyTypes = { 0x80, 0x10 } },
                        new Gp4Net.Domain.DataObjects.ScpImplementationSpecifier { Implementation = 0x1A, KeyTypes = { 0x80, 0x10 } }
                    }
                }
            }
        };
            
        // Create key information template for P71
        var keyInfoTemplate = new KeyInfoTemplate
        {
            KeyVersionNumber = 0x01,
            KeyIdentifier = 0x00,
            KeyTypesAndLengths =
            {
                new KeyTypeAndLength { Type = 0x80, Length = 0x10 }, // DES
                new KeyTypeAndLength { Type = 0x81, Length = 0x10 }, // DES-ECB  
                new KeyTypeAndLength { Type = 0x82, Length = 0x10 }  // DES-MAC
            }
        };
            
        // Create security domain info
        var securityDomainInfo = new SecurityDomainInfo
        {
            Oid = Convert.FromHexString("A000000151000000"),
            ImageData = Convert.FromHexString("A000000151535343"),
            LifeCycleData = Convert.FromHexString("03")
        };

        var cardCapabilitiesResult = CardCapabilitiesCodec.Encode(cardCapabilities);
        if (cardCapabilitiesResult.IsFailure)
            throw new InvalidOperationException($"Failed to encode card capabilities: {cardCapabilitiesResult.Error.Message}");
            
        var keyInfoTemplateResult = KeyInfoTemplateCodec.Encode(keyInfoTemplate);
        if (keyInfoTemplateResult.IsFailure)
            throw new InvalidOperationException($"Failed to encode key info template: {keyInfoTemplateResult.Error.Message}");
            
        var securityDomainInfoResult = SecurityDomainInfoCodec.Encode(securityDomainInfo);
        if (securityDomainInfoResult.IsFailure)
            throw new InvalidOperationException($"Failed to encode security domain info: {securityDomainInfoResult.Error.Message}");

        return ImmutableDictionary.Create<ushort, byte[]>()
            // CPLC Data (Card Production Life Cycle)
            .Add(0x9F7F, Convert.FromHexString("4790D3214700000000002345558919204839000000000000000018649535383931390000000000000000"))
            // Card Capabilities - legacy format for 0x67
            .Add(0x0067, Convert.FromHexString("6728A00D800103810500102060708201078103E5BEC082031E030083010284010285017B86010C87017B"))
            // Card Capabilities - using codec for 0x66
            .Add(0x0066, cardCapabilitiesResult.Value)
            // Key Information Template - using codec
            .Add(0x00E0, keyInfoTemplateResult.Value)
            // Security Domain Info - using codec
            .Add(0x00C1, securityDomainInfoResult.Value)
            // Key Diversification Data
            .Add(0x00CF, Convert.FromHexString("CF0A03700000000000000000"));
    }

    private static ImmutableList<byte> CreateP71SupportedInstructions()
    {
        return ImmutableList.Create<byte>(
            0xA4, // SELECT
            0x50, // INITIALIZE UPDATE
            0x82, // EXTERNAL AUTHENTICATE
            0xCA, // GET DATA
            0xF2, // GET STATUS
            0xE6, // INSTALL
            0xE8, // LOAD
            0xE4, // DELETE
            0xD8, // PUT KEY
            0xE2, // STORE DATA
            0xFE  // P71 IDENTIFY (proprietary)
        );
    }

    /// <summary>
    /// Creates SCP02 key sets using GlobalPlatform Test Keys.
    /// Per GP 2.3.1 Section 11.1.1: These are the standard test keys for SCP02 protocol testing.
    /// </summary>
    public static ImmutableDictionary<byte, IKeySet> CreateScp02TestKeys()
    {
        // GlobalPlatform Test Keys from GP 2.3.1 specification
        var gpTestKeys = new byte[] 
        { 
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F 
        };

        return Scp02KeySet.Create(gpTestKeys, gpTestKeys, gpTestKeys, 0x01)
            .Map(keySet => ImmutableDictionary.Create<byte, IKeySet>().Add(0x01, keySet))
            .GetValueOrDefault(ImmutableDictionary<byte, IKeySet>.Empty);
    }

    /// <summary>
    /// Creates SCP03 key sets using the same GlobalPlatform Test Keys.
    /// Per GP 2.3.1 Section 11.1.1: Same key material as SCP02 but in SCP03 key set format.
    /// </summary>
    public static ImmutableDictionary<byte, IKeySet> CreateScp03TestKeys()
    {
        // Same GlobalPlatform Test Keys from GP 2.3.1 specification
        var gpTestKeys = new byte[] 
        { 
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F 
        };

        return Scp03KeySet.Create(gpTestKeys, gpTestKeys, gpTestKeys, 0x01)
            .Map(keySet => ImmutableDictionary.Create<byte, IKeySet>().Add(0x01, keySet))
            .GetValueOrDefault(ImmutableDictionary<byte, IKeySet>.Empty);
    }

    /// <summary>
    /// Creates dual-protocol key sets supporting both SCP02 and SCP03 with GlobalPlatform Test Keys.
    /// Per GP 2.3.1 Section 11.1.1: Provides proper type safety for both protocols using same key material.
    /// </summary>
    public static ImmutableDictionary<byte, IKeySet> CreateDualProtocolTestKeys()
    {
        // Same GlobalPlatform Test Keys from GP 2.3.1 specification  
        var gpTestKeys = new byte[] 
        { 
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F 
        };

        return Scp02KeySet.Create(gpTestKeys, gpTestKeys, gpTestKeys, 0x01)
            .Bind(scp02KeySet => Scp03KeySet.Create(gpTestKeys, gpTestKeys, gpTestKeys, 0x02)
                .Map(scp03KeySet => ImmutableDictionary.Create<byte, IKeySet>()
                    .Add(0x01, scp02KeySet)
                    .Add(0x02, scp03KeySet)))
            .GetValueOrDefault(ImmutableDictionary<byte, IKeySet>.Empty);
    }

    public static ImmutableDictionary<ushort, byte[]> CreateGenericDataObjects()
    {
        return ImmutableDictionary.Create<ushort, byte[]>()
            // Basic card data
            .Add(0x0066, [0x66, 0x04, 0x01, 0x00, 0x00, 0x00])
            // Basic capabilities
            .Add(0x0067, [0x67, 0x04, 0x81, 0x01, 0x00, 0x01]);
    }

    public static ImmutableList<byte> CreateStandardGpInstructions()
    {
        return ImmutableList.Create<byte>(
            0xA4, // SELECT
            0x50, // INITIALIZE UPDATE
            0x82, // EXTERNAL AUTHENTICATE
            0xCA, // GET DATA
            0xF2, // GET STATUS
            0xE6, // INSTALL
            0xE8, // LOAD
            0xE4, // DELETE
            0xD8  // PUT KEY
        );
    }

    /// <summary>
    /// Creates a minimal instruction set supporting only SELECT and GET DATA commands.
    /// Used for testing instruction validation and unsupported command handling.
    /// </summary>
    public static ImmutableList<byte> CreateMinimalInstructions()
    {
        return ImmutableList.Create<byte>(
            0xA4, // SELECT
            0xCA  // GET DATA
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
    private static ImmutableDictionary<ushort, byte[]> CreateDualProtocolDataObjects()
    {
        // Create dual-protocol card capabilities (both SCP02 and SCP03)
        var cardCapabilities = new CardCapabilities
        {
            CardRecognitionData = Convert.FromHexString("42"),
            CardManagementTypeAndVersion = [0x02, 0x00],
            CardIdentificationScheme = 0x00,
            SecureChannelProtocols =
            {
                new SecureChannelProtocol
                {
                    Protocol = 0x02,
                    Implementations =
                    {
                        new Gp4Net.Domain.DataObjects.ScpImplementationSpecifier { Implementation = 0x15, KeyTypes = { 0x80, 0x10 } },
                        new Gp4Net.Domain.DataObjects.ScpImplementationSpecifier { Implementation = 0x04, KeyTypes = { 0x80, 0x10 } },
                        new Gp4Net.Domain.DataObjects.ScpImplementationSpecifier { Implementation = 0x55, KeyTypes = { 0x80, 0x10 } }
                    }
                },
                new SecureChannelProtocol
                {
                    Protocol = 0x03,
                    Implementations =
                    {
                        new Gp4Net.Domain.DataObjects.ScpImplementationSpecifier { Implementation = 0x70, KeyTypes = { 0x80, 0x20 } }
                    }
                }
            }
        };
            
        // Create key information template for dual protocol
        var keyInfoTemplate = new KeyInfoTemplate
        {
            KeyVersionNumber = 0x01,
            KeyIdentifier = 0x00,
            KeyTypesAndLengths =
            {
                new KeyTypeAndLength { Type = 0x80, Length = 0x10 }, // DES for SCP02
                new KeyTypeAndLength { Type = 0x88, Length = 0x10 }, // AES-128 for SCP03
                new KeyTypeAndLength { Type = 0x88, Length = 0x20 }  // AES-256 for SCP03
            }
        };
            
        // Create security domain info
        var securityDomainInfo = new SecurityDomainInfo
        {
            Oid = Convert.FromHexString("A000000151000000"),
            ImageData = Convert.FromHexString("A000000151535343"),
            LifeCycleData = Convert.FromHexString("03")
        };

        var cardCapabilitiesResult = CardCapabilitiesCodec.Encode(cardCapabilities);
        if (cardCapabilitiesResult.IsFailure)
            throw new InvalidOperationException($"Failed to encode card capabilities: {cardCapabilitiesResult.Error.Message}");
            
        var keyInfoTemplateResult = KeyInfoTemplateCodec.Encode(keyInfoTemplate);
        if (keyInfoTemplateResult.IsFailure)
            throw new InvalidOperationException($"Failed to encode key info template: {keyInfoTemplateResult.Error.Message}");
            
        var securityDomainInfoResult = SecurityDomainInfoCodec.Encode(securityDomainInfo);
        if (securityDomainInfoResult.IsFailure)
            throw new InvalidOperationException($"Failed to encode security domain info: {securityDomainInfoResult.Error.Message}");

        return ImmutableDictionary.Create<ushort, byte[]>()
            // Card capabilities using codec
            .Add(0x0066, cardCapabilitiesResult.Value)
            // Key info template using codec
            .Add(0x00E0, keyInfoTemplateResult.Value)
            // Security domain data using codec
            .Add(0x00C1, securityDomainInfoResult.Value);
    }

    /// <summary>
    /// Creates data objects optimized for SCP03-first cards.
    /// </summary>
    private static ImmutableDictionary<ushort, byte[]> CreateScp03DataObjects()
    {
        // Create SCP03-first card capabilities
        var cardCapabilities = new CardCapabilities
        {
            CardRecognitionData = Convert.FromHexString("42"),
            CardManagementTypeAndVersion = [0x02, 0x00],
            CardIdentificationScheme = 0x00,
            SecureChannelProtocols =
            {
                new SecureChannelProtocol
                {
                    Protocol = 0x03, // SCP03 first
                    Implementations =
                    {
                        new Gp4Net.Domain.DataObjects.ScpImplementationSpecifier { Implementation = 0x70, KeyTypes = { 0x80, 0x20 } },
                        new Gp4Net.Domain.DataObjects.ScpImplementationSpecifier { Implementation = 0x60, KeyTypes = { 0x80, 0x10 } },
                        new Gp4Net.Domain.DataObjects.ScpImplementationSpecifier { Implementation = 0x10, KeyTypes = { 0x80, 0x20 } }
                    }
                },
                new SecureChannelProtocol
                {
                    Protocol = 0x02, // SCP02 fallback
                    Implementations =
                    {
                        new Gp4Net.Domain.DataObjects.ScpImplementationSpecifier { Implementation = 0x15, KeyTypes = { 0x80, 0x10 } }
                    }
                }
            }
        };
            
        // Create key information template for SCP03
        var keyInfoTemplate = new KeyInfoTemplate
        {
            KeyVersionNumber = 0x11, // Different version for SCP03
            KeyIdentifier = 0x01,
            KeyTypesAndLengths =
            {
                new KeyTypeAndLength { Type = 0x88, Length = 0x20 }, // AES-256 primary
                new KeyTypeAndLength { Type = 0x88, Length = 0x10 }, // AES-128 fallback
                new KeyTypeAndLength { Type = 0x80, Length = 0x10 }  // DES for SCP02
            }
        };
            
        // Create security domain info for SCP03
        var securityDomainInfo = new SecurityDomainInfo
        {
            Oid = Convert.FromHexString("A000000151000000"),
            ImageData = Convert.FromHexString("A000000151535343"),
            LifeCycleData = Convert.FromHexString("03")
        };

        var cardCapabilitiesResult = CardCapabilitiesCodec.Encode(cardCapabilities);
        if (cardCapabilitiesResult.IsFailure)
            throw new InvalidOperationException($"Failed to encode card capabilities: {cardCapabilitiesResult.Error.Message}");
            
        var keyInfoTemplateResult = KeyInfoTemplateCodec.Encode(keyInfoTemplate);
        if (keyInfoTemplateResult.IsFailure)
            throw new InvalidOperationException($"Failed to encode key info template: {keyInfoTemplateResult.Error.Message}");
            
        var securityDomainInfoResult = SecurityDomainInfoCodec.Encode(securityDomainInfo);
        if (securityDomainInfoResult.IsFailure)
            throw new InvalidOperationException($"Failed to encode security domain info: {securityDomainInfoResult.Error.Message}");

        return ImmutableDictionary.Create<ushort, byte[]>()
            // Card capabilities using codec
            .Add(0x0066, cardCapabilitiesResult.Value)
            // Key info template using codec
            .Add(0x00E0, keyInfoTemplateResult.Value)
            // Security domain data using codec
            .Add(0x00C1, securityDomainInfoResult.Value);
    }
}