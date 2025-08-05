using System;
using Gp4Net.Domain.Protocol;
using Gp4Net.CardEmulator.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Test builder for creating functional virtual cards with various configurations.
/// Provides a fluent API for setting up test scenarios with different card types,
/// cryptographic services, and validation modes.
/// </summary>
[PublicAPI]
public static class VirtualCardTestBuilder
{
    /// <summary>
    /// Creates a P71 card with test cryptographic service.
    /// </summary>
    public static VirtualCard P71Card() =>
        new(CardConfiguration.P71(), new CryptographicService());

    /// <summary>
    /// Creates a generic JavaCard with test cryptographic service.
    /// </summary>
    public static VirtualCard GenericCard() =>
        new(CardConfiguration.Generic(), new CryptographicService());

    /// <summary>
    /// Creates a card with the specified configuration.
    /// </summary>
    public static VirtualCard WithConfiguration(CardConfiguration config) =>
        new(config, new CryptographicService());

    /// <summary>
    /// Creates a card with mock crypto service that always fails (for testing error conditions).
    /// </summary>
    public static VirtualCard WithFailingCrypto(this CardConfiguration config) =>
        new(config, new FailingCryptographicService());

    /// <summary>
    /// Creates a card with deterministic test crypto service.
    /// </summary>
    public static VirtualCard WithTestCrypto(this CardConfiguration config) =>
        new(config, new CryptographicService());

    /// <summary>
    /// Creates a P71 card that supports IDENTIFY command.
    /// </summary>
    public static VirtualCard P71CardWithIdentify() =>
        P71Card(); // P71 configuration already includes IDENTIFY support

    /// <summary>
    /// Creates a card with specific SCP configuration.
    /// </summary>
    public static VirtualCard WithScp(this CardConfiguration config, byte version, Gp4Net.Domain.Protocol.ScpImplementation implementation) =>
        new(config.WithScpDefaults(version, implementation), new CryptographicService());

    /// <summary>
    /// Creates a card with additional data objects for testing.
    /// </summary>
    public static VirtualCard WithDataObject(this CardConfiguration config, ushort tag, byte[] data) =>
        new(config.WithDataObject(tag, data), new CryptographicService());

    /// <summary>
    /// Creates a card with additional supported instruction.
    /// </summary>
    public static VirtualCard WithInstruction(this CardConfiguration config, byte instruction) =>
        new(config.WithInstruction(instruction), new CryptographicService());

    /// <summary>
    /// Creates a card configuration that will be used for trace validation testing.
    /// </summary>
    public static CardConfiguration ForTraceValidation(string tracePath)
    {
        // For now, return P71 config - in the future this could parse trace files
        // to determine the appropriate configuration
        return CardConfiguration.P71();
    }

    /// <summary>
    /// Creates a card set up for secure channel testing.
    /// </summary>
    public static VirtualCard ForSecureChannelTesting(byte scpVersion = 0x02)
    {
        var config = scpVersion switch
        {
            0x02 => CardConfiguration.P71().WithScpDefaults(0x02, Gp4Net.Domain.Protocol.ScpImplementation.Scp02StaticMac),
            0x03 => CardConfiguration.P71().WithScpDefaults(0x03, Gp4Net.Domain.Protocol.ScpImplementation.Scp03PseudoRandom),
            _ => throw new ArgumentException($"Unsupported SCP version: {scpVersion:X2}")
        };

        return new VirtualCard(config, new CryptographicService());
    }

    /// <summary>
    /// Creates a card that simulates error conditions.
    /// </summary>
    public static VirtualCard SimulatingErrors()
    {
        return new VirtualCard(CardConfiguration.Generic(), new FailingCryptographicService());
    }

    /// <summary>
    /// Creates a minimal card with only basic GP support.
    /// </summary>
    public static VirtualCard MinimalCard()
    {
        // Create a truly minimal configuration with only SELECT and GET DATA
        var baseConfig = CardConfiguration.Generic();
        var minimalConfig = baseConfig with
        {
            SupportedInstructions = System.Collections.Immutable.ImmutableList.Create<byte>(
                0xA4, // SELECT only
                0xCA  // GET DATA only
            )
        };

        return new VirtualCard(minimalConfig, new CryptographicService());
    }

    /// <summary>
    /// Creates a card with SCP02 protocol support.
    /// </summary>
    public static VirtualCard Scp02Card()
    {
        var config = CardConfiguration.Generic() with
        {
            DefaultScpVersion = 0x02,
            DefaultScpImplementation = Gp4Net.Domain.Protocol.ScpImplementation.Scp02StaticMac
        };
            
        var card = new VirtualCard(config, new CryptographicService());
        return card;
    }

    /// <summary>
    /// Creates a card with SCP03 protocol support.
    /// </summary>
    public static VirtualCard Scp03Card()
    {
        var config = CardConfiguration.Generic() with
        {
            DefaultScpVersion = 0x03,
            DefaultScpImplementation = Gp4Net.Domain.Protocol.ScpImplementation.Scp03PseudoRandom
        };
            
        var card = new VirtualCard(config, new CryptographicService());
        return card;
    }

    /// <summary>
    /// Creates a card with custom ATR for testing.
    /// </summary>
    public static VirtualCard WithCustomAtr(byte[] atr)
    {
        var config = CardConfiguration.Generic() with { Atr = atr };
        return new VirtualCard(config, new CryptographicService());
    }

    /// <summary>
    /// Creates a dual-protocol card supporting both SCP02 and SCP03.
    /// Defaults to SCP02 i=15 but supports SCP03 i=70 as well.
    /// </summary>
    public static VirtualCard DualProtocolCard()
    {
        return new VirtualCard(CardConfiguration.DualProtocol(), new CryptographicService());
    }

    /// <summary>
    /// Creates an SCP03-first card configuration.
    /// Defaults to SCP03 i=70 but supports SCP02 fallback.
    /// </summary>
    public static VirtualCard Scp03FirstCard()
    {
        return new VirtualCard(CardConfiguration.Scp03First(), new CryptographicService());
    }

    /// <summary>
    /// Creates a card builder for complex test scenarios.
    /// </summary>
    public static VirtualCardBuilder Builder() => new();
}

/// <summary>
/// Builder class for creating complex virtual card configurations.
/// </summary>
[PublicAPI]
public class VirtualCardBuilder
{
    private CardConfiguration _config = CardConfiguration.Generic();
    private ICryptographicService _cryptoService = new CryptographicService();

    /// <summary>
    /// Sets the base configuration to P71.
    /// </summary>
    public VirtualCardBuilder AsP71()
    {
        _config = CardConfiguration.P71();
        return this;
    }

    /// <summary>
    /// Sets the base configuration to generic JavaCard.
    /// </summary>
    public VirtualCardBuilder AsGeneric()
    {
        _config = CardConfiguration.Generic();
        return this;
    }

    /// <summary>
    /// Sets a custom ATR.
    /// </summary>
    public VirtualCardBuilder WithAtr(byte[] atr)
    {
        _config = _config with { Atr = atr };
        return this;
    }

    /// <summary>
    /// Adds support for a specific instruction.
    /// </summary>
    public VirtualCardBuilder WithInstruction(byte instruction)
    {
        _config = _config.WithInstruction(instruction);
        return this;
    }

    /// <summary>
    /// Adds a data object.
    /// </summary>
    public VirtualCardBuilder WithDataObject(ushort tag, byte[] data)
    {
        _config = _config.WithDataObject(tag, data);
        return this;
    }

    /// <summary>
    /// Sets SCP configuration.
    /// </summary>
    public VirtualCardBuilder WithScp(byte version, Gp4Net.Domain.Protocol.ScpImplementation implementation)
    {
        _config = _config.WithScpDefaults(version, implementation);
        return this;
    }

    /// <summary>
    /// Uses test cryptographic service.
    /// </summary>
    public VirtualCardBuilder WithTestCrypto()
    {
        _cryptoService = new CryptographicService();
        return this;
    }

    /// <summary>
    /// Uses failing cryptographic service for error testing.
    /// </summary>
    public VirtualCardBuilder WithFailingCrypto()
    {
        _cryptoService = new FailingCryptographicService();
        return this;
    }

    /// <summary>
    /// Uses a custom cryptographic service.
    /// </summary>
    public VirtualCardBuilder WithCrypto(ICryptographicService cryptoService)
    {
        _cryptoService = cryptoService ?? throw new ArgumentNullException(nameof(cryptoService));
        return this;
    }

    /// <summary>
    /// Builds the virtual card with the current configuration.
    /// </summary>
    public VirtualCard Build()
    {
        return new VirtualCard(_config, _cryptoService);
    }
}