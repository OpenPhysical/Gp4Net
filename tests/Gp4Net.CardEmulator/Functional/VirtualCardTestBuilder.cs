using System;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional
{
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
        public static FunctionalVirtualCard P71Card() =>
            new(CardConfiguration.P71(), new TestCryptographicService());

        /// <summary>
        /// Creates a generic JavaCard with test cryptographic service.
        /// </summary>
        public static FunctionalVirtualCard GenericCard() =>
            new(CardConfiguration.Generic(), new TestCryptographicService());

        /// <summary>
        /// Creates a card with the specified configuration.
        /// </summary>
        public static FunctionalVirtualCard WithConfiguration(CardConfiguration config) =>
            new(config, new TestCryptographicService());

        /// <summary>
        /// Creates a card with mock crypto service that always fails (for testing error conditions).
        /// </summary>
        public static FunctionalVirtualCard WithFailingCrypto(this CardConfiguration config) =>
            new(config, new FailingCryptographicService());

        /// <summary>
        /// Creates a card with deterministic test crypto service.
        /// </summary>
        public static FunctionalVirtualCard WithTestCrypto(this CardConfiguration config) =>
            new(config, new TestCryptographicService());

        /// <summary>
        /// Creates a P71 card that supports IDENTIFY command.
        /// </summary>
        public static FunctionalVirtualCard P71CardWithIdentify() =>
            P71Card(); // P71 configuration already includes IDENTIFY support

        /// <summary>
        /// Creates a card with specific SCP configuration.
        /// </summary>
        public static FunctionalVirtualCard WithScp(this CardConfiguration config, byte version, byte implementation) =>
            new(config.WithScpDefaults(version, implementation), new TestCryptographicService());

        /// <summary>
        /// Creates a card with additional data objects for testing.
        /// </summary>
        public static FunctionalVirtualCard WithDataObject(this CardConfiguration config, ushort tag, byte[] data) =>
            new(config.WithDataObject(tag, data), new TestCryptographicService());

        /// <summary>
        /// Creates a card with additional supported instruction.
        /// </summary>
        public static FunctionalVirtualCard WithInstruction(this CardConfiguration config, byte instruction) =>
            new(config.WithInstruction(instruction), new TestCryptographicService());

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
        public static FunctionalVirtualCard ForSecureChannelTesting(byte scpVersion = 0x02)
        {
            var config = scpVersion switch
            {
                0x02 => CardConfiguration.P71().WithScpDefaults(0x02, 0x15),
                0x03 => CardConfiguration.P71().WithScpDefaults(0x03, 0x70),
                _ => throw new ArgumentException($"Unsupported SCP version: {scpVersion:X2}")
            };

            return new FunctionalVirtualCard(config, new TestCryptographicService());
        }

        /// <summary>
        /// Creates a card that simulates error conditions.
        /// </summary>
        public static FunctionalVirtualCard SimulatingErrors()
        {
            return new FunctionalVirtualCard(CardConfiguration.Generic(), new FailingCryptographicService());
        }

        /// <summary>
        /// Creates a minimal card with only basic GP support.
        /// </summary>
        public static FunctionalVirtualCard MinimalCard()
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

            return new FunctionalVirtualCard(minimalConfig, new TestCryptographicService());
        }

        /// <summary>
        /// Creates a card with SCP02 protocol support.
        /// </summary>
        public static FunctionalVirtualCard Scp02Card()
        {
            var config = CardConfiguration.Generic() with
            {
                DefaultScpVersion = 0x02,
                DefaultScpImplementation = 0x15
            };
            
            var card = new FunctionalVirtualCard(config, new TestCryptographicService());
            return card;
        }

        /// <summary>
        /// Creates a card with SCP03 protocol support.
        /// </summary>
        public static FunctionalVirtualCard Scp03Card()
        {
            var config = CardConfiguration.Generic() with
            {
                DefaultScpVersion = 0x03,
                DefaultScpImplementation = 0x70
            };
            
            var card = new FunctionalVirtualCard(config, new TestCryptographicService());
            return card;
        }

        /// <summary>
        /// Creates a card with custom ATR for testing.
        /// </summary>
        public static FunctionalVirtualCard WithCustomAtr(byte[] atr)
        {
            var config = CardConfiguration.Generic() with { Atr = atr };
            return new FunctionalVirtualCard(config, new TestCryptographicService());
        }

        /// <summary>
        /// Creates a dual-protocol card supporting both SCP02 and SCP03.
        /// Defaults to SCP02 i=15 but supports SCP03 i=70 as well.
        /// </summary>
        public static FunctionalVirtualCard DualProtocolCard()
        {
            return new FunctionalVirtualCard(CardConfiguration.DualProtocol(), new TestCryptographicService());
        }

        /// <summary>
        /// Creates an SCP03-first card configuration.
        /// Defaults to SCP03 i=70 but supports SCP02 fallback.
        /// </summary>
        public static FunctionalVirtualCard Scp03FirstCard()
        {
            return new FunctionalVirtualCard(CardConfiguration.Scp03First(), new TestCryptographicService());
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
        private ICryptographicService _cryptoService = new TestCryptographicService();

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
        public VirtualCardBuilder WithScp(byte version, byte implementation)
        {
            _config = _config.WithScpDefaults(version, implementation);
            return this;
        }

        /// <summary>
        /// Uses test cryptographic service.
        /// </summary>
        public VirtualCardBuilder WithTestCrypto()
        {
            _cryptoService = new TestCryptographicService();
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
        public FunctionalVirtualCard Build()
        {
            return new FunctionalVirtualCard(_config, _cryptoService);
        }
    }
}