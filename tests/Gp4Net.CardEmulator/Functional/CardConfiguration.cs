using System;
using System.Collections.Immutable;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional
{
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
        byte DefaultScpImplementation
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
            DefaultScpImplementation: 0x15
        );

        /// <summary>
        /// Creates a generic JavaCard configuration for testing.
        /// </summary>
        public static CardConfiguration Generic() => new(
            Atr: Convert.FromHexString("3B00"),
            IsdAid: Convert.FromHexString("A000000151000000"),
            StaticKeys: CreateGenericKeys(),
            DefaultDataObjects: CreateGenericDataObjects(),
            SupportedInstructions: CreateStandardGpInstructions(),
            CardType: "Generic JavaCard",
            DefaultScpVersion: 0x02,
            DefaultScpImplementation: 0x15
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
        public CardConfiguration WithScpDefaults(byte version, byte implementation) => this with
        {
            DefaultScpVersion = version,
            DefaultScpImplementation = implementation
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
                .Add(0x01, Scp02KeySet.Create(testKeys, testKeys, testKeys, 0x01).GetOrThrow(e => new InvalidOperationException($"Failed to create Scp02KeySet: {e.Message}")))
                .Add(0xFF, Scp02KeySet.Create(testKeys, testKeys, testKeys, 0xFF).GetOrThrow(e => new InvalidOperationException($"Failed to create Scp02KeySet: {e.Message}"))); // Factory keys
        }

        private static ImmutableDictionary<ushort, byte[]> CreateP71DataObjects()
        {
            return ImmutableDictionary.Create<ushort, byte[]>()
                // CPLC Data (Card Production Life Cycle)
                .Add(0x9F7F, Convert.FromHexString("4790D3214700000000002345558919204839000000000000000018649535383931390000000000000000"))
                // Card Capabilities
                .Add(0x0067, Convert.FromHexString("6728A00D800103810500102060708201078103E5BEC082031E030083010284010285017B86010C87017B"))
                // Card Data
                .Add(0x0066, Convert.FromHexString("664D734B06072A864886FC6B01600B06092A864886FC6B020203630906072A864886FC6B03640B06092A864886FC6B040370650D060B2A864886FC6B0507020000660C060A2B060104012A026E0103"))
                // Key Information Template
                .Add(0x00E0, Convert.FromHexString("E012C00401018810C00402018810C00403018810"))
                // SSD Counter
                .Add(0x00C1, Convert.FromHexString("C103000019"))
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

        private static ImmutableDictionary<byte, IKeySet> CreateGenericKeys()
        {
            var defaultKeys = new byte[] 
            { 
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F 
            };

            return ImmutableDictionary.Create<byte, IKeySet>()
                .Add(0x01, Scp02KeySet.Create(defaultKeys, defaultKeys, defaultKeys, 0x01).GetOrThrow(e => new InvalidOperationException($"Failed to create Scp02KeySet: {e.Message}")));
        }

        private static ImmutableDictionary<ushort, byte[]> CreateGenericDataObjects()
        {
            return ImmutableDictionary.Create<ushort, byte[]>()
                // Basic card data
                .Add(0x0066, new byte[] { 0x66, 0x04, 0x01, 0x00, 0x00, 0x00 })
                // Basic capabilities
                .Add(0x0067, new byte[] { 0x67, 0x04, 0x81, 0x01, 0x00, 0x01 });
        }

        private static ImmutableList<byte> CreateStandardGpInstructions()
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
    }
}