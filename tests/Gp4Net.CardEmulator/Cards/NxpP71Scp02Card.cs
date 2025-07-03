using System;
using System.Collections.Generic;
using System.Linq;
using Gp4Net.CardEmulator.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Cards
{
    /// <summary>
    /// Emulates an NXP P71 card based on GP Pro traces.
    ///
    /// Key specifications:
    /// - ISD AID: A000000151000000
    /// - SCP02 and SCP03 support
    /// - Default keys: 404142434445464748494A4B4C4D4E4F (Key version 1)
    /// - Factory keys: Diversified keys (Key version 255)
    /// - ATR: 3BD518FF8191FE1FC38073C821100A
    /// - Supports GET DATA for CPLC, Key Info, Card Data, etc.
    /// </summary>
    [PublicAPI]
    public class NxpP71Scp02Card : GlobalPlatformCard
    {
        // P71 card constants from GP Pro traces
        private static readonly byte[] P71IsdAid = Convert.FromHexString("A000000151000000");
        private static readonly byte[] DefaultKey = Convert.FromHexString(
            "404142434445464748494A4B4C4D4E4F"
        );
        private static readonly byte[] FactoryEncKey = Convert.FromHexString(
            "AC2AD8C8E2E874A4C6B514D7ECD5FBE5"
        );
        private static readonly byte[] FactoryMacKey = Convert.FromHexString(
            "86E6282CE0463C510FD4CB14D2A158EA"
        );
        private static readonly byte[] FactoryDekKey = Convert.FromHexString(
            "7C290D97A5F4891F6C16ED7D2BB0A6E1"
        );

        // P71 ATR from GP Pro trace
        private static readonly byte[] CardAtr = Convert.FromHexString(
            "3BD518FF8191FE1FC38073C821100A"
        );

        // Card production life cycle data (CPLC) - simulated P71 values
        private static readonly byte[] DefaultCplcData = Convert.FromHexString(
            "4790"
                + // IC Fabricator (NXP)
                "5031"
                + // IC Type
                "4791"
                + // Operating System ID
                "0000"
                + // Operating System Release Date
                "0000"
                + // Operating System Release Level
                "20DA"
                + // IC Fabrication Date (8410 days from 2000-01-01 = 2023-01-15)
                "1234"
                + // IC Serial Number
                "ABCD"
                + // IC Batch Identifier
                "5678"
                + // IC Module Fabricator
                "20E0"
                + // IC Module Packaging Date
                "CDEF"
                + // ICC Manufacturer
                "20E5"
                + // IC Embedding Date
                "9ABC"
                + // IC Pre-personalizer
                "20EA"
                + // IC Pre-personalization Date
                "BEEF"
                + // IC Pre-personalization Equipment ID
                "DEF0"
                + // IC Personalizer
                "20EF"
                + // IC Personalization Date
                "1357"
                + // IC Personalization Equipment ID
                "24681357" // Additional data
        );

        // Current key configuration
        private byte _currentKeyVersion = 0xFF; // Start with factory keys
        private byte _defaultKeyVersion = 0xFF;

        /// <inheritdoc />
        protected override byte[] IsdAid => P71IsdAid;

        /// <inheritdoc />
        protected override Dictionary<byte, KeySet> StaticKeys { get; } =
            new()
            {
                [1] = new KeySet
                {
                    EncKey = DefaultKey,
                    MacKey = DefaultKey,
                    DekKey = DefaultKey
                },
                [255] = new KeySet
                {
                    EncKey = FactoryEncKey,
                    MacKey = FactoryMacKey,
                    DekKey = FactoryDekKey
                }
            };

        /// <inheritdoc />
        protected override byte CurrentKeyVersion => _currentKeyVersion;

        /// <summary>
        /// Initializes a new instance of the P71Card class.
        /// </summary>
        public NxpP71Scp02Card()
        {
            // Initialize default SCP configuration
            _scpVersion = 0x02;
            _scpImplementation = 0x15; // SCP02 i=15

            // Initialize configuration to support both SCP02 and SCP03
            _configData[0x1057] = new byte[] { 0x02, 0x15, 0x03, 0x70, 0x00, 0x00, 0x00, 0x00 };
        }

        /// <inheritdoc />
        public override byte[] GetAtr()
        {
            return (byte[])CardAtr.Clone();
        }

        /// <inheritdoc />
        public override void Reset()
        {
            base.Reset();
            _currentKeyVersion = _defaultKeyVersion;
        }

        /// <inheritdoc />
        protected override void InitializeDefaultDataObjects()
        {
            // Set up default data objects
            SetDataObject(0x9F7F, DefaultCplcData); // CPLC data
        }

        /// <inheritdoc />
        protected override ApduResponse GetSelectResponse()
        {
            // Return FCI response from GP Pro trace
            var fciResponse = Convert.FromHexString("6F108408A000000151000000A5049F6501FF");
            return ApduResponse.Success(fciResponse);
        }

        /// <inheritdoc />
        protected override ApduResponse ProcessInitializeUpdate(ApduCommand apdu)
        {
            if (!_isdSelected)
                return ApduResponse.Error(SW_CONDITIONS_NOT_SATISFIED);

            if (apdu.Data.Length != 8)
                return ApduResponse.Error(SW_WRONG_LENGTH);

            _hostChallenge = (byte[])apdu.Data.Clone();

            // Generate card challenge
            _cardChallenge = GenerateCardChallenge();

            // Determine key version to use
            var keyVersion = apdu.P1 == 0 ? _defaultKeyVersion : apdu.P1;

            // Generate session keys
            GenerateSessionKeys(keyVersion);

            // Build response based on current SCP configuration
            var response = new List<byte>();

            if (_scpVersion == 0x03)
            {
                // SCP03 response format
                response.AddRange(Convert.FromHexString("03700000000000000000")); // KDD for SCP03
                response.Add(keyVersion); // Key version
                response.Add((byte)(0x03 | _scpImplementation)); // SCP ID with implementation
                response.AddRange(_cardChallenge); // 8 bytes card challenge
                response.AddRange(CalculateCardCryptogram()); // Card cryptogram
                response.AddRange(Convert.FromHexString("000001")); // Sequence counter
            }
            else
            {
                // SCP02 response format
                response.AddRange(Convert.FromHexString("00002345558083204839")); // KDD
                response.Add(keyVersion); // Key version
                response.Add(0x02); // SCP ID
                response.AddRange(Convert.FromHexString("0003")); // Sequence counter
                response.AddRange(_cardChallenge); // 8 bytes card challenge
                response.AddRange(CalculateCardCryptogram()); // Card cryptogram
            }

            return ApduResponse.Success(response.ToArray());
        }

        /// <inheritdoc />
        protected override ApduResponse ProcessExternalAuthenticate(ApduCommand apdu)
        {
            if (!_isdSelected)
                return ApduResponse.Error(SW_CONDITIONS_NOT_SATISFIED);

            var expectedLength = _scpVersion == 0x03 ? 16 : 8;
            if (apdu.Data.Length < expectedLength)
                return ApduResponse.Error(SW_WRONG_LENGTH);

            // Extract security level
            _securityLevel = apdu.P1;

            // For simplicity, we'll accept any authentication data
            // In real implementation, would verify host cryptogram and MAC
            _secureChannelEstablished = true;

            return ApduResponse.Success();
        }

        /// <inheritdoc />
        protected override ApduResponse ProcessStoreData(ApduCommand apdu)
        {
            // For testing, accept STORE DATA commands without secure channel wrapping
            // In production, these would need proper secure messaging
            var structureFormat = apdu.P1;
            var data = apdu.Data;

            // Debug output
            Console.WriteLine(
                $"ProcessStoreData called: P1=0x{structureFormat:X2}, DataLen={data.Length}"
            );

            if (structureFormat == 0x80) // DGI format
            {
                return ProcessStoreDataDgi(data);
            }

            return ApduResponse.Error(SW_INCORRECT_P1P2);
        }

        /// <inheritdoc />
        protected override ApduResponse ProcessPutKey(ApduCommand apdu)
        {
            if (!_secureChannelEstablished)
                return ApduResponse.Error(SW_CONDITIONS_NOT_SATISFIED);

            // Parse PUT KEY command
            var keyUsageQualifier = apdu.P1;
            var keyIdentifier = apdu.P2;
            var data = apdu.Data;

            if (data.Length < 1)
                return ApduResponse.Error(SW_WRONG_LENGTH);

            var newKeyVersion = data[0];
            var offset = 1;

            // Process key data blocks
            var keyCheckValues = new List<byte[]>();
            while (offset < data.Length)
            {
                if (offset + 2 > data.Length)
                    return ApduResponse.Error(SW_WRONG_LENGTH);

                var keyType = data[offset++];
                var keyLength = data[offset++];

                if (offset + keyLength > data.Length)
                    return ApduResponse.Error(SW_WRONG_LENGTH);

                var keyValue = new byte[keyLength];
                Array.Copy(data, offset, keyValue, 0, keyLength);
                offset += keyLength;

                // Check for key check value
                if (offset + 3 <= data.Length)
                {
                    var kcv = new byte[3];
                    Array.Copy(data, offset, kcv, 0, 3);
                    keyCheckValues.Add(kcv);
                    offset += 3;
                }
            }

            // For emulation, just update the current key version
            _currentKeyVersion = newKeyVersion;

            // Build response with key check values
            var response = new List<byte>();
            response.Add(newKeyVersion);
            foreach (var kcv in keyCheckValues)
            {
                response.AddRange(kcv);
            }

            return ApduResponse.Success(response.ToArray());
        }

        /// <inheritdoc />
        protected override ApduResponse ProcessGetData(ApduCommand apdu)
        {
            var baseResponse = base.ProcessGetData(apdu);
            if (baseResponse.IsSuccessful)
                return baseResponse;

            // Handle P71-specific data objects
            var dataObjectId = (ushort)((apdu.P1 << 8) | apdu.P2);
            return dataObjectId switch
            {
                0x0042 => ApduResponse.Success(new byte[] { 0x12, 0x34, 0x56, 0x78 }), // IIN
                0x0045 => ApduResponse.Success(new byte[] { 0xAB, 0xCD, 0xEF }), // CIN
                0x0066 => GetCardData(), // Card Data
                0x0067 => GetCardCapabilities(), // Card Capabilities
                0x00E0 => GetKeyInformationTemplate(), // Key Information Template
                0x00C6 => ApduResponse.Success(new byte[] { 0x00, 0xFF, 0xFF }), // Free memory
                0x00CF => GetScpConfiguration(), // SCP configuration
                _ => ApduResponse.Error(SW_REFERENCED_DATA_NOT_FOUND),
            };
        }

        private ApduResponse GetKeyInformationTemplate()
        {
            var keyInfo = new List<byte>();
            keyInfo.Add(0xE0); // Tag

            var content = new List<byte>();

            // Add key information for each configured key
            foreach (var kvp in StaticKeys)
            {
                var keyVersion = kvp.Key;
                var keySet = kvp.Value;

                // Key 1 (ENC)
                content.Add(0xC0);
                content.Add(0x04);
                content.Add(0x01); // Key ID
                content.Add(keyVersion);
                content.Add(0x88); // AES key type for SCP03
                content.Add(0x10); // 16 bytes

                // Key 2 (MAC)
                content.Add(0xC0);
                content.Add(0x04);
                content.Add(0x02); // Key ID
                content.Add(keyVersion);
                content.Add(0x88); // AES key type for SCP03
                content.Add(0x10); // 16 bytes

                // Key 3 (DEK)
                content.Add(0xC0);
                content.Add(0x04);
                content.Add(0x03); // Key ID
                content.Add(keyVersion);
                content.Add(0x88); // AES key type for SCP03
                content.Add(0x10); // 16 bytes
            }

            keyInfo.Add((byte)content.Count);
            keyInfo.AddRange(content);

            return ApduResponse.Success(keyInfo.ToArray());
        }

        private ApduResponse GetCardData()
        {
            // Card Data with GlobalPlatform OID
            var cardData = new byte[]
            {
                0x73,
                0x0A, // Card recognition data tag
                0x06,
                0x08, // OID tag
                0x2A,
                0x86,
                0x48,
                0x86,
                0xFC,
                0x6B,
                0x01,
                0x00, // GlobalPlatform OID
            };
            return ApduResponse.Success(cardData);
        }

        private ApduResponse GetCardCapabilities()
        {
            // Basic card capabilities - empty for now
            var capabilities = new byte[] { 0x67, 0x00 };
            return ApduResponse.Success(capabilities);
        }

        private ApduResponse GetScpConfiguration()
        {
            // Return current SCP configuration
            if (_configData.TryGetValue(0x00CF, out var config))
            {
                return ApduResponse.Success(config);
            }

            // Default response showing current SCP configuration
            var scpConfig = new List<byte>();
            scpConfig.Add(0xCF); // Tag
            scpConfig.Add(0x0A); // Length
            scpConfig.Add((byte)(_scpVersion << 4 | (_scpImplementation >> 4))); // SCP version and implementation
            scpConfig.Add((byte)(_scpImplementation & 0xFF));
            // Add empty slots
            for (int i = 0; i < 8; i++)
            {
                scpConfig.Add(0x00);
            }

            return ApduResponse.Success(scpConfig.ToArray());
        }

        private byte[] GenerateCardChallenge()
        {
            // For SCP03 i=70, use pseudo-random challenge
            if (_scpVersion == 0x03 && _scpImplementation == 0x70)
            {
                // In real implementation, this would be pseudo-random based on internal counter
                return Convert.FromHexString("F2E867C1DA49BAB8");
            }
            else
            {
                // For SCP02 or other implementations, use fixed value for testing
                return Convert.FromHexString("000303D2C0BAFBF0");
            }
        }

        private void GenerateSessionKeys(byte keyVersion)
        {
            if (!StaticKeys.TryGetValue(keyVersion, out var staticKeys))
            {
                // Fall back to default keys if version not found
                staticKeys = StaticKeys[_defaultKeyVersion];
            }

            _sessionKeys = new SessionKeys();

            if (_scpVersion == 0x03)
            {
                // SCP03 session keys (simplified - real implementation would use KDF)
                _sessionKeys.SMac = Convert.FromHexString("3DBB70544697977EF2C45FA4C2D798BD");
                _sessionKeys.SEnc = Convert.FromHexString("0B7F02159A538077AD5A499E3C525AB4");
                _sessionKeys.RMac = Convert.FromHexString("31B070084A068C03F206825795CF3555");
            }
            else
            {
                // SCP02 session keys (simplified)
                _sessionKeys.EncKey = Convert.FromHexString("339F1D7F5D5841EB034F5CE234557894");
                _sessionKeys.MacKey = Convert.FromHexString("C6713F31B8DC1F8905DFECB4065CB81E");
                _sessionKeys.DekKey = Convert.FromHexString("06E72D52EEFBD1D8DB5C230C3F2B56E9");
            }
        }

        private byte[] CalculateCardCryptogram()
        {
            // Simplified cryptogram calculation for testing
            if (_scpVersion == 0x03)
            {
                return Convert.FromHexString("67B21792A5EEC190");
            }
            else
            {
                return Convert.FromHexString("D31B42E57648A0C5");
            }
        }

        /// <inheritdoc />
        protected override ApduResponse ProcessScpEnable(byte[] value)
        {
            var result = base.ProcessScpEnable(value);

            // If SCP_ENABLE was updated to SCP03 only, update default key version
            if (result.IsSuccessful && value.Length >= 2)
            {
                var firstImpl = (ushort)((value[0] << 8) | value[1]);
                if ((firstImpl >> 8) == 0x03) // SCP03
                {
                    // Set default key version to 1 (GP test keys) for SCP03
                    _defaultKeyVersion = 0x01;
                }
            }

            return result;
        }
    }
}
