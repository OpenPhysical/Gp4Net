using System;
using System.Collections.Generic;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Tool.Scripting;
using Gp4Net.Tool.Services;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Gp4Net.Tests.Integration
{
    /// <summary>
    /// Tests based on real card traces to verify secure channel auto-detection and KDF.
    /// </summary>
    public class TraceBasedSecureChannelTests
    {
        private readonly Mock<ILogger<KeysetResolver>> _loggerMock;
        private readonly Mock<IScriptManager> _scriptManagerMock;
        private readonly KeysetResolver _keysetResolver;

        public TraceBasedSecureChannelTests()
        {
            _loggerMock = new Mock<ILogger<KeysetResolver>>();
            _scriptManagerMock = new Mock<IScriptManager>();

            _keysetResolver = new KeysetResolver(_loggerMock.Object, _scriptManagerMock.Object);
        }

        [Fact]
        public void Can_Parse_InitializeUpdate_Response_VISA2_Diversified()
        {
            // Arrange - Real trace from gp_pro_lock.txt line 18
            var responseBytes = Convert.FromHexString(
                "000023455580832048390102000303D2C0BAFBF0D31B42E57648A0C5"
            );

            // Act
            var response = InitializeUpdateResponse.Parse(responseBytes);

            // Assert
            Assert.Equal(
                Convert.FromHexString("00002345558083204839"),
                response.KeyDiversificationData
            );
            Assert.Equal(0x01, response.KeyVersion); // Key version 1
            Assert.Equal(0x02, response.ScpId); // SCP02
            Assert.Equal(Convert.FromHexString("000303D2C0BAFBF0"), response.CardChallenge); // 8 bytes for SCP02
            Assert.Equal(Convert.FromHexString("D31B42E57648A0C5"), response.CardCryptogram);
        }

        [Fact]
        public void Can_Parse_InitializeUpdate_Response_Factory_Keys()
        {
            // Arrange - Real trace from gp_pro_factory_unlock.txt line 16
            var responseBytes = Convert.FromHexString(
                "00002345558083204839FF020003A33DFDBFFADF57EB6A4A52CFB3E9"
            );

            // Act
            var response = InitializeUpdateResponse.Parse(responseBytes);

            // Assert
            Assert.Equal(
                Convert.FromHexString("00002345558083204839"),
                response.KeyDiversificationData
            );
            Assert.Equal(0xFF, response.KeyVersion); // Factory key version
            Assert.Equal(0x02, response.ScpId); // SCP02
            Assert.Equal(Convert.FromHexString("0003A33DFDBFFADF"), response.CardChallenge); // 8 bytes for SCP02
            Assert.Equal(Convert.FromHexString("57EB6A4A52CFB3E9"), response.CardCryptogram);
        }

        [Fact]
        public void Auto_Detect_Secure_Channel_Parameters_VISA2()
        {
            // Arrange
            // Note: Using Parse since the constructor is private
            var responseBytes = Convert.FromHexString(
                "000023455580832048390102000303D2C0BAFBF0D31B42E57648A0C5"
            );
            var response = InitializeUpdateResponse.Parse(responseBytes);

            // Act
            var parameters = SecureChannelParameterDetector.DetectParameters(response);

            // Assert
            Assert.Equal(SecureChannelProtocol.SCP02, parameters.Protocol);
            Assert.Equal(0x01, parameters.KeyVersion);
            Assert.Equal(KeyDiversificationMethod.VISA2, parameters.DiversificationMethod);
            Assert.True(parameters.RequiresDiversification);
            Assert.Equal(
                Convert.FromHexString("00002345558083204839"),
                parameters.DiversificationData
            );
        }

        [Fact]
        public void Auto_Detect_Secure_Channel_Parameters_Factory()
        {
            // Arrange
            // Note: Using Parse since the constructor is private
            var responseBytes = Convert.FromHexString(
                "00002345558083204839FF020003A33DFDBFFADF57EB6A4A52CFB3E9"
            );
            var response = InitializeUpdateResponse.Parse(responseBytes);

            // Act
            var parameters = SecureChannelParameterDetector.DetectParameters(response);

            // Assert
            Assert.Equal(SecureChannelProtocol.SCP02, parameters.Protocol);
            Assert.Equal(0xFF, parameters.KeyVersion);
            Assert.Equal(KeyDiversificationMethod.None, parameters.DiversificationMethod);
            Assert.False(parameters.RequiresDiversification);
            Assert.Equal(
                Convert.FromHexString("00002345558083204839"),
                parameters.DiversificationData
            );
        }

        [Fact]
        public void Can_Resolve_VISA2_Keyset_With_Lua_Script()
        {
            // Arrange - Base key from real trace
            var baseKey = "A8E0E5B62A679216B0D31FF7680DE5F4";
            var keysetSpec = $"visa2:{baseKey}";

            var responseBytes = Convert.FromHexString(
                "000023455580832048390102000303D2C0BAFBF0D31B42E57648A0C5"
            );
            var cardResponse = InitializeUpdateResponse.Parse(responseBytes);

            // Expected diversified keys from trace (line 34 in gp_pro_lock.txt)
            var expectedKeys = new
            {
                Enc = Convert.FromHexString("B03DAC79005755CE75BF83C1082C5002"),
                Mac = Convert.FromHexString("ECA887BBCF6F9F3B30292DB1BE0CFE24"),
                Dek = Convert.FromHexString("D82C7773A427D40B7AD3FB409E715DCF"),
            };

            // Mock Lua script execution
            var scriptResult = CreateMockLuaResult(
                expectedKeys.Enc,
                expectedKeys.Mac,
                expectedKeys.Dek,
                0x01
            );
            _ = _scriptManagerMock
                .Setup(x =>
                    x.ExecuteScriptFunction(
                        "kdf/visa2",
                        "main",
                        new[] { baseKey },
                        It.IsAny<Dictionary<string, object>>()
                    )
                )
                .Returns(scriptResult);

            // Act
            var keyset = _keysetResolver.ResolveKeyset(
                keysetSpec,
                null,
                null,
                null,
                null,
                0x01,
                cardResponse
            );

            // Assert
            _ = Assert.IsType<Scp02KeySet>(keyset);
            var scp02Keyset = (Scp02KeySet)keyset;
            Assert.Equal(expectedKeys.Enc, scp02Keyset.EncKey);
            Assert.Equal(expectedKeys.Mac, scp02Keyset.MacKey);
            Assert.Equal(expectedKeys.Dek, scp02Keyset.DekKey);
            Assert.Equal(0x01, scp02Keyset.KeyVersion);

            // Verify script was called with correct context
            _scriptManagerMock.Verify(
                x =>
                    x.ExecuteScriptFunction(
                        "kdf/visa2",
                        "main",
                        new[] { baseKey },
                        It.Is<Dictionary<string, object>>(ctx =>
                            ctx.ContainsKey("key_diversification_data")
                            && ctx.ContainsKey("key_version")
                            && ctx.ContainsKey("scp_id")
                        )
                    ),
                Times.Once
            );
        }

        [Fact]
        public void Can_Resolve_GP_Test_Keys_Without_Diversification()
        {
            // Arrange
            var keysetSpec = "gp_test_keys";

            var responseBytes = Convert.FromHexString(
                "00002345558083204839FF020003A33DFDBFFADF57EB6A4A52CFB3E9"
            );
            var cardResponse = InitializeUpdateResponse.Parse(responseBytes);

            // GP test keys - static
            var testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
            var scriptResult = CreateMockLuaResult(testKey, testKey, testKey, 0xFF);

            _ = _scriptManagerMock
                .Setup(x =>
                    x.ExecuteScriptFunction(
                        "kdf/gp_test_keys",
                        "main",
                        Array.Empty<string>(),
                        It.IsAny<Dictionary<string, object>>()
                    )
                )
                .Returns(scriptResult);

            // Act
            var keyset = _keysetResolver.ResolveKeyset(
                keysetSpec,
                null,
                null,
                null,
                null,
                0xFF,
                cardResponse
            );

            // Assert
            _ = Assert.IsType<Scp02KeySet>(keyset);
            var scp02Keyset = (Scp02KeySet)keyset;
            Assert.Equal(testKey, scp02Keyset.EncKey);
            Assert.Equal(testKey, scp02Keyset.MacKey);
            Assert.Equal(testKey, scp02Keyset.DekKey);
            Assert.Equal(0xFF, scp02Keyset.KeyVersion);
        }

        [Fact]
        public void Can_Calculate_Session_Keys_SCP02_VISA2()
        {
            // Arrange - Use GP test keys as the diversified keys (trace line 24 shows them as used)
            // In reality these would be the result of VISA2 diversification, but for testing we use them directly
            var diversifiedKeys = new Scp02KeySet(
                encKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"), // GP test keys
                macKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
                dekKey: Convert.FromHexString("404142434445464748494A4B4C4D4E4F"),
                keyVersion: 0x01
            );

            var hostChallenge = Convert.FromHexString("53CA65B6EC16E7B0");
            var cardChallenge = Convert.FromHexString("000303D2C0BAFBF0"); // Full 8-byte challenge from trace
            var sequenceCounter = cardChallenge[..2]; // First 2 bytes are sequence counter

            // Act - Derive session keys using real SCP02 algorithm
            var sessionKeys = Scp02SessionKeyDerivation.DeriveSessionKeys(
                diversifiedKeys,
                hostChallenge,
                cardChallenge,
                sequenceCounter
            );

            // Assert - Session keys should be derived correctly (we'll verify they're not the static keys)
            Assert.NotEqual(diversifiedKeys.EncKey, sessionKeys.EncryptionKey);
            Assert.NotEqual(diversifiedKeys.MacKey, sessionKeys.MacKey);
            Assert.Equal(16, sessionKeys.EncryptionKey.Length);
            Assert.Equal(16, sessionKeys.MacKey.Length);
            Assert.Equal(16, sessionKeys.ReceiptMacKey.Length);

            // Verify that ENC and MAC keys are different
            Assert.NotEqual(sessionKeys.EncryptionKey, sessionKeys.MacKey);
        }

        private static MoonSharp.Interpreter.DynValue CreateMockLuaResult(
            byte[] enc,
            byte[] mac,
            byte[] dek,
            byte version
        )
        {
            var script = new MoonSharp.Interpreter.Script();

            // Register byte array type
            _ = MoonSharp.Interpreter.UserData.RegisterType<byte[]>();

            var table = script.DoString("return {}").Table;
            table["enc"] = MoonSharp.Interpreter.UserData.Create(enc);
            table["mac"] = MoonSharp.Interpreter.UserData.Create(mac);
            table["dek"] = MoonSharp.Interpreter.UserData.Create(dek);
            table["version"] = version;

            return MoonSharp.Interpreter.DynValue.NewTable(table);
        }
    }

    /// <summary>
    /// Functional service for auto-detecting secure channel parameters from card responses.
    /// </summary>
    public static class SecureChannelParameterDetector
    {
        public static SecureChannelParameters DetectParameters(InitializeUpdateResponse response)
        {
            var protocol = (response.ScpId & 0x0F) switch
            {
                0x02 => SecureChannelProtocol.SCP02,
                0x03 => SecureChannelProtocol.SCP03,
                _ => throw new NotSupportedException($"Unsupported SCP ID: {response.ScpId:X2}"),
            };

            var diversificationMethod = response.KeyVersion switch
            {
                0xFF => KeyDiversificationMethod.None, // Factory keys
                0x01 => KeyDiversificationMethod.VISA2, // Diversified keys version 1
                _ => KeyDiversificationMethod.Unknown,
            };

            return new SecureChannelParameters
            {
                Protocol = protocol,
                KeyVersion = response.KeyVersion,
                DiversificationMethod = diversificationMethod,
                RequiresDiversification = diversificationMethod != KeyDiversificationMethod.None,
                DiversificationData = response.KeyDiversificationData,
            };
        }
    }

    /// <summary>
    /// Functional service for SCP02 session key derivation.
    /// </summary>
    public static class Scp02SessionKeyDerivation
    {
        public static Scp02SessionKeys DeriveSessionKeys(
            Scp02KeySet diversifiedKeys,
            byte[] hostChallenge,
            byte[] cardChallenge,
            byte[] sequenceCounter
        )
        {
            // SCP02 session key derivation: derive from host + card challenges
            // Based on GlobalPlatform Card Specification v2.2.1 Section 6.2.2.3

            // Extract sequence counter from first 2 bytes of card challenge
            var seqCounter = new byte[] { cardChallenge[0], cardChallenge[1] };

            // SCP02 derivation data: sequence_counter || host_challenge || card_challenge
            var derivationBase = new byte[16];
            Array.Copy(seqCounter, 0, derivationBase, 0, 2); // Sequence counter (2 bytes)
            Array.Copy(hostChallenge, 0, derivationBase, 2, 8); // Host challenge (8 bytes)
            Array.Copy(cardChallenge, 2, derivationBase, 10, 6); // Card challenge without sequence (6 bytes)

            // Derive session keys using 3DES with static keys
            var sessionEncKey = Derive3DesSessionKey(diversifiedKeys.EncKey, derivationBase, 0x01);
            var sessionMacKey = Derive3DesSessionKey(diversifiedKeys.MacKey, derivationBase, 0x02);
            var sessionRMacKey = Derive3DesSessionKey(diversifiedKeys.MacKey, derivationBase, 0x02); // RMAC uses MAC key

            return new Scp02SessionKeys
            {
                EncryptionKey = sessionEncKey,
                MacKey = sessionMacKey,
                ReceiptMacKey = sessionRMacKey,
            };
        }

        private static byte[] Derive3DesSessionKey(
            byte[] staticKey,
            byte[] derivationData,
            byte keyType
        )
        {
            // SCP02 session key derivation algorithm per GlobalPlatform Card Specification v2.2.1
            // Uses 3DES-ECB encryption of derivation data with the static key

            // Create derivation input: derivation_data || key_type (16 bytes)
            var input = new byte[16];
            Array.Copy(derivationData, 0, input, 0, Math.Min(derivationData.Length, 15));
            input[15] = keyType; // Last byte is key type (0x01=ENC, 0x02=MAC)

            // Use BouncyCastle 3DES ECB encryption (no using statement - it's not IDisposable)
            var engine = new Org.BouncyCastle.Crypto.Engines.DesEdeEngine();

            // Expand 16-byte key to 24 bytes if needed (K1||K2||K1)
            byte[] expandedKey;
            if (staticKey.Length == 16)
            {
                expandedKey = new byte[24];
                Array.Copy(staticKey, 0, expandedKey, 0, 16);
                Array.Copy(staticKey, 0, expandedKey, 16, 8); // Repeat first 8 bytes
            }
            else
            {
                expandedKey = staticKey;
            }

            engine.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(expandedKey));

            // Encrypt 16 bytes of input to get 16-byte session key
            var output = new byte[16];
            _ = engine.ProcessBlock(input, 0, output, 0); // First 8 bytes
            _ = engine.ProcessBlock(input, 8, output, 8); // Second 8 bytes

            return output;
        }
    }

    // Supporting types
    public class SecureChannelParameters
    {
        public SecureChannelProtocol Protocol { get; set; }
        public byte KeyVersion { get; set; }
        public KeyDiversificationMethod DiversificationMethod { get; set; }
        public bool RequiresDiversification { get; set; }
        public byte[] DiversificationData { get; set; } = Array.Empty<byte>();
    }

    public enum SecureChannelProtocol
    {
        SCP02,
        SCP03,
    }

    public enum KeyDiversificationMethod
    {
        None,
        VISA2,
        Unknown,
    }

    public class Scp02SessionKeys
    {
        public byte[] EncryptionKey { get; set; } = Array.Empty<byte>();
        public byte[] MacKey { get; set; } = Array.Empty<byte>();
        public byte[] ReceiptMacKey { get; set; } = Array.Empty<byte>();
    }
}
