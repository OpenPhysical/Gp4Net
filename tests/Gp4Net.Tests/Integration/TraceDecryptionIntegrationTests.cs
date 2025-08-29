using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Integration tests for trace decryption using real trace files.
/// Tests end-to-end functionality with actual card trace data.
/// </summary>
[TestFixture]
[Category("Integration")]
public class TraceDecryptionIntegrationTests
{
    private readonly TraceApduDecryptorService _decryptorService;
    private const string TraceDataPath = "TestData/Traces";

    public TraceDecryptionIntegrationTests()
    {
        _decryptorService = new TraceApduDecryptorService(NullLogger<TraceApduDecryptorService>.Instance);
    }

    [Test]
    public void DecryptTrace_WithConfigureGpshellTrace_ShouldProcessSuccessfully()
    {
        // Trace file must be available for test to run
        string tracePath = Path.Combine(TraceDataPath, "Complex", "configure_gpshell_log.json");
        _ = File.Exists(tracePath).Should().BeTrue($"Test requires trace file at: {tracePath}");

        JsonDocument traceData = LoadTraceFile(tracePath);
        Gp4Net.Domain.Security.TraceExchange[] exchanges = ExtractExchangesFromTrace(traceData);

        // Use test session keys (in real scenario, these would be derived from actual keys)
        SessionKeys sessionKeys = CreateTestSessionKeys();
        SecurityLevel securityLevel = SecurityLevel.None; // Start with no security for plaintext commands
        ScpVersion protocolVersion = ScpVersion.Scp03;

        Result<DecryptedTrace, SmartCardError> result = _decryptorService.DecryptTrace(exchanges, sessionKeys, securityLevel, protocolVersion);

        _ = result.IsSuccess.Should().BeTrue("Trace decryption should succeed even with plaintext commands");
        DecryptedTrace? decryptedTrace = result.Value;
        _ = decryptedTrace.Exchanges.Should().NotBeEmpty("Trace should contain exchanges");

        // Verify all exchanges have valid decrypted APDUs
        foreach (DecryptedExchange? exchange in decryptedTrace.Exchanges)
        {
            _ = exchange.Command.Should().NotBeNull();
            _ = exchange.Response.Should().NotBeNull();
            _ = exchange.Command.OriginalBytes.Should().NotBeEmpty();
            _ = exchange.Response.OriginalBytes.Should().NotBeEmpty();

            // Verify response descriptions include status word information
            if (exchange.Response.Direction == ApduDirection.Response)
            {
                _ = exchange.Response.Description.Should().Contain("Response:");
            }
        }
    }

    [Test]
    public void DecryptTrace_WithMixedSecurityLevels_ShouldHandleGracefully()
    {
        // Create a mixed trace with both plaintext and secure messaging
        Gp4Net.Domain.Security.TraceExchange[] exchanges =
        [

            // Plaintext SELECT command
            new Gp4Net.Domain.Security.TraceExchange(1,
                HexStringToBytes("00A4040008A000000151000000"),
                HexStringToBytes("9000")),

            // Secure messaging command (simulated)
            new Gp4Net.Domain.Security.TraceExchange(2,
                HexStringToBytes("84500000081234567890ABCDEF"),
                HexStringToBytes("9000")),

            // Another plaintext command
            new Gp4Net.Domain.Security.TraceExchange(3,
                HexStringToBytes("80CA006600"),
                HexStringToBytes("6A88"))
        ];

        SessionKeys sessionKeys = CreateTestSessionKeys();
        SecurityLevel securityLevel = SecurityLevel.CMac;
        ScpVersion protocolVersion = ScpVersion.Scp03;

        Result<DecryptedTrace, SmartCardError> result = _decryptorService.DecryptTrace(exchanges, sessionKeys, securityLevel, protocolVersion);

        _ = result.IsSuccess.Should().BeTrue("Service should handle mixed security levels gracefully");
        DecryptedTrace? decryptedTrace = result.Value;
        _ = decryptedTrace.Exchanges.Should().HaveCount(3);

        // First exchange should be plaintext
        _ = decryptedTrace.Exchanges[0].Command.Status.Should().Be(DecryptionStatus.PlainText);
        _ = decryptedTrace.Exchanges[0].Response.Status.Should().Be(DecryptionStatus.PlainText);

        // Verify response status word descriptions
        _ = decryptedTrace.Exchanges[0].Response.Description.Should().Contain("Success");
        _ = decryptedTrace.Exchanges[2].Response.Description.Should().Contain("Referenced Data Not Found");
    }

    [Test]
    public void DecryptApdu_WithKnownStatusWords_ShouldProvideDescriptions()
    {
        (ushort StatusWord, string Description)[] testCases =
        [
            (StatusWord: (ushort)0x9000, Description: "Success"),
            (StatusWord: (ushort)0x6982, Description: "Security Status Not Satisfied"),
            (StatusWord: (ushort)0x6A88, Description: "Referenced Data Not Found"),
            (StatusWord: (ushort)0x6985, Description: "Conditions Not Satisfied"),
            (StatusWord: (ushort)0x6F00, Description: "General Error")
        ];

        SessionKeys sessionKeys = CreateTestSessionKeys();
        SecureChannelState sessionState = CreateTestSessionState(sessionKeys, SecurityLevel.None, ScpVersion.Scp03);

        foreach ((ushort statusWord, string expectedDescription) in testCases)
        {
            byte[] responseBytes = [(byte)(statusWord >> 8), (byte)(statusWord & 0xFF)];

            Result<(DecryptedApdu decryptedApdu, SecureChannelState updatedState), SmartCardError> result = _decryptorService.DecryptApdu(responseBytes, ApduDirection.Response, sessionState);

            _ = result.IsSuccess.Should().BeTrue($"Decryption should succeed for status word 0x{statusWord:X4}");
            (DecryptedApdu decryptedApdu, _) = result.Value;
            _ = decryptedApdu.Description.Should().Contain(expectedDescription,
                $"Description should include '{expectedDescription}' for status word 0x{statusWord:X4}");
        }
    }

    [Test]
    public void DecryptTrace_WithInvalidTrace_ShouldHandleGracefully()
    {
        // Create exchanges with malformed APDUs
        Gp4Net.Domain.Security.TraceExchange[] exchanges =
        [
            new Gp4Net.Domain.Security.TraceExchange(1,
                [0x00], // Too short for valid APDU
                [0x90, 0x00]),

            new Gp4Net.Domain.Security.TraceExchange(2,
                [0x00, 0xA4, 0x04, 0x00, 0x08], // Missing data despite Lc=8
                [0x6F, 0x00])
        ];

        SessionKeys sessionKeys = CreateTestSessionKeys();
        SecurityLevel securityLevel = SecurityLevel.None;
        ScpVersion protocolVersion = ScpVersion.Scp03;

        Result<DecryptedTrace, SmartCardError> result = _decryptorService.DecryptTrace(exchanges, sessionKeys, securityLevel, protocolVersion);

        // Should succeed with graceful degradation
        _ = result.IsSuccess.Should().BeTrue("Service should handle malformed APDUs gracefully");
        DecryptedTrace? decryptedTrace = result.Value;
        _ = decryptedTrace.Exchanges.Should().HaveCount(2, "All exchanges should be included even if some fail");
    }

    [TestCase("Complex/gp_pro_list_success.json")]
    [TestCase("Complex/configure_gpshell.json")]
    public void DecryptTrace_WithRealTraceFiles_ShouldProcessWhenAvailable(string relativeTracePath)
    {
        string tracePath = Path.Combine(TraceDataPath, relativeTracePath);
        _ = File.Exists(tracePath).Should().BeTrue($"Test requires trace file at: {tracePath}");

        JsonDocument traceData = LoadTraceFile(tracePath);
        Gp4Net.Domain.Security.TraceExchange[] exchanges = ExtractExchangesFromTrace(traceData);

        _ = exchanges.Should().NotBeEmpty($"Trace file {tracePath} must contain exchanges to test");

        SessionKeys sessionKeys = CreateTestSessionKeys();
        SecurityLevel securityLevel = SecurityLevel.None;
        ScpVersion protocolVersion = ScpVersion.Scp03;

        Result<DecryptedTrace, SmartCardError> result = _decryptorService.DecryptTrace(exchanges, sessionKeys, securityLevel, protocolVersion);

        _ = result.IsSuccess.Should().BeTrue($"Should successfully process trace file: {relativeTracePath}");
        DecryptedTrace? decryptedTrace = result.Value;
        _ = decryptedTrace.Exchanges.Should().NotBeEmpty("Trace should contain exchanges");

        // Verify basic structure integrity
        foreach (DecryptedExchange? exchange in decryptedTrace.Exchanges)
        {
            _ = exchange.Id.Should().BeGreaterThan(0, "Exchange ID should be positive");
            _ = exchange.Command.OriginalBytes.Should().NotBeEmpty("Command should have data");
            _ = exchange.Response.OriginalBytes.Should().NotBeEmpty("Response should have data");
        }
    }

    private static JsonDocument LoadTraceFile(string tracePath)
    {
        string jsonContent = File.ReadAllText(tracePath);
        return JsonDocument.Parse(jsonContent);
    }

    private static Gp4Net.Domain.Security.TraceExchange[] ExtractExchangesFromTrace(JsonDocument traceData)
    {
        if (!traceData.RootElement.TryGetProperty("exchanges", out JsonElement exchangesElement))
        {
            return [];
        }

        List<Gp4Net.Domain.Security.TraceExchange> exchanges = [];
        int currentIndex = 1; // Default index counter for traces without explicit indices

        foreach (JsonElement exchangeElement in exchangesElement.EnumerateArray())
        {
            if (exchangeElement.TryGetProperty("command", out JsonElement commandProp) &&
                exchangeElement.TryGetProperty("response", out JsonElement responseProp))
            {
                // Try to get explicit index, or use auto-incrementing counter
                int index = exchangeElement.TryGetProperty("index", out JsonElement indexProp)
                    ? indexProp.GetInt32()
                    : currentIndex++;

                string commandHex = commandProp.GetString() ?? "";
                string responseHex = responseProp.GetString() ?? "";

                if (!string.IsNullOrEmpty(commandHex) && !string.IsNullOrEmpty(responseHex))
                {
                    exchanges.Add(new Gp4Net.Domain.Security.TraceExchange(
                        index,
                        HexStringToBytes(commandHex),
                        HexStringToBytes(responseHex)));
                }
            }
        }

        return exchanges.ToArray();
    }

    private static byte[] HexStringToBytes(string hex)
    {
        // Remove any whitespace and ensure even length
        hex = hex.Replace(" ", "").Replace("\t", "").Replace("\n", "");
        if (hex.Length % 2 != 0)
        {
            hex = "0" + hex;
        }

        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    private static SessionKeys CreateTestSessionKeys()
    {
        byte[] key = new byte[16]; // AES-128 key for SCP03
        Array.Fill(key, (byte)0x01);

        return new SessionKeys(
            sEnc: key,
            sMac: key,
            sRMac: key,
            dek: key);
    }

    private static SecureChannelState CreateTestSessionState(SessionKeys sessionKeys, SecurityLevel securityLevel, byte protocolVersion)
    {
        byte[] macChaining = protocolVersion == ScpVersion.Scp03 ? new byte[16] : new byte[8];

        return SecureChannelState.Create(
            sessionKeys,
            securityLevel,
            protocolVersion,
            macChaining,
            0x00).Value;
    }
}
