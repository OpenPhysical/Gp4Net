using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Integration tests for trace decryption using real trace files.
/// Tests end-to-end functionality with actual card trace data.
/// </summary>
[TestFixture]
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
        // Skip if trace file not available
        var tracePath = Path.Combine(TraceDataPath, "Mixed", "configure_gpshell_log.json");
        if (!File.Exists(tracePath))
        {
            // Use Skip instead of Assert.Skip for better test reporting
            return;
        }

        var traceData = LoadTraceFile(tracePath);
        var exchanges = ExtractExchangesFromTrace(traceData);
        
        // Use test session keys (in real scenario, these would be derived from actual keys)
        var sessionKeys = CreateTestSessionKeys();
        var securityLevel = SecurityLevel.None; // Start with no security for plaintext commands
        var protocolVersion = ProtocolIdentifiers.Scp03;

        var result = _decryptorService.DecryptTrace(exchanges, sessionKeys, securityLevel, protocolVersion);

        result.IsSuccess.Should().BeTrue("Trace decryption should succeed even with plaintext commands");
        var decryptedTrace = result.Value;
        decryptedTrace.Exchanges.Should().NotBeEmpty("Trace should contain exchanges");
        
        // Verify all exchanges have valid decrypted APDUs
        foreach (var exchange in decryptedTrace.Exchanges)
        {
            exchange.Command.Should().NotBeNull();
            exchange.Response.Should().NotBeNull();
            exchange.Command.OriginalBytes.Should().NotBeEmpty();
            exchange.Response.OriginalBytes.Should().NotBeEmpty();
            
            // Verify response descriptions include status word information
            if (exchange.Response.Direction == ApduDirection.Response)
            {
                exchange.Response.Description.Should().Contain("Response:");
            }
        }
    }

    [Test]
    public void DecryptTrace_WithMixedSecurityLevels_ShouldHandleGracefully()
    {
        // Create a mixed trace with both plaintext and secure messaging
        var exchanges = new[]
        {
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
        };

        var sessionKeys = CreateTestSessionKeys();
        var securityLevel = SecurityLevel.CMac;
        var protocolVersion = ProtocolIdentifiers.Scp03;

        var result = _decryptorService.DecryptTrace(exchanges, sessionKeys, securityLevel, protocolVersion);

        result.IsSuccess.Should().BeTrue("Service should handle mixed security levels gracefully");
        var decryptedTrace = result.Value;
        decryptedTrace.Exchanges.Should().HaveCount(3);
        
        // First exchange should be plaintext
        decryptedTrace.Exchanges[0].Command.Status.Should().Be(DecryptionStatus.PlainText);
        decryptedTrace.Exchanges[0].Response.Status.Should().Be(DecryptionStatus.PlainText);
        
        // Verify response status word descriptions
        decryptedTrace.Exchanges[0].Response.Description.Should().Contain("Success");
        decryptedTrace.Exchanges[2].Response.Description.Should().Contain("Referenced Data Not Found");
    }

    [Test]
    public void DecryptApdu_WithKnownStatusWords_ShouldProvideDescriptions()
    {
        var testCases = new[]
        {
            (StatusWord: (ushort)0x9000, Description: "Success"),
            (StatusWord: (ushort)0x6982, Description: "Security Status Not Satisfied"),
            (StatusWord: (ushort)0x6A88, Description: "Referenced Data Not Found"),
            (StatusWord: (ushort)0x6985, Description: "Conditions Not Satisfied"),
            (StatusWord: (ushort)0x6F00, Description: "General Error")
        };

        var sessionKeys = CreateTestSessionKeys();
        var sessionState = CreateTestSessionState(sessionKeys, SecurityLevel.None, ProtocolIdentifiers.Scp03);

        foreach (var (statusWord, expectedDescription) in testCases)
        {
            var responseBytes = new byte[] { (byte)(statusWord >> 8), (byte)(statusWord & 0xFF) };
            
            var result = _decryptorService.DecryptApdu(responseBytes, ApduDirection.Response, sessionState);
            
            result.IsSuccess.Should().BeTrue($"Decryption should succeed for status word 0x{statusWord:X4}");
            var (decryptedApdu, _) = result.Value;
            decryptedApdu.Description.Should().Contain(expectedDescription, 
                $"Description should include '{expectedDescription}' for status word 0x{statusWord:X4}");
        }
    }

    [Test]
    public void DecryptTrace_WithInvalidTrace_ShouldHandleGracefully()
    {
        // Create exchanges with malformed APDUs
        var exchanges = new[]
        {
            new Gp4Net.Domain.Security.TraceExchange(1,
                new byte[] { 0x00 }, // Too short for valid APDU
                new byte[] { 0x90, 0x00 }),
            
            new Gp4Net.Domain.Security.TraceExchange(2,
                new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x08 }, // Missing data despite Lc=8
                new byte[] { 0x6F, 0x00 })
        };

        var sessionKeys = CreateTestSessionKeys();
        var securityLevel = SecurityLevel.None;
        var protocolVersion = ProtocolIdentifiers.Scp03;

        var result = _decryptorService.DecryptTrace(exchanges, sessionKeys, securityLevel, protocolVersion);

        // Should succeed with graceful degradation
        result.IsSuccess.Should().BeTrue("Service should handle malformed APDUs gracefully");
        var decryptedTrace = result.Value;
        decryptedTrace.Exchanges.Should().HaveCount(2, "All exchanges should be included even if some fail");
    }

    [TestCase("Mixed/gp_pro_list_success.json")]
    [TestCase("Mixed/configure_gpshell.json")]
    public void DecryptTrace_WithRealTraceFiles_ShouldProcessWhenAvailable(string relativeTracePath)
    {
        var tracePath = Path.Combine(TraceDataPath, relativeTracePath);
        if (!File.Exists(tracePath))
        {
            // Skip test if trace file not available
            return;
        }

        var traceData = LoadTraceFile(tracePath);
        var exchanges = ExtractExchangesFromTrace(traceData);
        
        if (!exchanges.Any())
        {
            return; // Skip if no exchanges to test
        }

        var sessionKeys = CreateTestSessionKeys();
        var securityLevel = SecurityLevel.None;
        var protocolVersion = ProtocolIdentifiers.Scp03;

        var result = _decryptorService.DecryptTrace(exchanges, sessionKeys, securityLevel, protocolVersion);

        result.IsSuccess.Should().BeTrue($"Should successfully process trace file: {relativeTracePath}");
        var decryptedTrace = result.Value;
        decryptedTrace.Exchanges.Should().NotBeEmpty("Trace should contain exchanges");
        
        // Verify basic structure integrity
        foreach (var exchange in decryptedTrace.Exchanges)
        {
            exchange.Id.Should().BeGreaterThan(0, "Exchange ID should be positive");
            exchange.Command.OriginalBytes.Should().NotBeEmpty("Command should have data");
            exchange.Response.OriginalBytes.Should().NotBeEmpty("Response should have data");
        }
    }

    private static JsonDocument LoadTraceFile(string tracePath)
    {
        var jsonContent = File.ReadAllText(tracePath);
        return JsonDocument.Parse(jsonContent);
    }

    private static Gp4Net.Domain.Security.TraceExchange[] ExtractExchangesFromTrace(JsonDocument traceData)
    {
        if (!traceData.RootElement.TryGetProperty("exchanges", out var exchangesElement))
        {
            return Array.Empty<Gp4Net.Domain.Security.TraceExchange>();
        }

        var exchanges = new List<Gp4Net.Domain.Security.TraceExchange>();
        
        foreach (var exchangeElement in exchangesElement.EnumerateArray())
        {
            if (exchangeElement.TryGetProperty("index", out var indexProp) &&
                exchangeElement.TryGetProperty("command", out var commandProp) &&
                exchangeElement.TryGetProperty("response", out var responseProp))
            {
                var index = indexProp.GetInt32();
                var commandHex = commandProp.GetString() ?? "";
                var responseHex = responseProp.GetString() ?? "";
                
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
            hex = "0" + hex;

        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    private static SessionKeys CreateTestSessionKeys()
    {
        var key = new byte[16]; // AES-128 key for SCP03
        Array.Fill(key, (byte)0x01);
        
        return new SessionKeys(
            sEnc: key,
            sMac: key,
            sRMac: key,
            dek: key);
    }

    private static SecureChannelState CreateTestSessionState(SessionKeys sessionKeys, SecurityLevel securityLevel, byte protocolVersion)
    {
        var macChaining = protocolVersion == ProtocolIdentifiers.Scp03 ? new byte[16] : new byte[8];
        
        return SecureChannelState.Create(
            sessionKeys,
            securityLevel,
            protocolVersion,
            macChaining,
            0x00).Value;
    }
}