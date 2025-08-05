using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.Tests.Unit.Security;

/// <summary>
/// Unit tests for TraceApduDecryptorService.
/// Tests the functional decryption service following established patterns.
/// </summary>
[TestFixture]
public class TraceApduDecryptorServiceTests
{
    private readonly TraceApduDecryptorService _service;
    private readonly ILogger<TraceApduDecryptorService> _logger;

    public TraceApduDecryptorServiceTests()
    {
        _logger = NullLogger<TraceApduDecryptorService>.Instance;
        _service = new TraceApduDecryptorService(_logger);
    }

    [Test]
    public void Constructor_WithNullLogger_ShouldCreateService()
    {
        var service = new TraceApduDecryptorService(null);
        
        service.Should().NotBeNull();
    }

    [Test]
    public void Constructor_WithLogger_ShouldCreateService()
    {
        var service = new TraceApduDecryptorService(_logger);
        
        service.Should().NotBeNull();
    }

    [TestCase(ApduDirection.Command)]
    [TestCase(ApduDirection.Response)]
    public void DecryptApdu_WithPlaintextApdu_ShouldReturnOriginalApdu(ApduDirection direction)
    {
        // Plaintext APDU (no secure messaging indicator)
        var plaintextApdu = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00 };
        var sessionKeys = CreateTestSessionKeys();
        var securityLevel = SecurityLevel.None;
        var sessionState = CreateTestSessionState(sessionKeys, securityLevel, ProtocolIdentifiers.Scp03);

        var result = _service.DecryptApdu(plaintextApdu, direction, sessionState);

        result.IsSuccess.Should().BeTrue();
        var (decryptedApdu, updatedState) = result.Value;
        decryptedApdu.OriginalBytes.Should().BeEquivalentTo(plaintextApdu);
        decryptedApdu.DecryptedBytes.Should().BeEquivalentTo(plaintextApdu);
        decryptedApdu.Direction.Should().Be(direction);
        decryptedApdu.Status.Should().Be(DecryptionStatus.PlainText);
        decryptedApdu.Metadata.Should().Contain("No secure messaging detected");
        updatedState.Should().Be(sessionState); // State unchanged for plaintext
    }

    [Test] 
    public void DecryptApdu_WithSecureCommand_ShouldDetectSecureMessaging()
    {
        // Command with secure messaging indicator (CLA = 0x84)
        var secureCommand = new byte[] { 0x84, 0x50, 0x00, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
        var sessionKeys = CreateTestSessionKeys();
        var securityLevel = SecurityLevel.CMac;
        var sessionState = CreateTestSessionState(sessionKeys, securityLevel, ProtocolIdentifiers.Scp03);

        var result = _service.DecryptApdu(secureCommand, ApduDirection.Command, sessionState);

        result.IsSuccess.Should().BeTrue();
        var (decryptedApdu, _) = result.Value;
        decryptedApdu.Status.Should().NotBe(DecryptionStatus.PlainText);
        decryptedApdu.Metadata.Should().Contain("SCP03");
    }

    [Test]
    public void DecryptTrace_WithEmptyExchanges_ShouldReturnEmptyTrace()
    {
        var exchanges = Array.Empty<TraceExchange>();
        var sessionKeys = CreateTestSessionKeys();
        var securityLevel = SecurityLevel.None;
        var protocolVersion = ProtocolIdentifiers.Scp03;

        var result = _service.DecryptTrace(exchanges, sessionKeys, securityLevel, protocolVersion);

        result.IsSuccess.Should().BeTrue();
        var decryptedTrace = result.Value;
        decryptedTrace.Exchanges.Should().BeEmpty();
        decryptedTrace.SessionKeys.Should().Be(sessionKeys);
        decryptedTrace.SecurityLevel.Should().Be(securityLevel);
        decryptedTrace.ProtocolVersion.Should().Be(protocolVersion);
    }

    [Test]
    public void DecryptTrace_WithPlaintextExchanges_ShouldReturnDecryptedTrace()
    {
        var exchanges = new[]
        {
            new TraceExchange(1, 
                new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00 }, // SELECT
                new byte[] { 0x90, 0x00 }) // Success
        };
        var sessionKeys = CreateTestSessionKeys();
        var securityLevel = SecurityLevel.None;
        var protocolVersion = ProtocolIdentifiers.Scp03;

        var result = _service.DecryptTrace(exchanges, sessionKeys, securityLevel, protocolVersion);

        result.IsSuccess.Should().BeTrue();
        var decryptedTrace = result.Value;
        decryptedTrace.Exchanges.Should().HaveCount(1);
        
        var exchange = decryptedTrace.Exchanges.First();
        exchange.Id.Should().Be(1);
        exchange.Command.Status.Should().Be(DecryptionStatus.PlainText);
        exchange.Response.Status.Should().Be(DecryptionStatus.PlainText);
        exchange.Response.Description.Should().Contain("Success");
    }

    [Test]
    public void DecryptTrace_WithInvalidSessionKeys_ShouldReturnError()
    {
        var exchanges = new[]
        {
            new TraceExchange(1,
                new byte[] { 0x84, 0x50, 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
                new byte[] { 0x90, 0x00 })
        };
        
        // Invalid session keys (empty components)
        var emptyKey = new byte[0];
        var invalidKeys = new SessionKeys(emptyKey, emptyKey, emptyKey, emptyKey);
        var securityLevel = SecurityLevel.CMac;
        var protocolVersion = ProtocolIdentifiers.Scp03;

        var result = _service.DecryptTrace(exchanges, invalidKeys, securityLevel, protocolVersion);

        result.IsFailure.Should().BeTrue();
        result.Error.Should().BeOfType<SmartCardError>();
    }

    [TestCase(ProtocolIdentifiers.Scp02)]
    [TestCase(ProtocolIdentifiers.Scp03)]
    public void DecryptTrace_WithDifferentProtocols_ShouldHandleCorrectly(byte protocolVersion)
    {
        var exchanges = new[]
        {
            new TraceExchange(1,
                new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x00 }, // SELECT with no data
                new byte[] { 0x90, 0x00 }) // Success
        };
        var sessionKeys = CreateTestSessionKeys();
        var securityLevel = SecurityLevel.None;

        var result = _service.DecryptTrace(exchanges, sessionKeys, securityLevel, protocolVersion);

        result.IsSuccess.Should().BeTrue();
        var decryptedTrace = result.Value;
        decryptedTrace.ProtocolVersion.Should().Be(protocolVersion);
    }

    [Test]
    public void DecryptedApdu_Description_ShouldFormatResponseStatusWord()
    {
        var responseBytes = new byte[] { 0x01, 0x02, 0x90, 0x00 }; // Data + Success status
        var decryptedApdu = new DecryptedApdu(responseBytes, ApduDirection.Response, DecryptionStatus.PlainText, "Test");

        decryptedApdu.Description.Should().Contain("Response: 0x9000 (Success)");
    }

    [Test]
    public void DecryptedApdu_Description_ShouldFormatCommand()
    {
        var commandBytes = new byte[] { 0x00, 0xA4, 0x04, 0x00 };
        var decryptedApdu = new DecryptedApdu(commandBytes, ApduDirection.Command, DecryptionStatus.PlainText, "Test");

        decryptedApdu.Description.Should().Contain("Command APDU (4 bytes)");
    }

    [Test]
    public void DecryptedApdu_DecryptedBytes_ShouldReturnOriginalWhenNotDecrypted()
    {
        var originalBytes = new byte[] { 0x01, 0x02, 0x03 };
        var decryptedApdu = new DecryptedApdu(originalBytes, ApduDirection.Command, DecryptionStatus.PlainText, "Test");

        decryptedApdu.DecryptedBytes.Should().BeEquivalentTo(originalBytes);
    }

    [Test]
    public void TraceExchange_ShouldStoreAllProperties()
    {
        var id = 42;
        var command = new byte[] { 0x01, 0x02 };
        var response = new byte[] { 0x03, 0x04 };
        
        var exchange = new TraceExchange(id, command, response);

        exchange.Id.Should().Be(id);
        exchange.Command.Should().BeEquivalentTo(command);
        exchange.Response.Should().BeEquivalentTo(response);
    }

    [Test]
    public void DecryptedTrace_ShouldStoreAllProperties()
    {
        var exchanges = new List<DecryptedExchange>();
        var sessionKeys = CreateTestSessionKeys();
        var securityLevel = SecurityLevel.CMac;
        var protocolVersion = ProtocolIdentifiers.Scp03;

        var trace = new DecryptedTrace(exchanges, sessionKeys, securityLevel, protocolVersion);

        trace.Exchanges.Should().BeSameAs(exchanges);
        trace.SessionKeys.Should().Be(sessionKeys);
        trace.SecurityLevel.Should().Be(securityLevel);
        trace.ProtocolVersion.Should().Be(protocolVersion);
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