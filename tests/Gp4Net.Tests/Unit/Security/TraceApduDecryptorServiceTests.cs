using System;
using System.Collections.Generic;
using System.Linq;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using ScpVersion = Gp4Net.Cryptography.CryptoService.ScpVersion;

namespace Gp4Net.Tests.Unit.Security;

/// <summary>
/// Unit tests for TraceApduDecryptorService.
/// Tests the functional decryption service following established patterns.
/// </summary>
[TestFixture]
[Category("Unit")]
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
        TraceApduDecryptorService service = new TraceApduDecryptorService();

        _ = service.Should().NotBeNull();
    }

    [Test]
    public void Constructor_WithLogger_ShouldCreateService()
    {
        TraceApduDecryptorService service = new TraceApduDecryptorService(_logger);

        _ = service.Should().NotBeNull();
    }

    [TestCase(ApduDirection.Command)]
    [TestCase(ApduDirection.Response)]
    public void DecryptApdu_WithPlaintextApdu_ShouldReturnOriginalApdu(ApduDirection direction)
    {
        // Plaintext APDU (no secure messaging indicator)
        byte[] plaintextApdu =
        [
            0x00,
            0xA4,
            0x04,
            0x00,
            0x08,
            0xA0,
            0x00,
            0x00,
            0x01,
            0x51,
            0x00,
            0x00,
            0x00,
        ];
        SessionKeys sessionKeys = CreateTestSessionKeys();
        SecurityLevel securityLevel = SecurityLevel.None;
        SecureChannelState sessionState = CreateTestSessionState(
            sessionKeys,
            securityLevel,
            (byte)ScpVersion.Scp03
        );

        Result<
            (DecryptedApdu decryptedApdu, SecureChannelState updatedState),
            SmartCardError
        > result = _service.DecryptApdu(plaintextApdu, direction, sessionState);

        _ = result.IsSuccess.Should().BeTrue();
        (DecryptedApdu decryptedApdu, SecureChannelState updatedState) = result.Value;
        _ = decryptedApdu.OriginalBytes.Should().BeEquivalentTo(plaintextApdu);
        _ = decryptedApdu.DecryptedBytes.Should().BeEquivalentTo(plaintextApdu);
        _ = decryptedApdu.Direction.Should().Be(direction);
        _ = decryptedApdu.Status.Should().Be(DecryptionStatus.PlainText);
        _ = decryptedApdu.Metadata.Should().Contain("No secure messaging detected");
        _ = updatedState.Should().Be(sessionState); // State unchanged for plaintext
    }

    [Test]
    public void DecryptApdu_WithSecureCommand_ShouldDetectSecureMessaging()
    {
        // Command with secure messaging indicator (CLA = 0x84)
        byte[] secureCommand =
        [
            0x84,
            0x50,
            0x00,
            0x00,
            0x10,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0A,
            0x0B,
            0x0C,
            0x0D,
            0x0E,
            0x0F,
            0x10,
        ];
        SessionKeys sessionKeys = CreateTestSessionKeys();
        SecurityLevel securityLevel = SecurityLevel.CMac;
        SecureChannelState sessionState = CreateTestSessionState(
            sessionKeys,
            securityLevel,
            (byte)ScpVersion.Scp03
        );

        Result<
            (DecryptedApdu decryptedApdu, SecureChannelState updatedState),
            SmartCardError
        > result = _service.DecryptApdu(secureCommand, ApduDirection.Command, sessionState);

        _ = result.IsSuccess.Should().BeTrue();
        (DecryptedApdu decryptedApdu, _) = result.Value;
        _ = decryptedApdu.Status.Should().NotBe(DecryptionStatus.PlainText);
        _ = decryptedApdu.Metadata.Should().Contain("SCP03");
    }

    [Test]
    public void DecryptTrace_WithEmptyExchanges_ShouldReturnEmptyTrace()
    {
        TraceExchange[] exchanges = [];
        SessionKeys sessionKeys = CreateTestSessionKeys();
        SecurityLevel securityLevel = SecurityLevel.None;
        ScpVersion protocolVersion = ScpVersion.Scp03;

        Result<DecryptedTrace, SmartCardError> result = _service.DecryptTrace(
            exchanges,
            sessionKeys,
            securityLevel,
            protocolVersion
        );

        _ = result.IsSuccess.Should().BeTrue();
        DecryptedTrace? decryptedTrace = result.Value;
        _ = decryptedTrace.Exchanges.Should().BeEmpty();
        _ = decryptedTrace.SessionKeys.Should().Be(sessionKeys);
        _ = decryptedTrace.SecurityLevel.Should().Be(securityLevel);
        _ = decryptedTrace.ProtocolVersion.Should().Be(protocolVersion);
    }

    [Test]
    public void DecryptTrace_WithPlaintextExchanges_ShouldReturnDecryptedTrace()
    {
        TraceExchange[] exchanges =
        [
            new TraceExchange(
                1,
                [0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00], // SELECT
                [0x90, 0x00]
            ), // Success
        ];
        SessionKeys sessionKeys = CreateTestSessionKeys();
        SecurityLevel securityLevel = SecurityLevel.None;
        ScpVersion protocolVersion = ScpVersion.Scp03;

        Result<DecryptedTrace, SmartCardError> result = _service.DecryptTrace(
            exchanges,
            sessionKeys,
            securityLevel,
            protocolVersion
        );

        _ = result.IsSuccess.Should().BeTrue();
        DecryptedTrace? decryptedTrace = result.Value;
        _ = decryptedTrace.Exchanges.Should().HaveCount(1);

        DecryptedExchange? exchange = decryptedTrace.Exchanges.First();
        _ = exchange.Id.Should().Be(1);
        _ = exchange.Command.Status.Should().Be(DecryptionStatus.PlainText);
        _ = exchange.Response.Status.Should().Be(DecryptionStatus.PlainText);
        _ = exchange.Response.Description.Should().Contain("Success");
    }

    [Test]
    public void DecryptTrace_WithInvalidSessionKeys_ShouldReturnError()
    {
        TraceExchange[] exchanges =
        [
            new TraceExchange(
                1,
                [0x84, 0x50, 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
                [0x90, 0x00]
            ),
        ];

        // Invalid session keys (empty components)
        byte[] emptyKey = [];
        SessionKeys invalidKeys = new SessionKeys(emptyKey, emptyKey, emptyKey, emptyKey);
        SecurityLevel securityLevel = SecurityLevel.CMac;
        ScpVersion protocolVersion = ScpVersion.Scp03;

        Result<DecryptedTrace, SmartCardError> result = _service.DecryptTrace(
            exchanges,
            invalidKeys,
            securityLevel,
            protocolVersion
        );

        _ = result.IsFailure.Should().BeTrue();
        _ = result.Error.Should().BeOfType<SmartCardError>();
    }

    [TestCase(ScpVersion.Scp02)]
    [TestCase(ScpVersion.Scp03)]
    public void DecryptTrace_WithDifferentProtocols_ShouldHandleCorrectly(ScpVersion protocolVersion)
    {
        TraceExchange[] exchanges =
        [
            new TraceExchange(
                1,
                [0x00, 0xA4, 0x04, 0x00, 0x00], // SELECT with no data
                [0x90, 0x00]
            ), // Success
        ];
        SessionKeys sessionKeys = CreateTestSessionKeys();
        SecurityLevel securityLevel = SecurityLevel.None;

        Result<DecryptedTrace, SmartCardError> result = _service.DecryptTrace(
            exchanges,
            sessionKeys,
            securityLevel,
            protocolVersion
        );

        _ = result.IsSuccess.Should().BeTrue();
        DecryptedTrace? decryptedTrace = result.Value;
        _ = decryptedTrace.ProtocolVersion.Should().Be(protocolVersion);
    }

    [Test]
    public void DecryptedApdu_Description_ShouldFormatResponseStatusWord()
    {
        byte[] responseBytes = [0x01, 0x02, 0x90, 0x00]; // Data + Success status
        DecryptedApdu decryptedApdu = new DecryptedApdu(
            responseBytes,
            ApduDirection.Response,
            DecryptionStatus.PlainText,
            "Test"
        );

        _ = decryptedApdu.Description.Should().Contain("Response: 0x9000 (Success)");
    }

    [Test]
    public void DecryptedApdu_Description_ShouldFormatCommand()
    {
        byte[] commandBytes = [0x00, 0xA4, 0x04, 0x00];
        DecryptedApdu decryptedApdu = new DecryptedApdu(
            commandBytes,
            ApduDirection.Command,
            DecryptionStatus.PlainText,
            "Test"
        );

        _ = decryptedApdu.Description.Should().Contain("Command APDU (4 bytes)");
    }

    [Test]
    public void DecryptedApdu_DecryptedBytes_ShouldReturnOriginalWhenNotDecrypted()
    {
        byte[] originalBytes = [0x01, 0x02, 0x03];
        DecryptedApdu decryptedApdu = new DecryptedApdu(
            originalBytes,
            ApduDirection.Command,
            DecryptionStatus.PlainText,
            "Test"
        );

        _ = decryptedApdu.DecryptedBytes.Should().BeEquivalentTo(originalBytes);
    }

    [Test]
    public void TraceExchange_ShouldStoreAllProperties()
    {
        int id = 42;
        byte[] command = [0x01, 0x02];
        byte[] response = [0x03, 0x04];

        TraceExchange exchange = new TraceExchange(id, command, response);

        _ = exchange.Id.Should().Be(id);
        _ = exchange.Command.Should().BeEquivalentTo(command);
        _ = exchange.Response.Should().BeEquivalentTo(response);
    }

    [Test]
    public void DecryptedTrace_ShouldStoreAllProperties()
    {
        List<DecryptedExchange> exchanges = [];
        SessionKeys sessionKeys = CreateTestSessionKeys();
        SecurityLevel securityLevel = SecurityLevel.CMac;
        ScpVersion protocolVersion = ScpVersion.Scp03;

        DecryptedTrace trace = new DecryptedTrace(
            exchanges,
            sessionKeys,
            securityLevel,
            protocolVersion
        );

        _ = trace.Exchanges.Should().BeSameAs(exchanges);
        _ = trace.SessionKeys.Should().Be(sessionKeys);
        _ = trace.SecurityLevel.Should().Be(securityLevel);
        _ = trace.ProtocolVersion.Should().Be(protocolVersion);
    }

    private static SessionKeys CreateTestSessionKeys()
    {
        byte[] key = new byte[16]; // AES-128 key for SCP03
        Array.Fill(key, (byte)0x01);

        return new SessionKeys(sEnc: key, sMac: key, sRMac: key, dek: key);
    }

    private static SecureChannelState CreateTestSessionState(
        SessionKeys sessionKeys,
        SecurityLevel securityLevel,
        byte protocolVersion
    )
    {
        byte[] macChaining = protocolVersion == (byte)CryptoService.ScpVersion.Scp03 ? new byte[16] : new byte[8];

        return SecureChannelState
            .Create(sessionKeys, securityLevel, (CryptoService.ScpVersion)protocolVersion, macChaining, 0x00)
            .Value;
    }
}
