using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Tool.Services;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.Tests.Tool.Services;

public class CardCompatibilityServiceTests
{
    private CardCompatibilityService _service = default!;
    private TestEnvironmentValidationService _envValidation = default!;
    private TestCardChannel _channel = default!;
    private TestApduTransport _transport = default!;

    [SetUp]
    public void Setup()
    {
        _envValidation = new TestEnvironmentValidationService();
        var serviceResult = CardCompatibilityService.Create(
            NullLogger<CardCompatibilityService>.Instance,
            _envValidation
        );
        _service = serviceResult.Value;
        _channel = new TestCardChannel();
        _transport = new TestApduTransport();
    }

    [Test]
    public async Task Should_Identify_Compatible_Card_For_Install_Operation()
    {
        var testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var keySet = Scp03KeySet.Create(testKey, testKey, testKey, 0x00).Value;

        _envValidation.SetValidationResult(
            new EnvironmentValidationResult(
                isSafe: true,
                cardEnvironment: CardEnvironment.Test,
                isTestKeySet: true,
                message: "Safe for testing"
            )
        );

        var result = await _service.CheckCompatibilityAsync(
            CardOperation.ApplicationInstallation,
            keySet,
            _channel,
            _transport,
            CancellationToken.None
        );

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value.IsCompatible, Is.True);
        Assert.That(result.Value.IsSafe, Is.True);
    }

    [Test]
    public async Task Should_Reject_Incompatible_Card_For_Install_Operation()
    {
        var testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var keySet = Scp03KeySet.Create(testKey, testKey, testKey, 0x00).Value;

        _envValidation.SetValidationResult(
            new EnvironmentValidationResult(
                isSafe: false,
                cardEnvironment: CardEnvironment.Production,
                isTestKeySet: true,
                message: "Environment validation failed",
                warnings: "Test keys detected"
            )
        );

        var result = await _service.CheckCompatibilityAsync(
            CardOperation.ApplicationInstallation,
            keySet,
            _channel,
            _transport,
            CancellationToken.None
        );

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value.IsCompatible, Is.False);
        Assert.That(result.Value.IsSafe, Is.False);
        Assert.That(result.Value.Message, Is.EqualTo("Environment validation failed"));
    }

    [Test]
    public async Task Should_Detect_Key_Installation_Compatibility()
    {
        var testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var keySet = Scp03KeySet.Create(testKey, testKey, testKey, 0x00).Value;

        _envValidation.SetValidationResult(
            new EnvironmentValidationResult(
                isSafe: true,
                cardEnvironment: CardEnvironment.Production,
                isTestKeySet: false,
                message: "Production environment"
            )
        );

        var result = await _service.CheckCompatibilityAsync(
            CardOperation.KeyInstallation,
            keySet,
            _channel,
            _transport,
            CancellationToken.None
        );

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value.IsCompatible, Is.True);
    }

    [Test]
    public async Task Should_Reject_Key_Installation_On_Incompatible_Card()
    {
        var testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var keySet = Scp03KeySet.Create(testKey, testKey, testKey, 0x00).Value;

        _envValidation.SetValidationResult(
            new EnvironmentValidationResult(
                isSafe: false,
                cardEnvironment: CardEnvironment.Production,
                isTestKeySet: true,
                message: "Unsafe environment",
                warnings: "Production card with test keys"
            )
        );

        var result = await _service.CheckCompatibilityAsync(
            CardOperation.KeyInstallation,
            keySet,
            _channel,
            _transport,
            CancellationToken.None
        );

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value.IsCompatible, Is.False);
        Assert.That(result.Value.IsSafe, Is.False);
    }

    [Test]
    public async Task Should_Analyze_Compatibility_For_All_Card_Types()
    {
        var testKey = Convert.FromHexString("404142434445464748494A4B4C4D4E4F");
        var keySet = Scp03KeySet.Create(testKey, testKey, testKey, 0x00).Value;

        _envValidation.SetValidationResult(
            new EnvironmentValidationResult(
                isSafe: true,
                cardEnvironment: CardEnvironment.Test,
                isTestKeySet: true,
                message: "Test environment"
            )
        );

        var operations = new[]
        {
            CardOperation.Authentication,
            CardOperation.ReadOnly,
            CardOperation.ApplicationInstallation,
            CardOperation.ApplicationDeletion,
            CardOperation.KeyInstallation,
            CardOperation.Personalization
        };

        foreach (var operation in operations)
        {
            var result = await _service.CheckCompatibilityAsync(
                operation,
                keySet,
                _channel,
                _transport,
                CancellationToken.None
            );

            Assert.That(result.IsSuccess, Is.True, $"Operation {operation} should succeed");
        }
    }

    [Test]
    public async Task Should_Return_CardType_For_DetectCardTypeAsync()
    {
        var result = await _service.DetectCardTypeAsync(
            _channel,
            _transport,
            CancellationToken.None
        );

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value, Is.Not.Null);
        Assert.That(result.Value.Manufacturer, Is.Not.Empty);
    }
}

public class TestEnvironmentValidationService : IEnvironmentValidationService
{
    private EnvironmentValidationResult _result =
        new(
            isSafe: true,
            cardEnvironment: CardEnvironment.Test,
            isTestKeySet: false,
            message: "Default"
        );

    public void SetValidationResult(EnvironmentValidationResult result)
    {
        _result = result;
    }

    public Task<Result<EnvironmentValidationResult, SmartCardError>> ValidateEnvironmentAsync(
        IKeySet keySet,
        ICardChannel channel,
        IApduTransport transport,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Success<EnvironmentValidationResult, SmartCardError>(_result)
        );
    }

    public bool IsTestKeySet(IKeySet keySet)
    {
        return _result.IsTestKeySet;
    }

    public Task<Result<CardEnvironment, SmartCardError>> DetectCardEnvironmentAsync(
        ICardChannel channel,
        IApduTransport transport,
        CancellationToken cancellationToken = default
    )
    {
        return Task.FromResult(
            Result.Success<CardEnvironment, SmartCardError>(_result.CardEnvironment)
        );
    }
}

public class TestCardChannel : ICardChannel
{
    public Task<byte[]> TransmitAsync(byte[] command, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new byte[] { 0x90, 0x00 });
    }

    public TransportProtocol Protocol => TransportProtocol.T1;
    public bool IsOpen => true;
}

public class TestApduTransport : IApduTransport
{
    public TransportProtocol Protocol => TransportProtocol.T1;
    public int MaxCommandDataLength => 255;
    public int MaxResponseDataLength => 256;
    public bool SupportsExtendedLength => false;

    public Task<Result<ApduResponse, SmartCardError>> TransmitAsync(
        IApduCommand command,
        ICardChannel channel,
        CancellationToken cancellationToken = default
    )
    {
        var response = new ApduResponse(Array.Empty<byte>(), 0x9000);
        return Task.FromResult(Result.Success<ApduResponse, SmartCardError>(response));
    }
}
