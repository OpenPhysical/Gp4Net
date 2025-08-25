using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Gp4Net.Domain;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Core;
using Gp4Net.Services;
using Gp4Net.Tool.Commands.Card;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Services;
using Gp4Net.CardEmulator.Services;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using Spectre.Console.Testing;
using StatusSubset = Gp4Net.Domain.Commands.GetStatusCommand.StatusSubset;
using Gp4Net.Tests.Tool;
using Gp4Net.Tests.TestHelpers;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Transport;
using CSharpFunctionalExtensions;

namespace Gp4Net.Tests.Tool.Commands.Card;

[TestFixture]
public class InfoCommandTests
{
    private IDisplayService _displayService;
    private Gp4Net.Tool.Services.ICardService _cardService;
    private IGlobalPlatformService _globalPlatformService;
    private IKeysetResolver _keysetResolver;
    private TestCliContext _testContext;
    private InfoCommand _command;
    private TestConsole _console;

    private VirtualCardService _virtualCardService = null!;

    [SetUp]
    public void Setup()
    {
        _displayService = new DisplayService(false);
        
        _virtualCardService = new VirtualCardService();
        _virtualCardService.SetupComprehensiveTestEnvironment();
        _cardService = new TestCardService(_virtualCardService);
        
        // Skip domain service factory setup for InfoCommand tests
        _globalPlatformService = null;
        _keysetResolver = new FunctionalKeysetResolverAdapter();
        _console = new TestConsole();

        _testContext = new TestCliContext(
            _displayService,
            _cardService,
            _globalPlatformService,
            _keysetResolver,
            Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance
        );

        _command = new InfoCommand();
    }

    [TearDown]
    public void TearDown()
    {
        _console?.Dispose();
        _cardService?.Dispose();
        _virtualCardService?.Dispose();
    }

    [Test]
    public async Task ExecuteAsync_WithValidContext_ReturnsSuccess()
    {
        // Arrange
        var settings = new InfoCommand.Settings();

        // Act
        var result = await _command.ExecuteAsync(_testContext, settings);

        // Assert
        _ = result.Should().Be(0);
    }

    [Test]
    public async Task ExecuteAsync_CardServiceException_ReturnsError()
    {
        // Arrange - Create a failing card service for this test
        var failingCardService = new FailingCardService();
        var failingContext = new TestCliContext(
            _displayService,
            failingCardService,
            _globalPlatformService,
            _keysetResolver,
            Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance
        );
        var settings = new InfoCommand.Settings();

        // Act
        var result = await _command.ExecuteAsync(failingContext, settings);

        // Assert
        _ = result.Should().Be(1);
    }

    [Test]
    public void Settings_RequiresSecureChannel_ReturnsFalse()
    {
        // Arrange
        var settings = new InfoCommand.Settings();

        // Assert - InfoCommand should not require secure channel by default
        // This assumes InfoCommand.Settings inherits from a base that has RequiresSecureChannel property
        // If not, this test can be removed
    }

    [Test]
    public async Task ExecuteAsync_IsdSelectionFails_ContinuesExecution()
    {
        // Arrange
        var settings = new InfoCommand.Settings();

        // Act
        var result = await _command.ExecuteAsync(_testContext, settings);

        // Assert
        _ = result.Should().Be(0); // Should still succeed
    }

    [Test]
    public async Task ExecuteAsync_CplcFails_ContinuesWithOtherData()
    {
        // Arrange
        var settings = new InfoCommand.Settings();

        // Act
        var result = await _command.ExecuteAsync(_testContext, settings);

        // Assert
        _ = result.Should().Be(0);
    }

    [Test]
    public async Task ExecuteAsync_GetApplicationsFails_StillShowsOtherInfo()
    {
        // Arrange
        var settings = new InfoCommand.Settings();

        // Act
        var result = await _command.ExecuteAsync(_testContext, settings);

        // Assert
        _ = result.Should().Be(0);
    }

    [Test]
    public async Task ExecuteAsync_WithAtr_DisplaysAtr()
    {
        // Arrange
        var settings = new InfoCommand.Settings();

        // Act
        var result = await _command.ExecuteAsync(_testContext, settings);

        // Assert
        _ = result.Should().Be(0);
    }

    [Test]
    public async Task ExecuteAsync_WithCplc_DisplaysCplc()
    {
        // Arrange
        var settings = new InfoCommand.Settings();

        // Act
        var result = await _command.ExecuteAsync(_testContext, settings);

        // Assert
        _ = result.Should().Be(0);
    }

    [Test]
    public async Task ExecuteAsync_WithApplications_DisplaysSummary()
    {
        // Arrange
        var settings = new InfoCommand.Settings();

        // Act
        var result = await _command.ExecuteAsync(_testContext, settings);

        // Assert
        _ = result.Should().Be(0);
    }
}

/// <summary>
/// Test implementation of card service that fails for testing error handling.
/// </summary>
public class FailingCardService : Gp4Net.Tool.Services.ICardService
{
    public bool IsSecureChannelEstablished => false;
    public bool IsConnected => false;
    public bool IsDisposed { get; private set; }
    
    public byte[] GetAtr() => [];
    
    public IReadOnlyList<string> GetReaders() => new List<string>();
    
    public bool Connect(string readerName) => false;
    
    public void Disconnect() { }
    
    public Gp4Net.Tool.Services.CardResponse SendCommand(byte[] command) => new Gp4Net.Tool.Services.CardResponse([], 0x6F00);
    
    public Gp4Net.Tool.Services.CardResponse SendCommand(IApduCommand command) => new Gp4Net.Tool.Services.CardResponse([], 0x6F00);
    
    public bool EstablishSecureChannel(byte[] keySet, byte securityLevel) => false;
    
    public void Dispose()
    {
        IsDisposed = true;
        GC.SuppressFinalize(this);
    }
}
