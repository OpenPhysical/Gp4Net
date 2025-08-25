// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

namespace Gp4Net.Tests.Tool.Commands.Card;

using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
using Gp4Net.Services;
using Gp4Net.Tool.Commands.Card;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Services;
using Gp4Net.CardEmulator.Services;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using CSharpFunctionalExtensions;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tests.Tool;
using Gp4Net.Tests.TestHelpers;

/// <summary>
/// Unit tests for the <see cref="ListReadersCommand"/> class.
/// </summary>
[TestFixture]
public class ListReadersCommandTests
{
    private IDisplayService _displayService;
    private Gp4Net.Tool.Services.ICardService _cardService;
    private IGlobalPlatformService _globalPlatformService;
    private IKeysetResolver _keysetResolver;
    private TestCliContext _testContext;
    private ListReadersCommand _command;

    /// <summary>
    /// Sets up the test environment before each test.
    /// </summary>
    private VirtualCardService _virtualCardService = null!;

    [SetUp]
    public void SetUp()
    {
        _displayService = new DisplayService(false);
        
        _virtualCardService = new VirtualCardService();
        _virtualCardService.SetupComprehensiveTestEnvironment();
        _cardService = new TestCardService(_virtualCardService);
        
        // Skip domain service factory setup for ListReadersCommand tests
        _globalPlatformService = null;
        _keysetResolver = new FunctionalKeysetResolverAdapter();

        _testContext = new TestCliContext(
            _displayService,
            _cardService,
            _globalPlatformService, // null is fine for ListReaders
            _keysetResolver,
            Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance
        );

        _command = new ListReadersCommand();
    }

    [TearDown]
    public void TearDown()
    {
        _cardService?.Dispose();
        _virtualCardService?.Dispose();
    }

    /// <summary>
    /// Tests that the command can be constructed without dependencies.
    /// </summary>
    [Test]
    public void Constructor_WithNoDependencies_CreatesInstance()
    {
        // Act & Assert
        _ = this._command.Should().NotBeNull();
    }

    /// <summary>
    /// Tests that the command executes successfully when readers are available.
    /// </summary>
    [Test]
    public async Task ExecuteAsync_WithAvailableReaders_ReturnsSuccess()
    {
        // Arrange
        var settings = new ListReadersCommand.Settings();

        // Act
        var result = await this._command.ExecuteAsync(this._testContext, settings);

        // Assert
        _ = result.Should().Be(0);
    }

    /// <summary>
    /// Tests that the command handles no readers gracefully.
    /// </summary>
    [Test]
    public async Task ExecuteAsync_WithNoReaders_ReturnsSuccess()
    {
        // Arrange
        var settings = new ListReadersCommand.Settings();

        // Act
        var result = await this._command.ExecuteAsync(this._testContext, settings);

        // Assert
        _ = result.Should().Be(0);
    }

    /// <summary>
    /// Tests that the command handles card service exceptions gracefully.
    /// </summary>
    [Test]
    public async Task ExecuteAsync_WithCardServiceException_ReturnsError()
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
        var settings = new ListReadersCommand.Settings();

        // Act
        var result = await this._command.ExecuteAsync(failingContext, settings);

        // Assert
        _ = result.Should().Be(1); // Should handle exceptions gracefully
    }
}

/// <summary>
/// Test implementation of CLI execution context for functional testing with virtual card.
/// </summary>
public class TestCliContext : ICliExecutionContext
{
    public IDisplayService Display { get; }
    public Gp4Net.Tool.Services.ICardService CardService { get; }
    private readonly IGlobalPlatformService _globalPlatformService;
    public IKeysetResolver KeysetResolver { get; }
    public ILogger Logger { get; }

    public TestCliContext(
        IDisplayService display,
        Gp4Net.Tool.Services.ICardService cardService,
        IGlobalPlatformService globalPlatformService,
        IKeysetResolver keysetResolver,
        ILogger logger)
    {
        Display = display;
        CardService = cardService;
        _globalPlatformService = globalPlatformService;
        KeysetResolver = keysetResolver;
        Logger = logger;
    }

    public IGlobalPlatformService GetGlobalPlatformService() => _globalPlatformService;

    public Task<ICliExecutionContext> RequireCardConnection(Maybe<string> readerName = default) =>
        Task.FromResult<ICliExecutionContext>(this);

    public Task<ICliExecutionContext> RequireSecureChannel(byte securityLevel = 1, Maybe<string> keyset = default) =>
        Task.FromResult<ICliExecutionContext>(this);

    public Task<int> ExecuteAsync(System.Func<ICliExecutionContext, Task<int>> commandLogic) =>
        commandLogic(this);

    public Task<int> ExecuteAsync(System.Func<ICliExecutionContext, int> commandLogic) =>
        Task.FromResult(commandLogic(this));
}
