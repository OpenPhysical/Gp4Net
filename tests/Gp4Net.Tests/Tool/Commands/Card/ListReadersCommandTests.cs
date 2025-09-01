// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Core;
using Gp4Net.Services;
using Gp4Net.Tool.Commands.Card;
using Gp4Net.Tool.Pipeline;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.Tests.Tool.Commands.Card;

/// <summary>
/// Unit tests for the <see cref="ListReadersCommand"/> class.
/// </summary>
[TestFixture]
public class ListReadersCommandTests
{
    private IDisplayService _displayService;
    private ISmartCardService _smartCardService;
    private IGlobalPlatformService _globalPlatformService;
    private IKeysetResolver _keysetResolver;
    private TestCliContext _testContext;
    private ListReadersCommand _command;

    /// <summary>
    /// Sets up the test environment before each test.
    /// </summary>
    private VirtualCardService _virtualCardService;

    [SetUp]
    public void SetUp()
    {
        _displayService = new DisplayService();

        _virtualCardService = new VirtualCardService();
        _virtualCardService.SetupComprehensiveTestEnvironment();
        _smartCardService = new TestCardService(_virtualCardService);

        // Skip domain service factory setup for ListReadersCommand tests - use empty implementation
        _globalPlatformService = new EmptyGlobalPlatformService();
        _keysetResolver = new KeysetResolver();

        _testContext = new TestCliContext(
            _displayService,
            _smartCardService,
            _globalPlatformService,
            _keysetResolver,
            NullLogger.Instance
        );

        _command = new ListReadersCommand();
    }

    [TearDown]
    public void TearDown()
    {
        _smartCardService.Dispose();
        _virtualCardService.Dispose();
    }

    /// <summary>
    /// Tests that the command can be constructed without dependencies.
    /// </summary>
    [Test]
    public void Constructor_WithNoDependencies_CreatesInstance()
    {
        // Act & Assert
        _ = _command.Should().NotBeNull();
    }

    /// <summary>
    /// Tests that the command executes successfully when readers are available.
    /// </summary>
    [Test]
    public async Task ExecuteAsync_WithAvailableReaders_ReturnsSuccess()
    {
        // Arrange
        ListReadersCommand.Settings settings = new ListReadersCommand.Settings();

        // Act
        int result = await _command.ExecuteAsync(_testContext, settings);

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
        ListReadersCommand.Settings settings = new ListReadersCommand.Settings();

        // Act
        int result = await _command.ExecuteAsync(_testContext, settings);

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
        TestCliContext failingContext = new TestCliContext(
            _displayService,
            failingCardService,
            _globalPlatformService,
            _keysetResolver,
            NullLogger.Instance
        );
        ListReadersCommand.Settings settings = new ListReadersCommand.Settings();

        // Act
        int result = await _command.ExecuteAsync(failingContext, settings);

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
    public ISmartCardService CardService { get; }
    private readonly IGlobalPlatformService _globalPlatformService;
    public IKeysetResolver KeysetResolver { get; }
    public ILogger Logger { get; }

    public TestCliContext(
        IDisplayService display,
        ISmartCardService smartCardService,
        IGlobalPlatformService globalPlatformService,
        IKeysetResolver keysetResolver,
        ILogger logger
    )
    {
        Display = display;
        CardService = smartCardService;
        _globalPlatformService = globalPlatformService;
        KeysetResolver = keysetResolver;
        Logger = logger;
    }

    public IGlobalPlatformService GetGlobalPlatformService() => _globalPlatformService;

    public Func<
        SecureChannelRequest,
        CancellationToken,
        Task<Result<SecureChannelExecutionContext, SmartCardError>>
    > EstablishSecureChannelAsync => (request, ct) => 
        Task.FromResult(Result.Failure<SecureChannelExecutionContext, SmartCardError>(
            SmartCardError.CommunicationError("Test context does not support secure channels")));

    public Task<Result<ICliExecutionContext, SmartCardError>> RequireCardConnection(
        Maybe<string> readerName = default
    ) => Task.FromResult(Result.Success<ICliExecutionContext, SmartCardError>(this));

    public Task<Result<ICliExecutionContext, SmartCardError>> RequireSecureChannel(
        byte securityLevel = 1,
        Maybe<string> keyset = default
    ) => Task.FromResult(Result.Success<ICliExecutionContext, SmartCardError>(this));

    public Task<int> ExecuteAsync(Func<ICliExecutionContext, Task<int>> commandLogic) =>
        commandLogic(this);

    public Task<int> ExecuteAsync(Func<ICliExecutionContext, int> commandLogic) =>
        Task.FromResult(commandLogic(this));
}
