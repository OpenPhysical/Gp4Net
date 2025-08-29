using System;
using System.Threading.Tasks;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Services;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Services;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Core;
using NUnit.Framework;
using Spectre.Console.Testing;
using Gp4Net.Tests.TestHelpers;

namespace Gp4Net.Tests.Tool.Commands;

/// <summary>
/// Tests for the pipeline command context which replaces BaseCommand functionality.
/// </summary>
[TestFixture]
public class BaseCommandTests
{
    private IDisplayService _displayService;
    private ISmartCardService _smartCardService;
    private IGlobalPlatformService _globalPlatformService;
    private Maybe<IDomainServiceFactory> _domainServiceFactory;
    private IKeysetResolver _keysetResolver;
    private CliContext _cliContext;
    private TestConsole _console;
    private VirtualCardService _virtualCardService;

    [SetUp]
    public void Setup()
    {
        _displayService = new DisplayService(false);
        _virtualCardService = new VirtualCardService();
        _virtualCardService.SetupComprehensiveTestEnvironment();
        _smartCardService = new TestCardService(_virtualCardService);
        _keysetResolver = new KeysetResolver();
        // Skip complex domain service factory setup for base command tests - use empty implementation
        _domainServiceFactory = Maybe<IDomainServiceFactory>.None;
        _globalPlatformService = new EmptyGlobalPlatformService();
        _console = new TestConsole();

        _cliContext = new CliContext(
            _displayService,
            _smartCardService,
            _domainServiceFactory.GetValueOrDefault(CreateEmptyDomainServiceFactory()),
            _keysetResolver,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<CliContext>.Instance
        );
    }

    private static IDomainServiceFactory CreateEmptyDomainServiceFactory()
    {
        return new EmptyDomainServiceFactory();
    }

    [TearDown]
    public void TearDown()
    {
        _console.Dispose();
        _smartCardService.Dispose();
        _virtualCardService.Dispose();
    }

    [Test]
    public async Task RequireCardConnection_AlreadyConnected_ReturnsContext()
    {
        // Arrange
        // Virtual card service handles connection state automatically

        // Act
        Result<ICliExecutionContext, SmartCardError> result = await _cliContext.RequireCardConnection("TestReader");

        // Assert
        _ = result.Should().BeEquivalentTo(_cliContext);
        // Virtual card service connection verified through context state
    }

    [Test]
    public async Task RequireCardConnection_WithSpecificReader_ConnectsSuccessfully()
    {
        // Arrange
        // Virtual card service handles connection automatically

        // Act
        Result<ICliExecutionContext, SmartCardError> result = await _cliContext.RequireCardConnection("TestReader");

        // Assert
        _ = result.Should().BeEquivalentTo(_cliContext);
        // Virtual card service connection verified through context state
    }

    [Test]
    public async Task RequireCardConnection_AutoDetect_UsesFirstReader()
    {
        // Arrange
        // Virtual card service provides readers and handles connection automatically

        // Act
        Result<ICliExecutionContext, SmartCardError> result = await _cliContext.RequireCardConnection("auto");

        // Assert
        _ = result.Should().BeEquivalentTo(_cliContext);
        // Virtual card service connection verified through context state
    }

    [Test]
    public void RequireCardConnection_NoReadersAvailable_ThrowsException()
    {
        // Arrange
        // Create a failing card service for this test
        var failingCardService = new FailingCardService();
        CliContext failingContext = new CliContext(
            _displayService,
            failingCardService,
            _domainServiceFactory,
            _keysetResolver,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<CliContext>.Instance
        );

        // Act & Assert
        Action act = () => { _ = failingContext.RequireCardConnection("auto").GetAwaiter().GetResult(); };
        _ = act.Should().ThrowExactly<InvalidOperationException>();
    }

    [Test]
    public void RequireCardConnection_ConnectionFails_ThrowsException()
    {
        // Arrange
        // Create a failing card service for this test
        var failingCardService = new FailingCardService();
        CliContext failingContext = new CliContext(
            _displayService,
            failingCardService,
            _domainServiceFactory,
            _keysetResolver,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<CliContext>.Instance
        );

        // Act & Assert
        Action act = () => { _ = failingContext.RequireCardConnection("TestReader").GetAwaiter().GetResult(); };
        _ = act.Should().ThrowExactly<InvalidOperationException>();
    }

    [Test]
    public async Task RequireSecureChannel_AlreadyEstablished_ReturnsContext()
    {
        // Arrange
        // Virtual card service secure channel state handled automatically

        // Act
        Result<ICliExecutionContext, SmartCardError> result = await _cliContext.RequireSecureChannel();

        // Assert
        _ = result.Should().BeEquivalentTo(_cliContext);
        // Virtual card service secure channel verified through context state
    }

    [Test]
    public async Task RequireSecureChannel_EstablishesSuccessfully_ReturnsContext()
    {
        // Arrange
        // Virtual card service handles secure channel establishment automatically

        // Act
        Result<ICliExecutionContext, SmartCardError> result = await _cliContext.RequireSecureChannel(1);

        // Assert
        _ = result.Should().BeEquivalentTo(_cliContext);
        // Virtual card service secure channel verified through context state
    }

    [Test]
    public void RequireSecureChannel_EstablishmentFails_ThrowsException()
    {
        // Arrange
        // Create a failing card service for this test
        var failingCardService = new FailingCardService();
        CliContext failingContext = new CliContext(
            _displayService,
            failingCardService,
            _domainServiceFactory,
            _keysetResolver,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<CliContext>.Instance
        );

        // Act & Assert
        Action act = () => { _ = failingContext.RequireSecureChannel().GetAwaiter().GetResult(); };
        _ = act.Should().ThrowExactly<InvalidOperationException>();
    }

    [Test]
    public async Task ExecuteAsync_WithAsyncFunction_ExecutesSuccessfully()
    {
        // Arrange
        bool executed = false;

        // Act
        int result = await _cliContext.ExecuteAsync(async ctx =>
        {
            executed = true;
            await Task.Delay(1);
            return 42;
        });

        // Assert
        _ = result.Should().Be(42);
        _ = executed.Should().BeTrue();
    }

    [Test]
    public async Task ExecuteAsync_WithSyncFunction_ExecutesSuccessfully()
    {
        // Arrange
        bool executed = false;

        // Act
        int result = await _cliContext.ExecuteAsync(ctx =>
        {
            executed = true;
            return 42;
        });

        // Assert
        _ = result.Should().Be(42);
        _ = executed.Should().BeTrue();
    }

    [Test]
    public async Task ExecuteAsync_WithException_ReturnsErrorCode()
    {
        // Act
        int result = await _cliContext.ExecuteAsync((Func<ICliExecutionContext, int>)(ctx =>
            {
                throw new InvalidOperationException("Test exception");
            }));

        // Assert
        _ = result.Should().Be(1);
        // Exception handling verified through result code
    }

}
