using System;
using System.Threading.Tasks;
using AwesomeAssertions;
using Gp4Net.Services;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Services;
using Moq;
using NUnit.Framework;
using CSharpFunctionalExtensions;
using Spectre.Console.Testing;

namespace Gp4Net.Tests.Tool.Commands;

/// <summary>
/// Tests for the pipeline command context which replaces BaseCommand functionality.
/// </summary>
[TestFixture]
public class BaseCommandTests
{
    private Mock<IDisplayService> _mockDisplayService;
    private Mock<ICardService> _mockCardService;
    private Mock<IGlobalPlatformService> _mockGlobalPlatformService;
    private Mock<IDomainServiceFactory> _mockDomainServiceFactory;
    private Mock<IKeysetResolver> _mockKeysetResolver;
    private CommandContext _commandContext;
    private TestConsole _console;

    [SetUp]
    public void Setup()
    {
        _mockDisplayService = new Mock<IDisplayService>();
        _mockCardService = new Mock<ICardService>();
        _mockGlobalPlatformService = new Mock<IGlobalPlatformService>();
        _mockDomainServiceFactory = new Mock<IDomainServiceFactory>();
        _mockKeysetResolver = new Mock<IKeysetResolver>();
        _console = new TestConsole();

        // Setup the factory to return our mock service
        _mockDomainServiceFactory
            .Setup(f => f.CreateGlobalPlatformService(It.IsAny<ICardService>()))
            .Returns(_mockGlobalPlatformService.Object);

        _commandContext = new CommandContext(
            _mockDisplayService.Object,
            _mockCardService.Object,
            _mockDomainServiceFactory.Object,
            _mockKeysetResolver.Object
        );
    }

    [TearDown]
    public void TearDown()
    {
        _console?.Dispose();
    }

    [Test]
    public async Task RequireCardConnection_AlreadyConnected_ReturnsContext()
    {
        // Arrange
        _ = _mockCardService.Setup(s => s.IsConnected).Returns(true);

        // Act
        var result = await _commandContext.RequireCardConnection("TestReader");

        // Assert
        result.Should().BeEquivalentTo(_commandContext);
        _mockCardService.Verify(s => s.Connect(It.IsAny<string>()), Times.Never);
    }

    [Test]
    public async Task RequireCardConnection_WithSpecificReader_ConnectsSuccessfully()
    {
        // Arrange
        _ = _mockCardService.Setup(s => s.IsSecureChannelEstablished).Returns(false);
        _ = _mockCardService.Setup(s => s.Connect("TestReader")).Returns(true);

        // Act
        var result = await _commandContext.RequireCardConnection("TestReader");

        // Assert
        result.Should().BeEquivalentTo(_commandContext);
        _mockCardService.Verify(s => s.Connect("TestReader"), Times.Once);
    }

    [Test]
    public async Task RequireCardConnection_AutoDetect_UsesFirstReader()
    {
        // Arrange
        _ = _mockCardService.Setup(s => s.IsSecureChannelEstablished).Returns(false);
        _ = _mockCardService.Setup(s => s.GetReaders()).Returns(new[] { "Reader1", "Reader2" });
        _ = _mockCardService.Setup(s => s.Connect("Reader1")).Returns(true);

        // Act
        var result = await _commandContext.RequireCardConnection("auto");

        // Assert
        result.Should().BeEquivalentTo(_commandContext);
        _mockCardService.Verify(s => s.Connect("Reader1"), Times.Once);
    }

    [Test]
    public void RequireCardConnection_NoReadersAvailable_ThrowsException()
    {
        // Arrange
        _ = _mockCardService.Setup(s => s.IsSecureChannelEstablished).Returns(false);
        _ = _mockCardService.Setup(s => s.GetReaders()).Returns(Array.Empty<string>());

        // Act & Assert
        Action act = () => { var _ = _commandContext.RequireCardConnection("auto").GetAwaiter().GetResult(); };
        act.Should().ThrowExactly<InvalidOperationException>();
    }

    [Test]
    public void RequireCardConnection_ConnectionFails_ThrowsException()
    {
        // Arrange
        _ = _mockCardService.Setup(s => s.IsSecureChannelEstablished).Returns(false);
        _ = _mockCardService.Setup(s => s.Connect(It.IsAny<string>())).Returns(false);

        // Act & Assert
        Action act = () => { var _ = _commandContext.RequireCardConnection("TestReader").GetAwaiter().GetResult(); };
        act.Should().ThrowExactly<InvalidOperationException>();
    }

    [Test]
    public async Task RequireSecureChannel_AlreadyEstablished_ReturnsContext()
    {
        // Arrange
        _ = _mockCardService.Setup(s => s.IsSecureChannelEstablished).Returns(true);

        // Act
        var result = await _commandContext.RequireSecureChannel();

        // Assert
        result.Should().BeEquivalentTo(_commandContext);
        _mockCardService.Verify(
            s => s.EstablishSecureChannel(It.IsAny<byte[]>(), It.IsAny<byte>()),
            Times.Never
        );
    }

    [Test]
    public async Task RequireSecureChannel_EstablishesSuccessfully_ReturnsContext()
    {
        // Arrange
        _ = _mockCardService.Setup(s => s.IsSecureChannelEstablished).Returns(false);
        _ = _mockCardService
            .Setup(s => s.EstablishSecureChannel(It.IsAny<byte[]>(), It.IsAny<byte>()))
            .Returns(true);

        // Act
        var result = await _commandContext.RequireSecureChannel(1);

        // Assert
        result.Should().BeEquivalentTo(_commandContext);
        _mockCardService.Verify(
            s => s.EstablishSecureChannel(It.IsAny<byte[]>(), (byte)1),
            Times.Once
        );
    }

    [Test]
    public void RequireSecureChannel_EstablishmentFails_ThrowsException()
    {
        // Arrange
        _ = _mockCardService.Setup(s => s.IsSecureChannelEstablished).Returns(false);
        _ = _mockCardService
            .Setup(s => s.EstablishSecureChannel(It.IsAny<byte[]>(), It.IsAny<byte>()))
            .Returns(false);

        // Act & Assert
        Action act = () => { var _ = _commandContext.RequireSecureChannel().GetAwaiter().GetResult(); };
        act.Should().ThrowExactly<InvalidOperationException>();
    }

    [Test]
    public async Task ExecuteAsync_WithAsyncFunction_ExecutesSuccessfully()
    {
        // Arrange
        var executed = false;

        // Act
        var result = await _commandContext.ExecuteAsync(async ctx =>
        {
            executed = true;
            await Task.Delay(1);
            return 42;
        });

        // Assert
        result.Should().Be(42);
        executed.Should().BeTrue();
    }

    [Test]
    public async Task ExecuteAsync_WithSyncFunction_ExecutesSuccessfully()
    {
        // Arrange
        var executed = false;

        // Act
        var result = await _commandContext.ExecuteAsync(ctx =>
        {
            executed = true;
            return 42;
        });

        // Assert
        result.Should().Be(42);
        executed.Should().BeTrue();
    }

    [Test]
    public async Task ExecuteAsync_WithException_ReturnsErrorCode()
    {
        // Act
        var result = await _commandContext.ExecuteAsync((Func<ICliExecutionContext, int>)(ctx =>
            {
                throw new InvalidOperationException("Test exception");
            }));

        // Assert
        result.Should().Be(1);
        _mockDisplayService.Verify(d => d.Exception(It.IsAny<Exception>()), Times.Once);
    }

}
