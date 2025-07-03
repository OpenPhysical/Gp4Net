using System;
using System.Threading.Tasks;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Services;
using Moq;
using NUnit.Framework;
using Spectre.Console.Testing;

namespace Gp4Net.Tests.Tool.Commands
{
    /// <summary>
    /// Tests for the pipeline command context which replaces BaseCommand functionality.
    /// </summary>
    [TestFixture]
    public class BaseCommandTests
    {
        private Mock<IDisplayService> _mockDisplayService;
        private Mock<ICardService> _mockCardService;
        private Mock<IGlobalPlatformService> _mockGlobalPlatformService;
        private Mock<IKeysetResolver> _mockKeysetResolver;
        private CommandContext _commandContext;
        private TestConsole _console;

        [SetUp]
        public void Setup()
        {
            _mockDisplayService = new Mock<IDisplayService>();
            _mockCardService = new Mock<ICardService>();
            _mockGlobalPlatformService = new Mock<IGlobalPlatformService>();
            _mockKeysetResolver = new Mock<IKeysetResolver>();
            _console = new TestConsole();

            _commandContext = new CommandContext(
                _mockDisplayService.Object,
                _mockCardService.Object,
                _mockGlobalPlatformService.Object,
                _mockKeysetResolver.Object
            );
        }

        [TearDown]
        public void TearDown()
        {
            _console?.Dispose();
        }

        #region RequireCardConnection Tests

        [Test]
        public async Task RequireCardConnection_AlreadyConnected_ReturnsContext()
        {
            // Arrange
            _ = _mockCardService.Setup(s => s.IsConnected).Returns(true);

            // Act
            var result = await _commandContext.RequireCardConnection("TestReader");

            // Assert
            Assert.That(result, Is.EqualTo(_commandContext));
            _mockCardService.Verify(s => s.Connect(It.IsAny<string>()), Times.Never);
        }

        [Test]
        public async Task RequireCardConnection_WithSpecificReader_ConnectsSuccessfully()
        {
            // Arrange
            _ = _mockCardService.Setup(s => s.IsConnected).Returns(false);
            _ = _mockCardService.Setup(s => s.Connect("TestReader")).Returns(true);

            // Act
            var result = await _commandContext.RequireCardConnection("TestReader");

            // Assert
            Assert.That(result, Is.EqualTo(_commandContext));
            _mockCardService.Verify(s => s.Connect("TestReader"), Times.Once);
        }

        [Test]
        public async Task RequireCardConnection_AutoDetect_UsesFirstReader()
        {
            // Arrange
            _ = _mockCardService.Setup(s => s.IsConnected).Returns(false);
            _ = _mockCardService.Setup(s => s.GetReaders()).Returns(new[] { "Reader1", "Reader2" });
            _ = _mockCardService.Setup(s => s.Connect("Reader1")).Returns(true);

            // Act
            var result = await _commandContext.RequireCardConnection("auto");

            // Assert
            Assert.That(result, Is.EqualTo(_commandContext));
            _mockCardService.Verify(s => s.Connect("Reader1"), Times.Once);
        }

        [Test]
        public void RequireCardConnection_NoReadersAvailable_ThrowsException()
        {
            // Arrange
            _ = _mockCardService.Setup(s => s.IsConnected).Returns(false);
            _ = _mockCardService.Setup(s => s.GetReaders()).Returns(Array.Empty<string>());

            // Act & Assert
            _ = Assert.ThrowsAsync<InvalidOperationException>(
                async () => await _commandContext.RequireCardConnection("auto")
            );
        }

        [Test]
        public void RequireCardConnection_ConnectionFails_ThrowsException()
        {
            // Arrange
            _ = _mockCardService.Setup(s => s.IsConnected).Returns(false);
            _ = _mockCardService.Setup(s => s.Connect(It.IsAny<string>())).Returns(false);

            // Act & Assert
            _ = Assert.ThrowsAsync<InvalidOperationException>(
                async () => await _commandContext.RequireCardConnection("TestReader")
            );
        }

        #endregion

        #region RequireSecureChannel Tests

        [Test]
        public async Task RequireSecureChannel_AlreadyEstablished_ReturnsContext()
        {
            // Arrange
            _ = _mockCardService.Setup(s => s.IsSecureChannelEstablished).Returns(true);

            // Act
            var result = await _commandContext.RequireSecureChannel();

            // Assert
            Assert.That(result, Is.EqualTo(_commandContext));
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
            Assert.That(result, Is.EqualTo(_commandContext));
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
            _ = Assert.ThrowsAsync<InvalidOperationException>(
                async () => await _commandContext.RequireSecureChannel()
            );
        }

        #endregion

        #region ExecuteAsync Tests

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
            Assert.That(result, Is.EqualTo(42));
            Assert.That(executed, Is.True);
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
            Assert.That(result, Is.EqualTo(42));
            Assert.That(executed, Is.True);
        }

        [Test]
        public async Task ExecuteAsync_WithException_ReturnsErrorCode()
        {
            // Act
            var result = await _commandContext.ExecuteAsync(
                (Func<ICommandContext, int>)(
                    ctx =>
                    {
                        throw new InvalidOperationException("Test exception");
                    }
                )
            );

            // Assert
            Assert.That(result, Is.EqualTo(1));
            _mockDisplayService.Verify(d => d.Exception(It.IsAny<Exception>()), Times.Once);
        }

        #endregion
    }
}
