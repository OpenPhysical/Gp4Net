// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

namespace Gp4Net.Tests.Tool.Commands.Card
{
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using Gp4Net.Tool.Commands.Card;
    using Gp4Net.Tool.Pipeline;
    using Gp4Net.Tool.Services;
    using Moq;
    using NUnit.Framework;

    /// <summary>
    /// Unit tests for the <see cref="ListReadersCommand"/> class.
    /// </summary>
    [TestFixture]
    public class ListReadersCommandTests
    {
        private Mock<IDisplayService> mockDisplayService;
        private Mock<ICardService> mockCardService;
        private Mock<IGlobalPlatformService> mockGlobalPlatformService;
        private Mock<IKeysetResolver> mockKeysetResolver;
        private MockCommandContext mockContext;
        private ListReadersCommand command;

        /// <summary>
        /// Sets up the test environment before each test.
        /// </summary>
        [SetUp]
        public void SetUp()
        {
            this.mockDisplayService = new Mock<IDisplayService>();
            this.mockCardService = new Mock<ICardService>();
            this.mockGlobalPlatformService = new Mock<IGlobalPlatformService>();
            this.mockKeysetResolver = new Mock<IKeysetResolver>();

            this.mockContext = new MockCommandContext(
                this.mockDisplayService.Object,
                this.mockCardService.Object,
                this.mockGlobalPlatformService.Object,
                this.mockKeysetResolver.Object
            );

            this.command = new ListReadersCommand();
        }

        /// <summary>
        /// Tests that the command can be constructed without dependencies.
        /// </summary>
        [Test]
        public void Constructor_WithNoDependencies_CreatesInstance()
        {
            // Act & Assert
            Assert.That(this.command, Is.Not.Null);
        }

        /// <summary>
        /// Tests that the command executes successfully when readers are available.
        /// </summary>
        [Test]
        public async Task ExecuteAsync_WithAvailableReaders_ReturnsSuccess()
        {
            // Arrange
            var readers = new List<string> { "Reader 1", "Reader 2" }.AsReadOnly();
            _ = this.mockCardService.Setup(x => x.GetReaders()).Returns(readers);
            var settings = new ListReadersCommand.Settings();

            // Act
            var result = await this.command.ExecuteAsync(this.mockContext, settings);

            // Assert
            Assert.That(result, Is.EqualTo(0));
            this.mockCardService.Verify(x => x.GetReaders(), Times.Once);
        }

        /// <summary>
        /// Tests that the command handles no readers gracefully.
        /// </summary>
        [Test]
        public async Task ExecuteAsync_WithNoReaders_ReturnsSuccess()
        {
            // Arrange
            var readers = new List<string>().AsReadOnly();
            _ = this.mockCardService.Setup(x => x.GetReaders()).Returns(readers);
            var settings = new ListReadersCommand.Settings();

            // Act
            var result = await this.command.ExecuteAsync(this.mockContext, settings);

            // Assert
            Assert.That(result, Is.EqualTo(0));
            this.mockCardService.Verify(x => x.GetReaders(), Times.Once);
        }

        /// <summary>
        /// Tests that the command handles card service exceptions gracefully.
        /// </summary>
        [Test]
        public async Task ExecuteAsync_WithCardServiceException_ReturnsError()
        {
            // Arrange
            _ = this
                .mockCardService.Setup(x => x.GetReaders())
                .Throws(new System.InvalidOperationException("Test exception"));
            var settings = new ListReadersCommand.Settings();

            // Act
            var result = await this.command.ExecuteAsync(this.mockContext, settings);

            // Assert
            Assert.That(result, Is.EqualTo(1));
            this.mockCardService.Verify(x => x.GetReaders(), Times.Once);
        }
    }
}
