using System;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Tests.Infrastructure;
using Gp4Net.Tests.TestHelpers;
using Gp4Net.Tool.Services;
using Gp4Net.Transport;
using NUnit.Framework;
using ToolICommandContext = Gp4Net.Tool.Pipeline.ICommandContext;

namespace Gp4Net.Tests.Services
{
    /// <summary>
    /// Tests for the SmartCardService class.
    /// </summary>
    [TestFixture]
    public class SmartCardServiceTests
    {
        private MockTransport _mockTransport;
        private ICommandPipeline _pipeline;
        private ICommandContext _context;
        private SmartCardService _service;

        [SetUp]
        public void SetUp()
        {
            _mockTransport = new MockTransport();
            _pipeline = new TestCommandPipeline();
            _context = new TestCommandContext();
            _service = new SmartCardService(_pipeline, _context, _mockTransport);
        }

        [Test]
        public void Constructor_WithNullPipeline_ThrowsArgumentNullException()
        {
            // This is acceptable at service boundaries for dependency injection
            Assert.Throws<ArgumentNullException>(() => new SmartCardService(null, _context, _mockTransport));
        }

        [Test]
        public void Constructor_WithNullContext_ThrowsArgumentNullException()
        {
            // This is acceptable at service boundaries for dependency injection
            Assert.Throws<ArgumentNullException>(() => new SmartCardService(_pipeline, null, _mockTransport));
        }

        [Test]
        public void Constructor_WithNullTransport_ThrowsArgumentNullException()
        {
            // This is acceptable at service boundaries for dependency injection
            Assert.Throws<ArgumentNullException>(() => new SmartCardService(_pipeline, _context, null));
        }

        [Test]
        public void IsConnected_WithConnectedTransport_ReturnsTrue()
        {
            // Arrange
            _mockTransport.SetConnected(true);

            // Act
            var result = _service.IsConnected;

            // Assert
            result.Should().BeTrue();
        }

        [Test]
        public void IsConnected_WithDisconnectedTransport_ReturnsFalse()
        {
            // Arrange
            _mockTransport.SetConnected(false);

            // Act
            var result = _service.IsConnected;

            // Assert
            result.Should().BeFalse();
        }

        [Test]
        public async Task SendCommandAsync_WithValidCommand_ReturnsResult()
        {
            // Arrange
            var command = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 };
            var expectedResponse = new byte[] { 0x90, 0x00 };
            _mockTransport.AddExpectedResponse(expectedResponse);

            // Act
            var result = await _service.SendCommandAsync(command);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Value.Should().NotBeNull();
            result.Value.Should().BeEquivalentTo(expectedResponse);
        }

        [Test]
        public async Task SendCommandAsync_WithTransportError_ReturnsError()
        {
            // Arrange
            var command = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 };
            _mockTransport.SetShouldFail(true);

            // Act
            var result = await _service.SendCommandAsync(command);

            // Assert
            result.Should().NotBeNull();
            result.IsFailure.Should().BeTrue();
            result.Error.Should().NotBeNull();
        }

        [Test]
        public async Task ConnectAsync_WithValidTransport_ReturnsSuccess()
        {
            // Act
            var result = await _service.ConnectAsync();

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
        }

        [Test]
        public async Task DisconnectAsync_WithValidTransport_ReturnsSuccess()
        {
            // Act
            var result = await _service.DisconnectAsync();

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
        }

        /// <summary>
        /// Simple test command pipeline implementation for testing.
        /// </summary>
        private class TestCommandPipeline : ICommandPipeline
        {
            public Task<Result<CommandResponse, SmartCardError>> ExecuteAsync(
                IApduCommand command,
                ToolICommandContext context,
                CancellationToken cancellationToken = default)
            {
                // Simple pass-through implementation for testing
                var response = new CommandResponse(new byte[] { 0x90, 0x00 }, null);
                return Task.FromResult(Result<CommandResponse, SmartCardError>.Ok(response));
            }

            public Task<Result<CommandResponse, SmartCardError>> ExecuteAsync(
                CommandRequest request,
                CancellationToken cancellationToken = default)
            {
                // Simple pass-through implementation for testing
                var response = new CommandResponse(new byte[] { 0x90, 0x00 }, null);
                return Task.FromResult(Result<CommandResponse, SmartCardError>.Ok(response));
            }
        }

        /// <summary>
        /// Simple test command context implementation for testing.
        /// </summary>
        private class TestCommandContext : ToolICommandContext
        {
            public IDisplayService Display { get; } = null!;
            public ICardService CardService { get; } = null!;
            public IKeysetResolver KeysetResolver { get; } = null!;

            public Gp4Net.Services.IGlobalPlatformService GetGlobalPlatformService() => null!;

            public Task<ToolICommandContext> RequireCardConnection(string? readerName = null) =>
                Task.FromResult<ToolICommandContext>(this);

            public Task<ToolICommandContext> RequireSecureChannel(byte securityLevel = 1, string? keyset = null) =>
                Task.FromResult<ToolICommandContext>(this);

            public Task<int> ExecuteAsync(Func<ToolICommandContext, Task<int>> commandLogic) =>
                Task.FromResult(0);

            public Task<int> ExecuteAsync(Func<ToolICommandContext, int> commandLogic) =>
                Task.FromResult(0);
        }
    }
}