using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Pipeline;
using Gp4Net.Services;
using Gp4Net.Tests.Infrastructure;
using Gp4Net.Tests.TestHelpers;
using Gp4Net.Tool.Services;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Transport;
using NUnit.Framework;

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
        private IPipelineContext _context;
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
                IPipelineContext context,
                CancellationToken cancellationToken = default)
            {
                // Simple pass-through implementation for testing
                var response = new CommandResponse(new byte[] { 0x90, 0x00 }, null);
                return Task.FromResult(Result.Success<CommandResponse, SmartCardError>(response));
            }

            public Task<Result<CommandResponse, SmartCardError>> ExecuteAsync(
                CommandRequest request,
                CancellationToken cancellationToken = default)
            {
                // Simple pass-through implementation for testing
                var response = new CommandResponse(new byte[] { 0x90, 0x00 }, null);
                return Task.FromResult(Result.Success<CommandResponse, SmartCardError>(response));
            }
        }

        /// <summary>
        /// Simple test command context implementation for testing.
        /// </summary>
        private class TestCommandContext : IPipelineContext
        {
            private readonly ImmutableDictionary<string, object> _values;

            public TestCommandContext() : this(ImmutableDictionary<string, object>.Empty)
            {
            }

            private TestCommandContext(ImmutableDictionary<string, object> values)
            {
                _values = values;
            }

            public Maybe<T> Get<T>(string key)
            {
                if (_values.TryGetValue(key, out var value) && value is T typedValue)
                {
                    return Maybe<T>.From(typedValue);
                }
                return Maybe<T>.None;
            }

            public IPipelineContext With<T>(string key, T value)
            {
                var newValues = value != null ? _values.SetItem(key, value) : _values;
                return new TestCommandContext(newValues);
            }

            public IPipelineContext Without(string key)
            {
                return new TestCommandContext(_values.Remove(key));
            }

            public ImmutableArray<string> Keys => _values.Keys.ToImmutableArray();

            public IPipelineContext WithMany(ImmutableDictionary<string, object> values)
            {
                var newValues = _values;
                foreach (var kvp in values)
                {
                    newValues = newValues.SetItem(kvp.Key, kvp.Value);
                }
                return new TestCommandContext(newValues);
            }

            public ImmutableDictionary<string, object> ToImmutableDictionary()
            {
                return _values;
            }
        }
    }
}