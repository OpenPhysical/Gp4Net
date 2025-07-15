using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using AwesomeAssertions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Tests.Infrastructure;
using Gp4Net.Tests.TestHelpers;
using NUnit.Framework;

namespace Gp4Net.Tests.Services
{
    /// <summary>
    /// Tests for the GlobalPlatformService class.
    /// </summary>
    [TestFixture]
    public class GlobalPlatformServiceTests
    {
        private MockTransport _mockTransport;
        private ICardService _cardService;
        private GlobalPlatformService _service;

        [SetUp]
        public void SetUp()
        {
            _mockTransport = new MockTransport();
            _cardService = new TestCardService(_mockTransport);
            _service = new GlobalPlatformService(_cardService, null);
        }

        [Test]
        public void Constructor_WithNullCardService_ThrowsArgumentNullException()
        {
            // This is acceptable at service boundaries for dependency injection
            Assert.Throws<ArgumentNullException>(() => new GlobalPlatformService(null, null));
        }

        [Test]
        public async Task GetStatusAsync_WithValidStatusSubset_ReturnsResult()
        {
            // Arrange
            var expectedResponse = new byte[] { 0x4F, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x9F, 0x70, 0x01, 0x01, 0x90, 0x00 };
            _mockTransport.AddExpectedResponse(expectedResponse);

            // Act
            var result = await _service.GetStatusAsync(StatusSubset.Applications);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Value.Should().NotBeNull();
            result.Value.Should().BeOfType<ImmutableList<ApplicationInfo>>();
        }

        [Test]
        public async Task GetStatusAsync_WithInvalidResponse_ReturnsError()
        {
            // Arrange
            var invalidResponse = new byte[] { 0x6A, 0x82 }; // File not found
            _mockTransport.AddExpectedResponse(invalidResponse);

            // Act
            var result = await _service.GetStatusAsync(StatusSubset.Applications);

            // Assert
            result.Should().NotBeNull();
            result.IsFailure.Should().BeTrue();
            result.Error.Should().NotBeNull();
        }

        [Test]
        public async Task GetStatusAsync_WithTransportError_ReturnsError()
        {
            // Arrange
            _mockTransport.SetShouldFail(true);

            // Act
            var result = await _service.GetStatusAsync(StatusSubset.Applications);

            // Assert
            result.Should().NotBeNull();
            result.IsFailure.Should().BeTrue();
            result.Error.Should().NotBeNull();
        }

        [Test]
        public async Task SelectAsync_WithValidAid_ReturnsResult()
        {
            // Arrange
            var aid = new byte[] { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 };
            var expectedResponse = new byte[] { 0x6F, 0x10, 0x84, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x90, 0x00 };
            _mockTransport.AddExpectedResponse(expectedResponse);

            // Act
            var result = await _service.SelectAsync(aid);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Value.Should().NotBeNull();
        }

        [Test]
        public async Task SelectAsync_WithNullAid_ReturnsError()
        {
            // Act
            var result = await _service.SelectAsync(null);

            // Assert
            result.Should().NotBeNull();
            result.IsFailure.Should().BeTrue();
            result.Error.Should().NotBeNull();
        }

        [Test]
        public async Task SelectAsync_WithEmptyAid_ReturnsError()
        {
            // Act
            var result = await _service.SelectAsync(new byte[0]);

            // Assert
            result.Should().NotBeNull();
            result.IsFailure.Should().BeTrue();
            result.Error.Should().NotBeNull();
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

        /// <summary>
        /// Simple test card service implementation for testing.
        /// </summary>
        private class TestCardService : ICardService
        {
            private readonly MockTransport _transport;

            public TestCardService(MockTransport transport)
            {
                _transport = transport;
            }

            public bool IsConnected => _transport.IsConnected;

            public async Task<Result<byte[], SmartCardError>> SendCommandAsync(byte[] command)
            {
                try
                {
                    var response = await _transport.SendCommandAsync(command);
                    return response;
                }
                catch (Exception ex)
                {
                    return SmartCardError.CommunicationError(ex.Message);
                }
            }

            public Task<Result<Unit, SmartCardError>> ConnectAsync() => Task.FromResult(Result<Unit, SmartCardError>.Ok(Unit.Value));
            public Task<Result<Unit, SmartCardError>> DisconnectAsync() => Task.FromResult(Result<Unit, SmartCardError>.Ok(Unit.Value));
            public void Dispose() { }
        }
    }
}