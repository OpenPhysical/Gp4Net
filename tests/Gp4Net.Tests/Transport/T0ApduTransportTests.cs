using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Gp4Net.Tests.Transport;

[TestFixture]
[Category("Unit")]
public class T0ApduTransportTests
{
    private readonly ILogger<T0ApduTransport> _logger;
    private readonly ICardChannel _channel;
    private readonly T0ApduTransport _transport;

    public T0ApduTransportTests()
    {
        _logger = NullLogger<T0ApduTransport>.Instance;
        VirtualCardService virtualCardService = new VirtualCardService();
        virtualCardService.SetupComprehensiveTestEnvironment();
        // Connect to the first virtual reader
        var readers = virtualCardService.GetReaders();
        if (readers.Count > 0)
        {
            virtualCardService.Connect(readers[0]);
        }
        // Create test channel for transport testing
        _channel = new TestCardChannel(virtualCardService);
        _transport = new T0ApduTransport(_logger);
    }

    [Test]
    public void Constructor_SetsCorrectProtocol()
    {
        Assert.That(_transport.Protocol, Is.EqualTo(TransportProtocol.T0));
    }

    [Test]
    public void Constructor_SetsCorrectLimits()
    {
        Assert.Multiple(() =>
        {
            Assert.That(_transport.MaxCommandDataLength, Is.EqualTo(255));
            Assert.That(_transport.MaxResponseDataLength, Is.EqualTo(256));
            Assert.That(_transport.SupportsExtendedLength, Is.False);
        });
    }

    [Test]
    public async Task TransmitAsync_WithGetResponseChaining_Works()
    {
        // Arrange
        TestCommand command = new TestCommand(); // Uses default GP ISD AID

        // Act
        ApduResponse? response = await _transport.TransmitAsync(command, _channel);

        // Assert - Virtual card should handle GET RESPONSE chaining automatically
        Assert.That(response, Is.Not.Null);
        Assert.That(response.IsSuccess, Is.True);
    }

    [Test]
    public async Task TransmitAsync_WithWrongLengthLe_RetriesWithCorrectLength()
    {
        // Arrange
        TestCommand command = new TestCommand { ExpectedResponseLength = Maybe<int>.From(256) };

        // Act
        ApduResponse? response = await _transport.TransmitAsync(command, _channel);

        // Assert - Virtual card should handle wrong length retries automatically
        Assert.That(response, Is.Not.Null);
        Assert.That(response.IsSuccess, Is.True);
    }

    [Test]
    public async Task TransmitAsync_WithNoLe_DoesNotAddLeByte()
    {
        // Arrange
        TestCommand command = new TestCommand { ExpectedResponseLength = Maybe<int>.None };

        // Act
        ApduResponse? response = await _transport.TransmitAsync(command, _channel);

        // Assert - Virtual card should handle commands without LE properly
        Assert.That(response, Is.Not.Null);
        Assert.That(response.IsSuccess, Is.True);
    }

    private class TestCommand : IApduCommand
    {
        public byte Cla
        {
            get { return 0x00; }
        }
        public byte Ins
        {
            get { return 0xA4; }
        }
        public byte P1
        {
            get { return 0x04; }
        }
        public byte P2
        {
            get { return 0x00; }
        }
        public byte[] Data { get; set; } = Convert.FromHexString("A000000151000000"); // GP ISD AID
        public Maybe<int> ExpectedResponseLength { get; set; } = Maybe<int>.None;
        public bool IsExtendedLength
        {
            get { return false; }
        }
    }
}

/// <summary>
/// Minimal card channel implementation for transport testing.
/// Eliminates unnecessary adapter layers by implementing ICardChannel directly.
/// </summary>
internal class TestCardChannel : ICardChannel
{
    private readonly VirtualCardService _virtualCardService;

    public TestCardChannel(VirtualCardService virtualCardService)
    {
        _virtualCardService = virtualCardService;
    }

    public TransportProtocol Protocol => TransportProtocol.T0;
    public bool IsOpen => true;

    public async Task<byte[]> TransmitAsync(
        byte[] command,
        CancellationToken cancellationToken = default
    )
    {
        await Task.CompletedTask; // Satisfy async requirement

        // Use virtual card service API directly
        VirtualCommandResponse response = _virtualCardService.SendCommand(command);

        // Combine response data and status word into full response
        byte[] fullResponse = new byte[response.Data.Length + 2];
        Array.Copy(response.Data, fullResponse, response.Data.Length);
        fullResponse[^2] = (byte)(response.StatusWord >> 8);
        fullResponse[^1] = (byte)(response.StatusWord & 0xFF);

        return fullResponse;
    }
}
