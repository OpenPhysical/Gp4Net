using System;
using System.Threading.Tasks;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using CSharpFunctionalExtensions;

namespace Gp4Net.Tests.Transport;

public class T0ApduTransportTests
{
    private readonly Mock<ILogger<T0ApduTransport>> _mockLogger;
    private readonly Mock<ICardChannel> _mockChannel;
    private readonly T0ApduTransport _transport;

    public T0ApduTransportTests()
    {
        _mockLogger = new Mock<ILogger<T0ApduTransport>>();
        _mockChannel = new Mock<ICardChannel>();
        _transport = new T0ApduTransport(_mockLogger.Object);
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
        var command = new TestCommand { Data = new byte[10] };

        // First response indicates more data available (SW1=0x61)
        _ = _mockChannel
            .SetupSequence(c => c.TransmitAsync(It.IsAny<byte[]>(), default))
            .ReturnsAsync(new byte[] { 0x61, 0x10 }) // 16 more bytes available
            .ReturnsAsync(
                new byte[]
                {
                    0x01,
                    0x02,
                    0x03,
                    0x04,
                    0x05,
                    0x06,
                    0x07,
                    0x08,
                    0x09,
                    0x0A,
                    0x0B,
                    0x0C,
                    0x0D,
                    0x0E,
                    0x0F,
                    0x10,
                    0x90,
                    0x00,
                }
            ); // Data + SW

        // Act
        var response = await _transport.TransmitAsync(command, _mockChannel.Object);

        // Assert
        Assert.That(response, Is.Not.Null);
        Assert.That(response.IsSuccess, Is.True);
        Assert.That(response.Data.Length, Is.EqualTo(16));
        Assert.That(response.StatusWord.Value, Is.EqualTo((ushort)0x9000));

        // Verify GET RESPONSE was sent
        _mockChannel.Verify(
            c =>
                c.TransmitAsync(
                    It.Is<byte[]>(cmd => cmd[0] == 0x00 && cmd[1] == 0xC0), // GET RESPONSE
                    default
                ),
            Times.Once
        );
    }

    [Test]
    public async Task TransmitAsync_WithWrongLengthLe_RetriesWithCorrectLength()
    {
        // Arrange
        var command = new TestCommand { ExpectedResponseLength = 256 };

        // First response indicates wrong LE (SW1=0x6C)
        _ = _mockChannel
            .SetupSequence(c => c.TransmitAsync(It.IsAny<byte[]>(), default))
            .ReturnsAsync(new byte[] { 0x6C, 0x10 }) // Correct length is 0x10
            .ReturnsAsync(
                new byte[]
                {
                    0x01,
                    0x02,
                    0x03,
                    0x04,
                    0x05,
                    0x06,
                    0x07,
                    0x08,
                    0x09,
                    0x0A,
                    0x0B,
                    0x0C,
                    0x0D,
                    0x0E,
                    0x0F,
                    0x10,
                    0x90,
                    0x00,
                }
            ); // Data + SW

        // Act
        var response = await _transport.TransmitAsync(command, _mockChannel.Object);

        // Assert
        Assert.That(response, Is.Not.Null);
        Assert.That(response.IsSuccess, Is.True);
        Assert.That(response.Data.Length, Is.EqualTo(16));

        // Verify command was sent at least twice (original + retry)
        _mockChannel.Verify(
            c => c.TransmitAsync(It.IsAny<byte[]>(), default),
            Times.AtLeast(2)
        );
    }

    [Test]
    public async Task TransmitAsync_WithNoLe_DoesNotAddLeByte()
    {
        // Arrange
        var command = new TestCommand { ExpectedResponseLength = null };
        byte[] capturedCommand = null;

        _ = _mockChannel
            .Setup(c => c.TransmitAsync(It.IsAny<byte[]>(), default))
            .Callback<byte[], System.Threading.CancellationToken>(
                (cmd, ct) => capturedCommand = cmd
            )
            .ReturnsAsync(new byte[] { 0x90, 0x00 });

        // Act
        _ = await _transport.TransmitAsync(command, _mockChannel.Object);

        // Assert
        Assert.That(capturedCommand, Is.Not.Null);
        Assert.That(capturedCommand.Length, Is.EqualTo(4)); // CLA INS P1 P2 only
    }

    private class TestCommand : IApduCommand
    {
        public byte Cla => 0x00;
        public byte Ins => 0xA4;
        public byte P1 => 0x04;
        public byte P2 => 0x00;
        public byte[] Data { get; set; } = [];
        public int? ExpectedResponseLength { get; set; }
        public bool IsExtendedLength => false;
    }
}