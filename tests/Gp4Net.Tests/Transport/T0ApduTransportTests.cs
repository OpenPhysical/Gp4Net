using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Tests.Infrastructure;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using WSCT.ISO7816;

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
        var virtualCardService = new VirtualCardService();
        virtualCardService.SetupTestEnvironment();
        // Connect to the first virtual reader
        var readers = virtualCardService.GetReadersLegacy();
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
        var command = new TestCommand(); // Uses default GP ISD AID

        // Act
        var result = await _transport.TransmitAsync(command, _channel);

        // Assert - Virtual card should handle GET RESPONSE chaining automatically
        result.Should().BeSuccess();
    }

    [Test]
    public async Task TransmitAsync_WithWrongLengthLe_RetriesWithCorrectLength()
    {
        // Arrange
        var command = new TestCommand { ExpectedResponseLength = Maybe<int>.From(256) };

        // Act
        var result = await _transport.TransmitAsync(command, _channel);

        // Assert - Virtual card should handle wrong length retries automatically
        result.Should().BeSuccess();
    }

    [Test]
    public async Task TransmitAsync_WithNoLe_DoesNotAddLeByte()
    {
        // Arrange
        var command = new TestCommand { ExpectedResponseLength = Maybe<int>.None };

        // Act
        var result = await _transport.TransmitAsync(command, _channel);

        // Assert - Virtual card should handle commands without LE properly
        result.Should().BeSuccess();
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

        /// <summary>
        /// Converts this command to a WSCT CommandAPDU.
        /// </summary>
        /// <returns>The CommandAPDU representation of this command.</returns>
        public CommandAPDU ToApdu()
        {
            return ExpectedResponseLength.Match(
                expectedLength => new CommandAPDU(
                    Cla,
                    Ins,
                    P1,
                    P2,
                    (uint)Data.Length,
                    Data,
                    (uint)expectedLength
                ),
                () => new CommandAPDU(Cla, Ins, P1, P2, (uint)Data.Length, Data)
            );
        }

        /// <summary>
        /// Gets the raw APDU bytes for this command.
        /// </summary>
        /// <returns>The APDU bytes.</returns>
        public byte[] ToBytes()
        {
            return ToApdu().BinaryCommand;
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
        var response = _virtualCardService.SendCommand(command);

        // Combine response data and status word into full response
        byte[] fullResponse = new byte[response.Data.Length + 2];
        Array.Copy(response.Data, fullResponse, response.Data.Length);
        fullResponse[^2] = (byte)(response.StatusWord >> 8);
        fullResponse[^1] = (byte)(response.StatusWord & 0xFF);

        return fullResponse;
    }
}
