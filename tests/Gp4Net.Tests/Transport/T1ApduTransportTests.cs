using System;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Tests.Infrastructure;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using WSCT.ISO7816;

namespace Gp4Net.Tests.Transport;

[TestFixture]
[Category("Unit")]
public class T1ApduTransportTests
{
    [Test]
    public async Task Should_Follow_61xx_Response_Chaining_With_Original_Cla()
    {
        // ISO/IEC 7816-4:2020 §§5.3.4 and 5.6: 61xx is protocol-independent.
        var channel = new ScriptedCardChannel(
            TransportProtocol.T1,
            [
                Convert.FromHexString("AA6102"),
                Convert.FromHexString("BB6101"),
                Convert.FromHexString("CC9000"),
            ]
        );
        var transport = new T1ApduTransport(NullLogger<T1ApduTransport>.Instance);
        var command = new TestCommand();

        var result = await transport.TransmitAsync(command, channel);

        result.Should().BeSuccess();
        Assert.That(channel.Commands, Has.Count.EqualTo(3));
        Assert.That(channel.Commands[1], Is.EqualTo(Convert.FromHexString("01C0000002")));
        Assert.That(channel.Commands[2], Is.EqualTo(Convert.FromHexString("01C0000001")));
        Assert.That(result.Value.Data, Is.EqualTo(Convert.FromHexString("AABBCC")));
        Assert.That(result.Value.StatusWord, Is.EqualTo(0x9000));
    }

    private sealed class TestCommand : IApduCommand
    {
        public byte Cla => 0x01;
        public byte Ins => 0xCA;
        public byte P1 => 0x00;
        public byte P2 => 0x00;
        public byte[] Data => [];
        public Maybe<int> ExpectedResponseLength => Maybe<int>.From(256);
        public bool IsExtendedLength => false;

        public CommandAPDU ToApdu()
        {
            return new CommandAPDU(Cla, Ins, P1, P2, 256);
        }

        public byte[] ToBytes()
        {
            return ToApdu().BinaryCommand;
        }
    }
}
