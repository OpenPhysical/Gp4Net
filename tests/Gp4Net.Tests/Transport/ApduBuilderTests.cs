using CSharpFunctionalExtensions;
using Gp4Net.Transport;
using NUnit.Framework;

namespace Gp4Net.Tests.Transport;

[TestFixture]
[Category("Unit")]
public class ApduBuilderTests
{
    [Test]
    public void CreateCommand_WithShortDataAndMaxResponse_UsesShortLe00()
    {
        byte[] data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        var result = ApduBuilder.CreateCommand(
            0x80,
            0x50,
            0x01,
            0x00,
            Maybe<byte[]>.From(data),
            Maybe<int>.From(256)
        );

        Assert.That(result.IsSuccess, Is.True, () => result.Error.ToString());
        byte[] apdu = result.Value.ToBytes();

        Assert.That(apdu.Length, Is.EqualTo(14));
        Assert.That(apdu[4], Is.EqualTo(0x08));
        Assert.That(apdu[13], Is.EqualTo(0x00));
    }

    [Test]
    public void CreateCommand_WithExtendedData_UsesExtendedLengthEncoding()
    {
        byte[] data = new byte[300];

        var result = ApduBuilder.CreateCommand(
            0x80,
            0xE8,
            0x00,
            0x00,
            Maybe<byte[]>.From(data),
            Maybe<int>.From(256)
        );

        Assert.That(result.IsSuccess, Is.True, () => result.Error.ToString());
        byte[] apdu = result.Value.ToBytes();

        Assert.That(apdu.Length, Is.EqualTo(4 + 3 + data.Length + 2));
        Assert.That(apdu[4], Is.EqualTo(0x00));
        Assert.That(apdu[5], Is.EqualTo(0x01));
        Assert.That(apdu[6], Is.EqualTo(0x2C));
        Assert.That(apdu[^2], Is.EqualTo(0x01));
        Assert.That(apdu[^1], Is.EqualTo(0x00));
    }
}
