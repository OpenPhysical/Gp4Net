using System;
using AwesomeAssertions;
using Gp4Net.Domain.DataObjects;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.DataObjects;

[TestFixture]
public class SecurityDomainInfoCodecTests
{
    [Test]
    public void Should_Decode_Scp02_Sequence_Counter()
    {
        // GP Card Specification v2.3.1, section 11.3.2.1 and Appendix E.5.1.
        var result = SecurityDomainInfoCodec.Decode(Convert.FromHexString("C1021234"));

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.SequenceCounter.Should().Equal(0x12, 0x34);
        _ = result.Value.Value.Should().Be(0x1234);
    }

    [Test]
    public void Should_Decode_Scp03_Sequence_Counter()
    {
        // SCP03 Amendment D v1.2, section 7.1.1.6: the conditional counter is three bytes.
        var result = SecurityDomainInfoCodec.Decode(Convert.FromHexString("C103000019"));

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.SequenceCounter.Should().Equal(0x00, 0x00, 0x19);
        _ = result.Value.Value.Should().Be(0x19);
    }

    [TestCase("C100")]
    [TestCase("C10100")]
    [TestCase("C10400000001")]
    public void Should_Reject_Invalid_Sequence_Counter_Length(string encoded)
    {
        // GP Card Specification v2.3.1 Appendix E.5.1; SCP03 Amendment D v1.2 section 7.1.1.6.
        var result = SecurityDomainInfoCodec.Decode(Convert.FromHexString(encoded));

        _ = result.IsFailure.Should().BeTrue();
    }

    [Test]
    public void Should_Reject_A_Different_Tag()
    {
        var result = SecurityDomainInfoCodec.Decode(Convert.FromHexString("C2021234"));

        _ = result.IsFailure.Should().BeTrue();
    }

    [TestCase("0001")]
    [TestCase("000001")]
    public void Should_Round_Trip_Sequence_Counter(string counterHex)
    {
        byte[] counter = Convert.FromHexString(counterHex);
        var encoded = SecurityDomainInfoCodec.Encode(
            new SecurityDomainInfo { SequenceCounter = counter }
        );

        _ = encoded.IsSuccess.Should().BeTrue();
        _ = SecurityDomainInfoCodec
            .Decode(encoded.Value)
            .Value.SequenceCounter.Should()
            .Equal(counter);
    }
}
