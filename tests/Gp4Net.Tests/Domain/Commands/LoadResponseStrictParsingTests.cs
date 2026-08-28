using System;
using AwesomeAssertions;
using Gp4Net.Domain.Commands;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.Commands;

[TestFixture]
public sealed class LoadResponseStrictParsingTests
{
    [Test]
    public void Parse_DelegatedConfirmation_ParsesAllFields()
    {
        byte[] receipt = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        byte[] unique = Convert.FromHexString("420101450102");
        byte[] confirmation = [0x10, .. receipt, 0x02, 0x12, 0x34,
            (byte)unique.Length, .. unique];
        byte[] response = [(byte)confirmation.Length, .. confirmation];

        var result = LoadResponse.Parse(response, 0x9000);

        result.IsSuccess.Should().BeTrue();
        result.Value.Confirmation.HasValue.Should().BeTrue();
        result.Value.Confirmation.Value.Receipt.Should().Equal(receipt);
        result.Value.Confirmation.Value.ConfirmationCounter.Should().Be(0x1234);
        result.Value.Confirmation.Value.SecurityDomainUniqueData.Should().Equal(unique);
    }

    [TestCase("811000")]
    [TestCase("0100")]
    [TestCase("020000")]
    [TestCase("04100000")]
    public void Parse_RejectsMalformedOrNonCanonicalConfirmations(string value)
    {
        LoadResponse.Parse(Convert.FromHexString(value), 0x9000).IsFailure.Should().BeTrue();
    }
}
