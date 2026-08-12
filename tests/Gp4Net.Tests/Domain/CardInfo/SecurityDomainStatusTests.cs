using System;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.CardInfo;

public class SecurityDomainStatusTests
{
    [TestCase("C1020004", 4u)]
    [TestCase("C103000046", 70u)]
    [TestCase("C103FFFFFF", 16777215u)]
    public void Parse_ValidSequenceCounter_ReturnsCounter(string hex, uint expected)
    {
        var result = SecurityDomainStatus.Parse(Convert.FromHexString(hex));

        result.IsSuccess.Should().BeTrue();
        result.Value.GetSequenceCounter().Value.Should().Be(expected);
    }

    [TestCase("C10100")]
    [TestCase("C10400000000")]
    [TestCase("C2020004")]
    [TestCase("C1030000")]
    public void Parse_InvalidManagementData_ReturnsFailure(string hex)
    {
        SecurityDomainStatus.Parse(Convert.FromHexString(hex)).IsFailure.Should().BeTrue();
    }

    [Test]
    public void Parse_AbsentManagementData_ReturnsFailure()
    {
        SecurityDomainStatus.Parse(Maybe<byte[]>.None).IsFailure.Should().BeTrue();
    }

    [Test]
    public void Description_ReportsOnlyTheSequenceCounter()
    {
        var status = SecurityDomainStatus.Parse(Convert.FromHexString("C103123456")).Value;

        status.ToString().Should().Be("Security Domain Sequence Counter: 0x123456");
        status.GetShortDescription().Should().Be("Seq:0x123456");
    }
}
