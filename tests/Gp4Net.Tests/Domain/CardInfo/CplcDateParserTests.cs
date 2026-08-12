using System;
using AwesomeAssertions;
using Gp4Net.Domain.CardInfo;
using NUnit.Framework;

namespace Gp4Net.Tests.Domain.CardInfo;

[TestFixture]
public sealed class CplcDateParserTests
{
    [Test]
    public void Parse_Should_Decode_Industry_Yddd_Date()
    {
        var parsed = CplcDateParser.Parse(0x4123);

        parsed.HasValue.Should().BeTrue();
        parsed.Value.YearDigit.Should().Be(4);
        parsed.Value.DayOfYear.Should().Be(123);
        parsed.Value.Resolve(2020).Value.Should().Be(new DateTime(2024, 5, 2));
    }

    [TestCase(0x0000)]
    [TestCase(0xFFFF)]
    [TestCase(0x4367)]
    [TestCase(0x41A2)]
    public void Parse_Should_Reject_Invalid_Yddd_Date(int encoded)
    {
        CplcDateParser.Parse((ushort)encoded).HasValue.Should().BeFalse();
    }

    [Test]
    public void ToCplcDate_Should_Not_Imply_A_Decade()
    {
        ushort encoded = CplcDateParser.ToCplcDate(new DateTime(2031, 12, 31)).Value;

        encoded.Should().Be(0x1365);
        CplcDateParser.FormatDate(encoded).Should().Be("YDDD(year digit 1, day 365)");
    }
}
