using AwesomeAssertions;
using Gp4Net.CardEmulator.Transport;
using Gp4Net.Core;
using NUnit.Framework;

namespace Gp4Net.CardEmulator.Tests.Transport;

[TestFixture]
public class VirtualCardErrorResponseTests
{
    // GP Card Specification v2.3.1, Section 11.1.3, Table 11-10.
    [TestCase(0x6700)]
    [TestCase(0x6982)]
    [TestCase(0x6985)]
    [TestCase(0x6A86)]
    [TestCase(0x6D00)]
    [TestCase(0x6E00)]
    public void Should_Preserve_Command_Error_Status_Word(int expected)
    {
        SmartCardError error = SmartCardError.FromStatusWord((ushort)expected);

        byte[] response = VirtualCardErrorResponse.ToBytes(error);

        response.Should().Equal((byte)(expected >> 8), (byte)expected);
    }

    // GP Card Specification v2.3.1, Section 11.1.3, Table 11-10: 6400 is no specific diagnosis.
    [Test]
    public void Should_Return_No_Specific_Diagnosis_When_Error_Has_No_Status_Word()
    {
        SmartCardError error = SmartCardError.UnexpectedError("failure");

        byte[] response = VirtualCardErrorResponse.ToBytes(error);

        response.Should().Equal(0x64, 0x00);
    }
}
