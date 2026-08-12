using AwesomeAssertions;
using Gp4Net.CardEmulator.Functional;
using NUnit.Framework;

namespace Gp4Net.CardEmulator.Tests.Functional;

[TestFixture]
[Category("Unit")]
[Category("GpCompliance")]
public class DapProcessorTests
{
    private static readonly byte[] DapLoadFile =
    [
        0xE2,
        0x0A,
        0x4F,
        0x05,
        0xA0,
        0x00,
        0x00,
        0x00,
        0x01,
        0xC3,
        0x01,
        0xAA,
        0xC4,
        0x00,
    ];

    /// <summary>GP Card Specification v2.3.1, Table 11-58.</summary>
    [Test]
    public void Should_Parse_E2_Dap_Block_With_4F_And_C3()
    {
        var result = DapProcessor.ParseDapBlocks(DapLoadFile);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Should().HaveCount(1);
        _ = result.Value[0].SecurityDomainAid.Should().Equal(0xA0, 0x00, 0x00, 0x00, 0x01);
        _ = result.Value[0].LoadFileDataBlockSignature.Should().Equal(0xAA);
    }

    /// <summary>
    /// GP Card Specification v2.3.1, Table 11-58: DAP Blocks precede the Load File Data Block.
    /// </summary>
    [Test]
    public void Should_Not_Treat_E2_Inside_Load_File_Data_As_A_Dap_Block()
    {
        byte[] loadFile = [0xC4, 0x03, 0x01, 0xE2, 0x02];

        var result = DapProcessor.ParseDapBlocks(loadFile);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Should().BeEmpty();
    }

    /// <summary>GP Card Specification v2.3.1, Table 11-58.</summary>
    [Test]
    public void Should_Reject_A_Dap_Block_Without_Valid_4F_And_C3_Objects()
    {
        byte[] malformed = [0xE2, 0x03, 0x4F, 0x01, 0x00];

        var result = DapProcessor.ParseDapBlocks(malformed);

        _ = result.IsFailure.Should().BeTrue();
    }

    /// <summary>
    /// GP Card Specification v2.3.1, sections 9.2.1 and C.3: each DAP signature is
    /// verified by the Security Domain identified in its DAP Block using its DAP key.
    /// </summary>
    [Test]
    public void Should_Reject_Dap_When_No_Security_Domain_Verification_Key_Is_Configured()
    {
        var result = DapProcessor.VerifyDapSignature(DapLoadFile);

        _ = result.IsFailure.Should().BeTrue();
    }
}
