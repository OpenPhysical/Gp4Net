using System;
using AwesomeAssertions;
using Gp4Net.Services;
using NUnit.Framework;

namespace Gp4Net.Tests.Compliance;

[TestFixture]
[Category("Unit")]
[Category("GpCompliance")]
public class LoadFileDataBlockHashTests
{
    /// <summary>
    /// GP Card Specification v2.3.1, Appendix C.2 and Table C-3: OPEN may identify
    /// SHA-1, SHA-256, SHA-384, or SHA-512 from the LFDBH length.
    /// </summary>
    [TestCase("A9993E364706816ABA3E25717850C26C9CD0D89D")]
    [TestCase("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")]
    [TestCase(
        "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7"
    )]
    [TestCase(
        "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"
    )]
    public void Should_Verify_Each_Supported_Lfdbh_Length(string expectedHashHex)
    {
        var result = new CapFileOperations().VerifyLoadFileDataBlockHash(
            "abc"u8.ToArray(),
            Convert.FromHexString(expectedHashHex)
        );

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Should().BeTrue();
    }

    /// <summary>
    /// GP Card Specification v2.3.1, Appendix C.2: the LFDBH algorithm shall be a
    /// supported algorithm identified explicitly or automatically by OPEN.
    /// </summary>
    [Test]
    public void Should_Reject_An_Unsupported_Lfdbh_Length()
    {
        var result = new CapFileOperations().VerifyLoadFileDataBlockHash(
            "abc"u8.ToArray(),
            new byte[16]
        );

        _ = result.IsFailure.Should().BeTrue();
    }

    /// <summary>
    /// GP Card Specification v2.3.1, Appendix C.3: DAP verification requires the
    /// verifying Security Domain's key and implicitly known algorithm.
    /// </summary>
    [Test]
    public void Should_Not_Fabricate_A_Dap_Verification_Key()
    {
        var result = new CapFileOperations().VerifyDapSignature([0x01], [0x02]);

        _ = result.IsFailure.Should().BeTrue();
    }
}
