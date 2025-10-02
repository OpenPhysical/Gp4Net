using System.IO;
using System.Threading.Tasks;
using Gp4Net.Tool.Commands.Trace;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration;

[TestFixture]
public class TraceValidationTests
{
    private static readonly string RawTraceDirectory = Path.Combine(
        TestContext.CurrentContext.TestDirectory,
        "TestData",
        "Traces",
        "Raw"
    );

    [TestCase("gp_pro_scp03_enc.log")]
    [TestCase("gp_pro_scp03_mac.log")]
    [TestCase("gp_pro_scp03_renc.log")]
    [TestCase("gp_pro_scp03_rmac.log")]
    public async Task Should_Validate_Scp03_Trace(string traceFile)
    {
        var converter = new TraceConverter();
        var inputPath = Path.Combine(RawTraceDirectory, traceFile);

        var result = await converter.ConvertAsync(
            inputPath,
            "gp_pro",
            verbose: false,
            validate: true,
            keysetSpec: "gp_test"
        );

        Assert.That(
            result.IsSuccess,
            Is.True,
            () =>
                result.IsFailure
                    ? $"Validation failed for {traceFile}: {result.Error}"
                    : string.Empty
        );
    }

    [TestCase("gp_pro_scp02_clr.log")]
    [TestCase("gp_pro_scp02_enc.log")]
    [TestCase("gp_pro_scp02_mac.log")]
    public async Task Should_Validate_Scp02_Trace(string traceFile)
    {
        var converter = new TraceConverter();
        var inputPath = Path.Combine(RawTraceDirectory, traceFile);

        var result = await converter.ConvertAsync(
            inputPath,
            "gp_pro",
            verbose: false,
            validate: true,
            keysetSpec: "gp_test"
        );

        Assert.That(
            result.IsSuccess,
            Is.True,
            () =>
                result.IsFailure
                    ? $"Validation failed for {traceFile}: {result.Error}"
                    : string.Empty
        );
    }
}
