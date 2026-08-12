using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AwesomeAssertions;
using Gp4Net.Tool.Commands.Trace;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Validates this library's secure-channel implementation against GlobalPlatformPro captures
/// taken from a physical JCOP card.
/// </summary>
/// <remarks>
/// These traces are the suite's external conformance oracle. Every C-MAC in them was accepted
/// by a real card and every R-MAC was produced by one, so the recorded bytes cannot agree with
/// a mistake in this codebase. <c>TraceConverter</c> hard-fails the conversion when any single
/// cryptographic check fails (see <c>ConvertCommand.ValidateTraceAsync</c>), which is what makes
/// asserting success meaningful here.
///
/// The assertions below additionally require that the expected checks actually ran. Validation
/// is skipped silently when no results are produced at all, so a regression that stopped
/// deriving session keys — or a parser change that yielded no secured exchanges — would
/// otherwise leave these tests green while verifying nothing.
/// </remarks>
[TestFixture]
public class TraceValidationTests
{
    private const string TestKeyset = "gp_test";

    /// <summary>A well-formed AES-128 key that is not the GP test key.</summary>
    private const string WrongKeyset = "000102030405060708090A0B0C0D0E0F";

    private static readonly string RawTraceDirectory = Path.Combine(
        TestContext.CurrentContext.TestDirectory,
        "TestData",
        "Traces",
        "Raw"
    );

    /// <summary>
    /// Traces that establish a secure channel and then issue at least one protected command.
    /// </summary>
    private static readonly string[] SecureChannelTraces =
    [
        "gp_pro_scp02_mac.log",
        "gp_pro_scp02_enc.log",
        "gp_pro_scp03_mac.log",
        "gp_pro_scp03_enc.log",
        "gp_pro_scp03_rmac.log",
        "gp_pro_scp03_renc.log",
    ];

    [TestCase("gp_pro_scp03_enc.log")]
    [TestCase("gp_pro_scp03_mac.log")]
    [TestCase("gp_pro_scp03_renc.log")]
    [TestCase("gp_pro_scp03_rmac.log")]
    public async Task Should_Validate_Scp03_Trace(string traceFile)
    {
        _ = await AssertTraceFullyValidates(traceFile);
    }

    [TestCase("gp_pro_scp02_clr.log")]
    [TestCase("gp_pro_scp02_enc.log")]
    [TestCase("gp_pro_scp02_mac.log")]
    public async Task Should_Validate_Scp02_Trace(string traceFile)
    {
        _ = await AssertTraceFullyValidates(traceFile);
    }

    /// <summary>
    /// Every trace that opens a secure channel must exercise the full handshake and at least one
    /// protected command, so the oracle cannot pass by validating nothing.
    /// </summary>
    [TestCaseSource(nameof(SecureChannelTraces))]
    public async Task Should_Exercise_Handshake_And_Secure_Messaging(string traceFile)
    {
        var validationTypes = await AssertTraceFullyValidates(traceFile);

        _ = validationTypes
            .Should()
            .Contain("INITIALIZE_UPDATE", "the card cryptogram must be verified against the card")
            .And.Contain(
                "EXTERNAL_AUTHENTICATE",
                "the host cryptogram and its C-MAC must be verified"
            );

        _ = validationTypes
            .Count(type => type == "SECURE_MESSAGING")
            .Should()
            .BeGreaterThan(
                0,
                "at least one protected command must have its C-MAC checked against the card"
            );
    }

    /// <summary>
    /// Negative control: the oracle must reject a trace validated with the wrong static keys.
    /// Without this, weakening validation to warn-only would go unnoticed.
    /// </summary>
    [TestCaseSource(nameof(SecureChannelTraces))]
    public async Task Should_Reject_Trace_When_Static_Keys_Are_Wrong(string traceFile)
    {
        var converter = new TraceConverter();

        var result = await converter.ConvertAsync(
            Path.Combine(RawTraceDirectory, traceFile),
            "gp_pro",
            verbose: false,
            validate: true,
            keysetSpec: WrongKeyset
        );

        _ = result
            .IsFailure.Should()
            .BeTrue(
                "validating {0} with keys the card never used must fail, otherwise the trace "
                    + "oracle is not enforcing anything",
                traceFile
            );
    }

    /// <summary>
    /// Negative control: flipping a single bit of one recorded C-MAC must fail validation.
    /// This pins the oracle's sensitivity to the exact bytes rather than to the flow.
    /// </summary>
    [TestCaseSource(nameof(SecureChannelTraces))]
    public async Task Should_Reject_Trace_When_A_Command_Mac_Is_Tampered(string traceFile)
    {
        var tamperedPath = WriteTraceWithTamperedCommandMac(traceFile);

        try
        {
            var converter = new TraceConverter();

            var result = await converter.ConvertAsync(
                tamperedPath,
                "gp_pro",
                verbose: false,
                validate: true,
                keysetSpec: TestKeyset
            );

            _ = result
                .IsFailure.Should()
                .BeTrue(
                    "a corrupted C-MAC in {0} must fail validation, otherwise MAC verification "
                        + "is not load bearing",
                    traceFile
                );
        }
        finally
        {
            File.Delete(tamperedPath);
        }
    }

    /// <summary>
    /// Converts a trace with the real card keys and asserts that every exchange validated.
    /// </summary>
    /// <param name="traceFile">Raw trace file name.</param>
    /// <returns>The validation type recorded for each exchange, in order.</returns>
    private static async Task<List<string>> AssertTraceFullyValidates(string traceFile)
    {
        var converter = new TraceConverter();

        var result = await converter.ConvertAsync(
            Path.Combine(RawTraceDirectory, traceFile),
            "gp_pro",
            verbose: false,
            validate: true,
            keysetSpec: TestKeyset
        );

        _ = result
            .IsSuccess.Should()
            .BeTrue(
                "validation of {0} must succeed but reported: {1}",
                traceFile,
                result.IsFailure ? result.Error.ToString() : string.Empty
            );

        var exchanges = result.Value.Exchanges;

        _ = exchanges.Should().NotBeEmpty("{0} must parse into APDU exchanges", traceFile);

        var unvalidated = exchanges.Where(exchange => exchange.Validation is null).ToList();

        _ = unvalidated
            .Should()
            .BeEmpty(
                "every exchange in {0} must carry a validation result, but {1} did not",
                traceFile,
                string.Join(", ", unvalidated.Select(exchange => exchange.Index))
            );

        var invalid = exchanges.Where(exchange => !exchange.Validation.IsValid).ToList();

        _ = invalid
            .Should()
            .BeEmpty(
                "every cryptographic check in {0} must pass, but these failed: {1}",
                traceFile,
                string.Join(
                    "; ",
                    invalid.Select(exchange =>
                        $"exchange {exchange.Index} {exchange.Validation.Type}: "
                        + $"{exchange.Validation.Details} {exchange.Validation.Error}"
                    )
                )
            );

        return exchanges.Select(exchange => exchange.Validation.Type).ToList();
    }

    /// <summary>
    /// Copies a trace, flipping the low bit of the final byte of the last protected command.
    /// </summary>
    /// <param name="traceFile">Raw trace file name.</param>
    /// <returns>Path to the tampered copy.</returns>
    private static string WriteTraceWithTamperedCommandMac(string traceFile)
    {
        var lines = File.ReadAllLines(Path.Combine(RawTraceDirectory, traceFile));

        var index = Array.FindLastIndex(lines, IsSecuredCommandLine);

        _ = index
            .Should()
            .BeGreaterThan(-1, "{0} must contain a protected command to tamper with", traceFile);

        lines[index] = FlipFinalDataBit(lines[index]);

        var tamperedPath = Path.Combine(
            Path.GetTempPath(),
            $"gp4net_tampered_{Guid.NewGuid():N}_{traceFile}"
        );

        File.WriteAllLines(tamperedPath, lines);

        return tamperedPath;
    }

    /// <summary>
    /// Determines whether a trace line is an outbound command carrying GP secure messaging.
    /// </summary>
    /// <param name="line">Raw trace line.</param>
    /// <returns><see langword="true"/> when the line is a secured command.</returns>
    private static bool IsSecuredCommandLine(string line)
    {
        if (!line.StartsWith("A>> ", StringComparison.Ordinal))
        {
            return false;
        }

        var fields = SplitTraceFields(line);

        // Fields are: A>>, T=n, (lc+le), header, Lc, data, [Le]. GP 2.3.1 Table 11-11:
        // CLA bit 3 indicates GlobalPlatform secure messaging.
        return fields.Length >= 6
            && fields[3].Length == 8
            && byte.TryParse(
                fields[3][..2],
                System.Globalization.NumberStyles.HexNumber,
                null,
                out var cla
            )
            && (cla & 0x04) != 0;
    }

    /// <summary>
    /// Flips the low bit of the last data byte on a secured command line.
    /// </summary>
    /// <param name="line">Raw trace line for a secured command.</param>
    /// <returns>The line with one C-MAC bit inverted.</returns>
    private static string FlipFinalDataBit(string line)
    {
        var fields = SplitTraceFields(line);
        var data = fields[5];

        var lastByte = byte.Parse(data[^2..], System.Globalization.NumberStyles.HexNumber, null);

        fields[5] = data[..^2] + (lastByte ^ 0x01).ToString("X2");

        return string.Join(' ', fields);
    }

    private static string[] SplitTraceFields(string line) =>
        line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
}
