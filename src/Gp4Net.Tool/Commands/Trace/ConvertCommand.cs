using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Trace;
using Gp4Net.Tool.Commands.Common;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Trace;

/// <summary>
/// Converts GlobalPlatform trace transcripts into structured JSON with validation metadata.
/// </summary>
/// <remarks>
/// The command runs the full trace ingestion pipeline: it parses GPPro/GPShell transcripts,
/// optionally validates every APDU exchange with secure-channel session keys, and emits a
/// documentation-friendly JSON artifact that mirrors the coverage workflows documented in
/// <see href="https://github.com/OpenPhysical/Gp4Net/docs/coverage/coverage-playbook.md">
/// the coverage playbook</see>. Output always includes conversion diagnostics so callers can
/// reason about the derived security posture before replaying commands.
/// </remarks>
[PublicAPI]
public class ConvertCommand : AsyncCommand<ConvertCommand.Settings>
{
    /// <summary>
    /// Declarative settings bound to CLI arguments for <see cref="ConvertCommand"/>.
    /// </summary>
    /// <remarks>
    /// Spectre.Console automatically populates these properties from the command line. Each
    /// property maps to the contracts documented in <c>contracts/xml-documentation.md</c> and is
    /// validated before conversion starts so that invalid traces never reach the analyzer.
    /// </remarks>
    /// <example>
    /// gp4net trace convert traces/gppro.log traces/gppro.json --format gp_pro --keyset gp_test
    /// </example>
    public class Settings : CommandSettings
    {
        /// <summary>
        /// Gets or sets the path to the trace transcript that should be converted.
        /// </summary>
        /// <value>
        /// Either an absolute or relative path to a GPPro (<c>.log</c>) or GPShell (<c>.txt</c>)
        /// trace file. The command will fail fast with <c>SmartCardError.InvalidArgument</c> if
        /// the file does not exist.
        /// </value>
        [CommandArgument(0, "<INPUT>")]
        [Description("Input trace file path")]
        public string InputFile { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the location where the JSON export should be written.
        /// </summary>
        /// <value>
        /// A file path that may target a new or existing directory. Parent directories are created
        /// automatically when missing so the command can run in clean workspaces.
        /// </value>
        [CommandArgument(1, "<OUTPUT>")]
        [Description("Output JSON file path")]
        public string OutputFile { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the trace dialect the parser should expect.
        /// </summary>
        /// <value>
        /// Accepts <c>gp_pro</c> for GlobalPlatformPro exports or <c>gpshell</c> for GPShell /
        /// GlobalPlatform library traces. Any other value is rejected with a descriptive validation
        /// error so that automation scripts surface actionable feedback.
        /// </value>
        [CommandOption("-f|--format <FORMAT>")]
        [Description(
            "Trace format (gp_pro for GlobalPlatformPro, gpshell for GPShell/GlobalPlatform library)"
        )]
        public string Format { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether high-level card operations should be detected.
        /// </summary>
        /// <value>
        /// Defaults to <see langword="true"/>. When enabled, the converter groups exchanges into
        /// logical operations (install, load, manage channel, and so on) so the resulting JSON can
        /// drive documentation and regression analysis dashboards.
        /// </value>
        [CommandOption("--detect-operations")]
        [Description("Automatically detect operations in trace")]
        [DefaultValue(true)]
        public bool DetectOperations { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether verbose parser diagnostics should be emitted.
        /// </summary>
        /// <value>
        /// Defaults to <see langword="false"/>. When <see langword="true"/>, the converter prints
        /// per-exchange parsing details to the console, mirroring the troubleshooting workflow
        /// described in <c>quickstart.md</c>.
        /// </value>
        [CommandOption("--verbose")]
        [Description("Enable verbose output")]
        [DefaultValue(false)]
        public bool Verbose { get; set; }

        /// <summary>
        /// Gets or sets the keyset used to validate secure-channel MACs during conversion.
        /// </summary>
        /// <value>
        /// Accepts a named keyset such as <c>gp_test</c>, a raw hex tuple formatted as
        /// <c>ENC:MAC:DEK</c>, or a single 16-byte hex string. Defaults to the GlobalPlatform test
        /// keyset so that security checks remain enabled during quickstart scenarios.
        /// </value>
        [CommandOption("-k|--keyset <KEYSET>")]
        [Description("Keyset for validation (gp_test, hex key, or ENC:MAC:DEK)")]
        [DefaultValue("gp_test")]
        public string Keyset { get; set; } = "gp_test";
    }

    /// <summary>
    /// Executes the convert command by orchestrating trace parsing, validation, and export.
    /// </summary>
    /// <param name="context">Spectre command context describing the current invocation.</param>
    /// <param name="settings">Resolved command-line arguments and options.</param>
    /// <returns>
    /// <c>0</c> when conversion succeeds; otherwise <c>1</c> after printing the error surfaced by
    /// the functional pipeline so scripts can react to the failure.
    /// </returns>
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings)
    {
        try
        {
            var result = await ConvertTraceAsync(settings);
            return result.Match(
                onSuccess: () => 0,
                onFailure: error =>
                {
                    AnsiConsole.MarkupLine($"[red]Error: {error.Message}[/]");
                    return 1;
                }
            );
        }
        catch (Exception ex)
        {
            AnsiConsole.WriteException(ex);
            return 1;
        }
    }

    /// <summary>
    /// Performs the functional trace conversion workflow used by the CLI command and tests.
    /// </summary>
    /// <param name="settings">User-supplied conversion parameters.</param>
    /// <returns>
    /// A <see cref="UnitResult{TError}"/> that is successful when the JSON file is emitted, or
    /// contains a <see cref="SmartCardError"/> describing why the conversion aborted early.
    /// </returns>
    /// <remarks>
    /// The method enforces security validation by default and mirrors the quickstart instructions
    /// so downstream tooling (coverage verification scripts) can reuse the same pipeline.
    /// </remarks>
    private async Task<UnitResult<SmartCardError>> ConvertTraceAsync(Settings settings)
    {
        if (!File.Exists(settings.InputFile))
        {
            return UnitResult.Failure(
                SmartCardError.InvalidArgument($"Input file not found: {settings.InputFile}")
            );
        }

        if (string.IsNullOrEmpty(settings.Format))
        {
            return UnitResult.Failure(
                SmartCardError.InvalidArgument(
                    "Format must be specified. Use --format with either 'gp_pro' or 'gpshell'"
                )
            );
        }

        // Validation is always performed for security
        const bool shouldValidate = true;

        AnsiConsole.MarkupLine(
            $"[green]Converting {settings.Format} trace:[/] {settings.InputFile}"
        );

        AnsiConsole.MarkupLine(
            "[yellow]Cryptographic validation: [bold]MANDATORY[/] (always enabled for security)[/]"
        );

        var converter = new TraceConverter();

        var convertResult = await converter.ConvertAsync(
            settings.InputFile,
            settings.Format,
            settings.Verbose,
            shouldValidate,
            settings.Keyset
        );

        if (convertResult.IsFailure)
        {
            return UnitResult.Failure(convertResult.Error);
        }

        // Safe value access after success check
        if (convertResult.IsSuccess)
        {
            var traceData = convertResult.Value;

            // Ensure output directory exists
            string outputDir = Path.GetDirectoryName(settings.OutputFile);
            if (!string.IsNullOrEmpty(outputDir) && !Directory.Exists(outputDir))
            {
                _ = Directory.CreateDirectory(outputDir);
            }

            // Write JSON with pretty formatting
            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            };

            await File.WriteAllTextAsync(
                settings.OutputFile,
                JsonSerializer.Serialize(traceData, options)
            );

            // Display summary
            AnsiConsole.MarkupLine($"[green]✓ Generated JSON trace:[/] {settings.OutputFile}");
            DisplaySummary(traceData);
        }

        return UnitResult.Success<SmartCardError>();
    }

    /// <summary>
    /// Writes a human-readable summary of the generated trace to the console.
    /// </summary>
    /// <param name="traceData">The structured trace produced by <see cref="TraceConverter"/>.</param>
    /// <remarks>
    /// This mirrors the manual verification steps outlined in <c>quickstart.md</c> so that users
    /// receive immediate feedback about the detected sessions, operations, and usage examples when
    /// running the command interactively.
    /// </remarks>
    private static void DisplaySummary(TraceData traceData)
    {
        var table = new Table();
        _ = table.AddColumn("Property");
        _ = table.AddColumn("Value");

        _ = table.AddRow("Source File", traceData.Metadata.Source.File);
        _ = table.AddRow("Format", traceData.Metadata.Source.Type);
        _ = table.AddRow("Total Exchanges", traceData.Exchanges.Count.ToString());
        _ = table.AddRow("Operations", traceData.Operations.Count.ToString());
        _ = table.AddRow("Sessions", traceData.Metadata.Sessions.Count.ToString());
        _ = table.AddRow("Usage Examples", traceData.UsageExamples.Count.ToString());

        AnsiConsole.Write(table);

        if (traceData.Operations.Any())
        {
            AnsiConsole.MarkupLine("\n[bold]Detected Operations:[/]");
            foreach (var op in traceData.Operations)
            {
                AnsiConsole.MarkupLine(
                    $"  • [cyan]{op.Key}:[/] {op.Value.Description} (exchanges {op.Value.StartExchange}-{op.Value.EndExchange})"
                );
            }
        }

        if (traceData.UsageExamples.Any())
        {
            AnsiConsole.MarkupLine("\n[bold]Usage Examples:[/]");
            foreach (var example in traceData.UsageExamples)
            {
                AnsiConsole.MarkupLine($"  • [yellow]{example.Description}:[/]");
                AnsiConsole.MarkupLine($"    [dim]{example.Command}[/]");
            }
        }
    }
}

/// <summary>
/// Structured representation of a GlobalPlatform trace used for JSON export and validation.
/// </summary>
/// <remarks>
/// The structure mirrors the schema documented in <c>quickstart.md</c>. It decomposes traces into
/// metadata, high-level operations, usage examples, and the raw exchange list so coverage tooling
/// can reason about both human-readable summaries and low-level APDUs.
/// </remarks>
/// <example>
/// {
///   "metadata": { "source": { "file": "traces/gppro.log", "type": "gp_pro" } },
///   "operations": { "secure_channel_establish": { "description": "SCP authentication" } }
/// }
/// </example>
public class TraceData
{
    /// <summary>
    /// Gets or sets descriptive metadata extracted from the input trace.
    /// </summary>
    /// <value>
    /// Includes source file information, detected card characteristics, and secure-channel session
    /// summaries that help analysts correlate validation output with card capabilities.
    /// </value>
    public TraceMetadata Metadata { get; set; } = new();

    /// <summary>
    /// Gets or sets the operations derived from the trace.
    /// </summary>
    /// <value>
    /// Keys represent human-friendly operation identifiers (for example <c>load-applet</c>),
    /// while values capture the detected exchanges, command names, and derived metadata.
    /// </value>
    public Dictionary<string, Operation> Operations { get; set; } = new();

    /// <summary>
    /// Gets or sets usage examples that demonstrate how to replay the trace via CLI commands.
    /// </summary>
    /// <value>
    /// Each example pairs a descriptive caption with a CLI command, allowing quickstart
    /// documentation to surface curated reproduction steps.
    /// </value>
    public List<UsageExample> UsageExamples { get; set; } = [];

    /// <summary>
    /// Gets or sets the ordered list of APDU exchanges that were parsed from the transcript.
    /// </summary>
    /// <value>
    /// Each exchange retains command/response payloads, derived plaintext, validation metadata,
    /// and linkage to detected operations so downstream processors can reconstruct the timeline.
    /// </value>
    public List<Exchange> Exchanges { get; set; } = [];
}

/// <summary>
/// Metadata captured during conversion to contextualize the trace.
/// </summary>
/// <remarks>
/// Metadata aggregates provenance (input file, tool version), detected card identity, and secure
/// channel sessions. It enables coverage automation to reason about trace authenticity and
/// security posture without reprocessing the underlying exchanges.
/// </remarks>
public class TraceMetadata
{
    /// <summary>
    /// Gets or sets the source trace information.
    /// </summary>
    /// <value>
    /// Contains file path, format, generation timestamp, and converter version so analysts can
    /// trace how the JSON artifact was produced.
    /// </value>
    public SourceInfo Source { get; set; } = new();

    /// <summary>
    /// Gets or sets the detected card information derived from the trace.
    /// </summary>
    /// <value>
    /// Includes ATR, ISD AID, inferred card type, and optional CPLC details to document where the
    /// trace originated and whether it represents a production or development device.
    /// </value>
    public CardInfo Card { get; set; } = new();

    /// <summary>
    /// Gets or sets the collection of secure-channel sessions observed in the trace.
    /// </summary>
    /// <value>
    /// Each entry records derived session identifiers, negotiated security levels, and diversifier
    /// data so auditors can verify that validation logic covered every secure messaging exchange.
    /// </value>
    public List<SessionMetadata> Sessions { get; set; } = [];
}

/// <summary>
/// Describes the provenance of the processed trace file.
/// </summary>
/// <remarks>
/// Values are populated during conversion so exported JSON can be audited and reproduced. The
/// <see cref="Generated"/> value uses UTC timestamps to provide stable automated reporting.
/// </remarks>
public class SourceInfo
{
    /// <summary>
    /// Gets or sets the original trace file path supplied by the user.
    /// </summary>
    /// <value>
    /// Captures the path exactly as parsed, enabling downstream tooling to reprocess the same
    /// transcript if additional validation is required.
    /// </value>
    public string File { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the trace dialect that was parsed.
    /// </summary>
    /// <value>
    /// Common values are <c>gp_pro</c> or <c>gpshell</c>, mirroring the options exposed on the
    /// command line.
    /// </value>
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the UTC timestamp indicating when the JSON artifact was generated.
    /// </summary>
    /// <value>
    /// Populated with ISO-8601 format (<c>yyyy-MM-ddTHH:mm:ssZ</c>) to support lexicographic
    /// sorting in dashboards.
    /// </value>
    public string Generated { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

    /// <summary>
    /// Gets or sets the converter version that produced the output.
    /// </summary>
    /// <value>
    /// Defaults to <c>gp4net-1.0</c> but should be overridden when the CLI version changes so that
    /// analysts can correlate artifacts with specific builds.
    /// </value>
    public string ToolVersion { get; set; } = "gp4net-1.0";
}

/// <summary>
/// Summarizes card identity inferred from the trace.
/// </summary>
/// <remarks>
/// The information is derived from the first SELECT commands and CPLC data contained in the trace,
/// enabling compatibility checks to run without contacting the card again.
/// </remarks>
public class CardInfo
{
    /// <summary>
    /// Gets or sets the Answer-To-Reset (ATR) reported by the card.
    /// </summary>
    /// <value>Stored as a hex string without spaces to simplify comparisons.</value>
    public string Atr { get; set; } = "3BD518FF8191FE1FC38073C821100A";

    /// <summary>
    /// Gets or sets the ISD (Issuer Security Domain) AID discovered in the trace.
    /// </summary>
    /// <value>
    /// Used by compatibility analysis when replaying management operations against the card.
    /// </value>
    public string IsdAid { get; set; } = "A000000151000000";

    /// <summary>
    /// Gets or sets an inferred card classification (for example production or development).
    /// </summary>
    /// <value>
    /// Derived from ATR heuristics and defaults to <c>UNKNOWN</c> when the classification cannot
    /// be determined.
    /// </value>
    public string CardType { get; set; } = "UNKNOWN";

    /// <summary>
    /// Gets or sets raw CPLC data when it was captured in the trace.
    /// </summary>
    /// <value>
    /// A <see cref="Maybe{T}"/> containing <see cref="CplcData"/> so consumers can access optional
    /// life-cycle information without introducing <see langword="null"/>s.
    /// </value>
    public Maybe<CplcData> Cplc { get; set; } = Maybe<CplcData>.None;
}

/// <summary>
/// Card Production Life Cycle (CPLC) metadata extracted from the trace.
/// </summary>
/// <remarks>
/// Values follow GlobalPlatform 2.3.1 Appendix A encoding rules and are represented as uppercase
/// hex strings to preserve fidelity with the original trace.
/// </remarks>
public class CplcData
{
    /// <summary>
    /// Gets or sets the integrated circuit fabricator identifier.
    /// </summary>
    /// <value>Two-byte hex string identifying the silicon manufacturer.</value>
    public string IcFabricator { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the integrated circuit type identifier.
    /// </summary>
    /// <value>
    /// Two-byte hex string detailing the chip family so compatibility rules can be applied.
    /// </value>
    public string IcType { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the operating system identifier.
    /// </summary>
    /// <value>Two-byte hex string corresponding to the card OS release.</value>
    public string OsId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the integrated circuit serial number.
    /// </summary>
    /// <value>Four-byte hex string uniquely identifying the physical chip.</value>
    public string IcSerial { get; set; } = string.Empty;
}

/// <summary>
/// Captures secure channel session characteristics derived from the trace.
/// </summary>
/// <remarks>
/// Each session corresponds to a distinct INITIALIZE UPDATE / EXTERNAL AUTHENTICATE pair and
/// aggregates the information needed to replay or audit the secure channel negotiation.
/// </remarks>
public class SessionMetadata
{
    /// <summary>
    /// Gets or sets the unique identifier assigned to the session within the JSON output.
    /// </summary>
    /// <value>Stable identifier used to link operations and exchanges to this session.</value>
    public string SessionId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the detected secure channel protocol version.
    /// </summary>
    /// <value>
    /// Uses numeric constants defined by GlobalPlatform (for example <c>2</c> for SCP02,
    /// <c>3</c> for SCP03).
    /// </value>
    public int ScpVersion { get; set; } = 3;

    /// <summary>
    /// Gets or sets the implementation variant identifier.
    /// </summary>
    /// <value>
    /// Matches the <c>i=</c> codes documented in GP 2.3.1 (for example <c>i=70</c>) so engineers
    /// can identify diversification algorithms.
    /// </value>
    public string ScpImplementation { get; set; } = "i=70";

    /// <summary>
    /// Gets or sets the static key version number that initiated the session.
    /// </summary>
    public int KeyVersion { get; set; } = 1;

    /// <summary>
    /// Gets or sets the negotiated security level flags.
    /// </summary>
    /// <value>
    /// A pipe-delimited string (<c>C_MAC|R_MAC</c>, etc.) describing which cryptographic services
    /// are active for the session.
    /// </value>
    public string SecurityLevel { get; set; } = "C_MAC|R_MAC|C_ENC|R_ENC";

    /// <summary>
    /// Gets or sets the diversification method applied to derive session keys.
    /// </summary>
    public string KeyDiversification { get; set; } = "none";

    /// <summary>
    /// Gets or sets the 8-byte host challenge echoed in the trace.
    /// </summary>
    public string HostChallenge { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the 8-byte card challenge echoed in the trace.
    /// </summary>
    public string CardChallenge { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the sequence counter observed during secure messaging.
    /// </summary>
    public string SequenceCounter { get; set; } = "000001";

    /// <summary>
    /// Gets or sets the raw derivation inputs used to construct session keys.
    /// </summary>
    public DerivationData DerivationData { get; set; }

    /// <summary>
    /// Gets or sets the operations that occurred within the session.
    /// </summary>
    /// <value>Contains operation identifiers that reference <see cref="TraceData.Operations"/>.</value>
    public List<string> Operations { get; set; } = [];
}

/// <summary>
/// Records diversification inputs used when deriving session keys.
/// </summary>
/// <remarks>
/// Values mirror the intermediate artifacts produced by <c>TraceValidationState</c> so that
/// coverage scripts can assert security-critical fields were populated.
/// </remarks>
public class DerivationData
{
    /// <summary>
    /// Gets or sets the key diversification data (KDD) extracted from the trace.
    /// </summary>
    public string Kdd { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the host challenge used in session key derivation.
    /// </summary>
    public string HostChallenge { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the card challenge used in session key derivation.
    /// </summary>
    public string CardChallenge { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the card cryptogram validated during EXTERNAL AUTHENTICATE.
    /// </summary>
    public string CardCryptogram { get; set; } = string.Empty;
}

/// <summary>
/// Describes a high-level card operation detected in the trace.
/// </summary>
/// <remarks>
/// Operations group contiguous exchanges that implement a workflow, such as loading an applet or
/// opening a secure channel. They underpin the usage examples surfaced by the quickstart guide.
/// </remarks>
public class Operation
{
    /// <summary>
    /// Gets or sets the human-readable description of the operation.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the session identifier associated with the operation.
    /// </summary>
    public string SessionId { get; set; } = "session_1";

    /// <summary>
    /// Gets or sets the first exchange index that belongs to the operation.
    /// </summary>
    public int StartExchange { get; set; }

    /// <summary>
    /// Gets or sets the last exchange index that belongs to the operation.
    /// </summary>
    public int EndExchange { get; set; }

    /// <summary>
    /// Gets or sets the APDU commands that make up the operation.
    /// </summary>
    public List<string> Commands { get; set; } = [];

    /// <summary>
    /// Gets or sets the expected CLI command used to reproduce the operation.
    /// </summary>
    public string ExpectedCli { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the GlobalPlatform package AID referenced by the operation.
    /// </summary>
    public string PackageAid { get; set; }

    /// <summary>
    /// Gets or sets the application AID referenced by the operation.
    /// </summary>
    public string AppletAid { get; set; }

    /// <summary>
    /// Gets or sets the target AID when an operation acts on a deployed artifact.
    /// </summary>
    public string TargetAid { get; set; }
}

/// <summary>
/// Provides a ready-to-run replay command for the converted trace.
/// </summary>
/// <remarks>
/// Examples connect the coverage workflow to real CLI invocations so new contributors can verify
/// behavior quickly.
/// </remarks>
public class UsageExample
{
    /// <summary>
    /// Gets or sets the descriptive caption for the example.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the CLI command that replays the operation or full trace.
    /// </summary>
    public string Command { get; set; } = string.Empty;
}

/// <summary>
/// Represents a single APDU command/response pair in the trace timeline.
/// </summary>
/// <remarks>
/// Exchanges retain both raw and decrypted payloads so verification tooling can assert secure
/// messaging coverage while still presenting human-readable summaries.
/// </remarks>
public class Exchange
{
    /// <summary>
    /// Gets or sets the 1-based position of the exchange within the trace.
    /// </summary>
    public int Index { get; set; }

    /// <summary>
    /// Gets or sets the operation identifier this exchange belongs to.
    /// </summary>
    public string Operation { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the secure-channel session identifier this exchange belongs to.
    /// </summary>
    public string SessionId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the step number within the containing operation.
    /// </summary>
    public int StepInOperation { get; set; }

    /// <summary>
    /// Gets or sets the APDU command in hexadecimal representation.
    /// </summary>
    public string Command { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the decrypted APDU command when secure messaging is active.
    /// </summary>
    public string CommandPlaintext { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the APDU response in hexadecimal representation.
    /// </summary>
    public string Response { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the decrypted APDU response when secure messaging is active.
    /// </summary>
    public string ResponsePlaintext { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the card processing time in milliseconds.
    /// </summary>
    public int ResponseTimeMs { get; set; }

    /// <summary>
    /// Gets or sets a descriptive message tying the exchange to a higher-level action.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the original line number from the transcript.
    /// </summary>
    public int SourceLine { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether secure messaging bits were present.
    /// </summary>
    public bool SecureMessaging { get; set; }

    /// <summary>
    /// Gets or sets the evaluated security level for the exchange.
    /// </summary>
    public string SecurityLevel { get; set; } = "None"; // Track actual security level at this exchange

    /// <summary>
    /// Gets or sets secure-channel artifacts associated with this exchange.
    /// </summary>
    public Maybe<ScpData> ScpData { get; set; }

    /// <summary>
    /// Gets or sets the validation outcome derived from <see cref="TraceValidation"/>.
    /// </summary>
    public ValidationInfo Validation { get; set; }
}

/// <summary>
/// Captures secure-channel specific details extracted while validating exchanges.
/// </summary>
/// <remarks>
/// Values help auditors confirm that derived session keys and cryptograms align with expectations.
/// Optional fields use <see cref="Maybe{T}"/> to avoid introducing <see langword="null"/> into the
/// JSON serialization pipeline.
/// </remarks>
public class ScpData
{
    /// <summary>
    /// Gets or sets the host challenge observed for the exchange.
    /// </summary>
    public string HostChallenge { get; set; }

    /// <summary>
    /// Gets or sets the card challenge observed for the exchange.
    /// </summary>
    public string CardChallenge { get; set; }

    /// <summary>
    /// Gets or sets the card cryptogram validated for the exchange.
    /// </summary>
    public string CardCryptogram { get; set; }

    /// <summary>
    /// Gets or sets the optional key version detected alongside the secure-channel data.
    /// </summary>
    [JsonIgnore]
    public Maybe<int> KeyVersionMaybe { get; set; } = Maybe<int>.None;

    /// <summary>
    /// Gets the resolved key version if it was identified during validation.
    /// </summary>
    public int KeyVersion => KeyVersionMaybe.GetValueOrDefault(0);

    /// <summary>
    /// Gets or sets the secure-channel identifier assigned by validation logic.
    /// </summary>
    public string ScpId { get; set; }

    /// <summary>
    /// Gets or sets the host cryptogram computed for the exchange.
    /// </summary>
    public string HostCryptogram { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the secure-channel establishment result is known.
    /// </summary>
    [JsonIgnore]
    public Maybe<bool> SessionEstablishedMaybe { get; set; } = Maybe<bool>.None;

    /// <summary>
    /// Gets a value indicating whether the secure channel was successfully established.
    /// </summary>
    public bool SessionEstablished => SessionEstablishedMaybe.GetValueOrDefault(false);
}

/// <summary>
/// Reports validation results for an individual exchange.
/// </summary>
/// <remarks>
/// Populated when cryptographic verification succeeds or fails so coverage gates can assert both
/// positive and negative paths were exercised.
/// </remarks>
public class ValidationInfo
{
    /// <summary>
    /// Gets or sets the validation primitive that produced the result (for example <c>C-MAC</c>).
    /// </summary>
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether the validation succeeded.
    /// </summary>
    public bool IsValid { get; set; }

    /// <summary>
    /// Gets or sets additional contextual details describing the validation outcome.
    /// </summary>
    public string Details { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the error message when validation fails.
    /// </summary>
    public string Error { get; set; }
}

/// <summary>
/// Provides the functional pipeline that converts trace transcripts into structured data.
/// </summary>
/// <remarks>
/// The converter is reused by the CLI command and unit tests. It parses supported trace dialects,
/// detects operations, enriches metadata, and optionally validates secure messaging using the key
/// parsing rules described in <c>contracts/coverage-analysis.md</c>.
/// </remarks>
public class TraceConverter
{
    private readonly ApduAnalyzer _apduAnalyzer = new();
    private readonly OperationDetector _operationDetector = new();
    private readonly SessionAnalyzer _sessionAnalyzer = new();
    private readonly MetadataExtractor _metadataExtractor = new();
    private readonly UsageExampleGenerator _usageGenerator = new();

    /// <summary>
    /// Converts a trace transcript into <see cref="TraceData"/> while optionally validating it.
    /// </summary>
    /// <param name="inputFile">Path to the transcript that should be processed.</param>
    /// <param name="format">Trace dialect (<c>gp_pro</c> or <c>gpshell</c>).</param>
    /// <param name="verbose">
    /// When set to <see langword="true"/>, emits diagnostic output describing parsing progress.
    /// </param>
    /// <param name="validate">
    /// When set to <see langword="true"/>, runs cryptographic validation for every exchange using
    /// the supplied <paramref name="keysetSpec"/>.
    /// </param>
    /// <param name="keysetSpec">
    /// Named or raw keyset specification understood by <see cref="KeysetParser"/>.
    /// </param>
    /// <returns>
    /// A <see cref="Result{TValue,TError}"/> containing populated <see cref="TraceData"/> when the
    /// conversion succeeds or a <see cref="SmartCardError"/> describing the failure.
    /// </returns>
    public async Task<Result<TraceData, SmartCardError>> ConvertAsync(
        string inputFile,
        string format,
        bool verbose = false,
        bool validate = false,
        string keysetSpec = "gp_test"
    )
    {
        // Parse trace based on format
        var parseResult = format.ToLower() switch
        {
            "gp_pro"
                => Result.Success<List<Exchange>, SmartCardError>(
                    await ParseGpProTraceAsync(inputFile, verbose)
                ),
            "gpshell"
                => Result.Success<List<Exchange>, SmartCardError>(
                    await ParseGpShellTraceAsync(inputFile, verbose)
                ),
            _
                => Result.Failure<List<Exchange>, SmartCardError>(
                    SmartCardError.Unsupported($"Unsupported format: {format}")
                ),
        };

        if (parseResult.IsFailure)
        {
            return Result.Failure<TraceData, SmartCardError>(parseResult.Error);
        }

        var exchanges = parseResult.Value;

        // Check if any exchanges were found
        if (exchanges.Count == 0)
        {
            return Result.Failure<TraceData, SmartCardError>(
                SmartCardError.InvalidArgument(
                    $"No APDU exchanges found in trace file. Verify the format '{format}' matches the file content. Try 'gp_pro' for GlobalPlatformPro or 'gpshell' for GPShell/GlobalPlatform library traces."
                )
            );
        }

        // Validate if requested
        if (validate)
        {
            var validationResult = await ValidateTraceAsync(exchanges, keysetSpec, verbose);
            if (validationResult.IsFailure)
            {
                return Result.Failure<TraceData, SmartCardError>(validationResult.Error);
            }
        }

        if (verbose)
        {
            AnsiConsole.MarkupLine($"[dim]Found {exchanges.Count} APDU exchanges[/]");
        }

        // Detect operations
        var operations = _operationDetector.AnalyzeTrace(exchanges);
        if (verbose)
        {
            AnsiConsole.MarkupLine(
                $"[dim]Detected operations: {string.Join(", ", operations.Keys)}[/]"
            );
        }

        // Analyze sessions
        var sessions = _sessionAnalyzer.DetectSessions(exchanges);
        if (verbose)
        {
            AnsiConsole.MarkupLine($"[dim]Detected {sessions.Count} session(s)[/]");
        }

        // Link operations to sessions
        LinkOperationsToSessions(operations, sessions);

        // Extract metadata
        var metadata = _metadataExtractor.ExtractAll(exchanges, inputFile, format);
        metadata.Sessions = sessions;

        // Generate usage examples
        var usageExamples = UsageExampleGenerator.GenerateExamples(operations);

        return Result.Success<TraceData, SmartCardError>(
            new TraceData
            {
                Metadata = metadata,
                Operations = operations,
                UsageExamples = usageExamples,
                Exchanges = exchanges,
            }
        );
    }

    private async Task<List<Exchange>> ParseGpProTraceAsync(string filename, bool verbose)
    {
        var commandPattern = new Regex(@"^A>> T=\d+ \([\d+]+\) ([0-9A-F\s]+)$");
        var responsePattern = new Regex(@"^A<< \([\d+]+\) \((\d+)ms\) ([0-9A-F\s]+)$");

        string[] lines = await File.ReadAllLinesAsync(filename);

        var result = lines
            .Select((line, index) => new { Line = line.Trim(), LineNum = index + 1 })
            .Where(x =>
                !string.IsNullOrEmpty(x.Line)
                && !x.Line.StartsWith('#')
                && !x.Line.StartsWith('[')
                && !x.Line.StartsWith("WARNING:")
            )
            .Aggregate(
                new
                {
                    Builder = ImmutableArray.CreateBuilder<Exchange>(),
                    CurrentCommand = Maybe<string>.None,
                    CurrentLine = 0,
                    SecurityLevel = "None"
                },
                (state, item) =>
                {
                    // Try to match command
                    var cmdMatch = commandPattern.Match(item.Line);
                    if (cmdMatch.Success)
                    {
                        return new
                        {
                            state.Builder,
                            CurrentCommand = Maybe<string>.From(
                                cmdMatch.Groups[1].Value.Trim().Replace(" ", "").ToUpper()
                            ),
                            CurrentLine = item.LineNum,
                            state.SecurityLevel
                        };
                    }

                    // Try to match response
                    var respMatch = responsePattern.Match(item.Line);
                    return state.CurrentCommand.Match(
                        cmd =>
                        {
                            if (!respMatch.Success)
                                return state;

                            var responseTime = int.Parse(respMatch.Groups[1].Value);
                            var responseData = respMatch
                                .Groups[2]
                                .Value.Trim()
                                .Replace(" ", "")
                                .ToUpper();

                            var exchange = CreateExchange(
                                state.Builder.Count + 1,
                                cmd,
                                responseData,
                                responseTime,
                                state.CurrentLine,
                                state.SecurityLevel
                            );

                            // Update security level if this is EXTERNAL AUTHENTICATE
                            var newSecurityLevel = UpdateSecurityLevel(
                                exchange,
                                state.SecurityLevel
                            );

                            state.Builder.Add(exchange);

                            return new
                            {
                                state.Builder,
                                CurrentCommand = Maybe<string>.None,
                                CurrentLine = 0,
                                SecurityLevel = newSecurityLevel
                            };
                        },
                        () => state
                    );
                }
            );

        return result.Builder.ToImmutable().ToList();
    }

    private async Task<List<Exchange>> ParseGpShellTraceAsync(string filename, bool verbose)
    {
        var sendPattern = new Regex(@"Command --> ([0-9A-F\s]+)");
        var recvPattern = new Regex(@"Response <-- ([0-9A-F\s]+)");

        string[] lines = await File.ReadAllLinesAsync(filename);

        var result = lines
            .Select((line, index) => new { Line = line.Trim(), LineNum = index + 1 })
            .Aggregate(
                new
                {
                    Builder = ImmutableArray.CreateBuilder<Exchange>(),
                    CurrentCommand = Maybe<string>.None,
                    CurrentLine = 0,
                    SecurityLevel = "None"
                },
                (state, item) =>
                {
                    // Try to match command
                    var sendMatch = sendPattern.Match(item.Line);
                    if (sendMatch.Success)
                    {
                        return new
                        {
                            state.Builder,
                            CurrentCommand = Maybe<string>.From(
                                sendMatch.Groups[1].Value.Trim().Replace(" ", "").ToUpper()
                            ),
                            CurrentLine = item.LineNum,
                            state.SecurityLevel
                        };
                    }

                    // Try to match response
                    var recvMatch = recvPattern.Match(item.Line);
                    return state.CurrentCommand.Match(
                        cmd =>
                        {
                            if (!recvMatch.Success)
                                return state;

                            var responseData = recvMatch
                                .Groups[1]
                                .Value.Trim()
                                .Replace(" ", "")
                                .ToUpper();

                            var exchange = CreateExchange(
                                state.Builder.Count + 1,
                                cmd,
                                responseData,
                                20,
                                state.CurrentLine,
                                state.SecurityLevel
                            );

                            // Update security level if this is EXTERNAL AUTHENTICATE
                            var newSecurityLevel = UpdateSecurityLevel(
                                exchange,
                                state.SecurityLevel
                            );

                            state.Builder.Add(exchange);

                            return new
                            {
                                state.Builder,
                                CurrentCommand = Maybe<string>.None,
                                CurrentLine = 0,
                                SecurityLevel = newSecurityLevel
                            };
                        },
                        () => state
                    );
                }
            );

        return result.Builder.ToImmutable().ToList();
    }

    private Exchange CreateExchange(
        int index,
        string command,
        string response,
        int responseTime,
        int sourceLine,
        string securityLevel = "None"
    )
    {
        string description = ApduAnalyzer.GetCommandDescription(command);
        bool secureMessaging = ApduAnalyzer.IsSecureMessaging(command);
        var scpData = ApduAnalyzer.ExtractScpData(command, response, description);

        return new Exchange
        {
            Index = index,
            Operation = "", // Will be filled by operation detector
            SessionId = "", // Will be filled by session analyzer
            StepInOperation = 0, // Will be calculated
            Command = command,
            Response = response,
            ResponseTimeMs = responseTime,
            Description = description,
            SourceLine = sourceLine,
            SecureMessaging = secureMessaging,
            SecurityLevel = securityLevel,
            ScpData = scpData,
        };
    }

    private string UpdateSecurityLevel(Exchange exchange, string currentLevel)
    {
        // Check if this is EXTERNAL AUTHENTICATE
        if (exchange.Description.Contains("EXTERNAL AUTHENTICATE") && exchange.Command.Length >= 10)
        {
            // Extract P1 parameter (security level)
            var p1 = exchange.Command.Substring(4, 2);

            return p1 switch
            {
                "00" => "None",
                "01" => "C_MAC",
                "03" => "C_MAC|C_DECRYPTION",
                "10" => "R_MAC",
                "11" => "C_MAC|R_MAC",
                "13" => "C_MAC|C_DECRYPTION|R_MAC",
                "30" => "R_MAC|R_ENCRYPTION",
                "31" => "C_MAC|R_MAC|R_ENCRYPTION",
                "33" => "C_MAC|C_DECRYPTION|R_MAC|R_ENCRYPTION",
                _ => currentLevel // Keep current if unknown
            };
        }

        return currentLevel;
    }

    private async Task<UnitResult<SmartCardError>> ValidateTraceAsync(
        List<Exchange> exchanges,
        string keysetSpec,
        bool verbose
    )
    {
        // Parse the keyset
        var keysetResult = KeysetParser.ParseRawKeysetSpecification(keysetSpec);
        if (keysetResult.IsFailure)
        {
            return UnitResult.Failure(keysetResult.Error);
        }

        // Detect SCP version from trace exchanges
        var scpVersion = DetectScpVersionFromTrace(exchanges);

        // Convert RawKeyset to appropriate IKeySet based on detected SCP version
        var keysetConversionResult =
            scpVersion == CryptoService.ScpVersion.Scp03
                ? keysetResult.Value.ToScp03KeySet().Map(ks => (IKeySet)ks)
                : keysetResult.Value.ToScp02KeySet().Map(ks => (IKeySet)ks);

        if (keysetConversionResult.IsFailure)
        {
            return UnitResult.Failure(keysetConversionResult.Error);
        }

        // Diagnostics removed during refactoring

        // Create initial validation state
        var initialState = TraceValidationState.Create(
            keysetConversionResult.Value,
            keysetResult.Value.Diversification
        );

        // Validate all exchanges using functional composition
        var finalStateResult = exchanges.Aggregate(
            Result.Success<TraceValidationState, SmartCardError>(initialState),
            (stateResult, exchange) =>
                stateResult.Bind(state =>
                {
                    // Convert hex strings to byte arrays for the library
                    var commandBytes = Result.Try(
                        () => Convert.FromHexString(exchange.Command.Replace(" ", "")),
                        ex =>
                            SmartCardError.InvalidArgument(
                                $"Invalid command hex at exchange {exchange.Index}: {ex.Message}"
                            )
                    );

                    var responseBytes = Result.Try(
                        () => Convert.FromHexString(exchange.Response.Replace(" ", "")),
                        ex =>
                            SmartCardError.InvalidArgument(
                                $"Invalid response hex at exchange {exchange.Index}: {ex.Message}"
                            )
                    );

                    return commandBytes.Bind(cmd =>
                        responseBytes.Bind(resp =>
                        {
                            var validationResult = TraceValidation.ValidateExchange(
                                state,
                                cmd,
                                resp,
                                exchange.Index
                            );

                            return validationResult.Map(newState =>
                            {
                                // Extract the latest validation result for this exchange
                                var latestResult = newState
                                    .Results.Where(r => r.ExchangeIndex == exchange.Index)
                                    .LastOrDefault();

                                Maybe<Gp4Net.Domain.Trace.ValidationResult>
                                    .From(latestResult)
                                    .Match(
                                        Some: result =>
                                        {
                                            exchange.Validation = new ValidationInfo
                                            {
                                                Type = result.ValidationType,
                                                IsValid = result.IsValid,
                                                Details = result.Details,
                                                Error = result.Error.GetValueOrDefault()
                                            };

                                            if (verbose)
                                            {
                                                var status = result.IsValid
                                                    ? "[green]✓[/]"
                                                    : "[red]✗[/]";
                                                AnsiConsole.MarkupLine(
                                                    $"{status} Exchange {exchange.Index}: {result.ValidationType} - {result.Details}"
                                                );
                                            }
                                        },
                                        None: () => { }
                                    );

                                // Extract plaintext from secure messaging if session keys are available
                                newState.SessionKeys.Execute(sessionKeys =>
                                {
                                    // Check if command has secure messaging bit set (CLA bit 2)
                                    bool hasSecureMessaging =
                                        cmd.Length > 0 && (cmd[0] & 0x04) != 0;

                                    if (hasSecureMessaging && newState.SecurityLevel != 0)
                                    {
                                        var plaintextCmd = TraceConverter.ExtractPlaintextCommand(
                                            cmd,
                                            sessionKeys,
                                            newState.SecurityLevel,
                                            newState.ScpVersion,
                                            newState.CommandIcv
                                        );
                                        exchange.CommandPlaintext = plaintextCmd.Match(
                                            pt => Convert.ToHexString(pt),
                                            () => exchange.Command
                                        );

                                        var plaintextResp = TraceConverter.ExtractPlaintextResponse(
                                            resp,
                                            sessionKeys,
                                            newState.SecurityLevel,
                                            newState.ScpVersion,
                                            newState.ResponseIcv
                                        );
                                        exchange.ResponsePlaintext = plaintextResp.Match(
                                            pt => Convert.ToHexString(pt),
                                            () => exchange.Response
                                        );
                                    }
                                    else
                                    {
                                        // No secure messaging - plaintext equals encrypted
                                        exchange.CommandPlaintext = exchange.Command;
                                        exchange.ResponsePlaintext = exchange.Response;
                                    }
                                });

                                // If no session keys yet, plaintext equals encrypted
                                if (newState.SessionKeys.HasNoValue)
                                {
                                    exchange.CommandPlaintext = exchange.Command;
                                    exchange.ResponsePlaintext = exchange.Response;
                                }

                                return newState;
                            });
                        })
                    );
                })
        );

        // Check if validation succeeded
        var validationResult = finalStateResult.Match(
            state =>
            {
                if (state.Results.Any())
                {
                    var validCount = state.Results.Count(r => r.IsValid);
                    var totalCount = state.Results.Count;

                    if (verbose)
                    {
                        var color =
                            validCount == totalCount
                                ? "green"
                                : validCount > 0
                                    ? "yellow"
                                    : "red";
                        AnsiConsole.MarkupLine(
                            $"[{color}]Validation Summary: {validCount}/{totalCount} checks passed[/]"
                        );
                    }

                    // Fail if any validation check failed
                    if (validCount < totalCount)
                    {
                        var failedChecks = state.Results.Where(r => !r.IsValid).ToList();
                        var firstFailure = failedChecks.First();
                        var errorDetail = firstFailure.Error.Match(
                            value => $" ({value})",
                            () => string.Empty
                        );

                        return UnitResult.Failure<SmartCardError>(
                            SmartCardError.SecurityError(
                                $"Validation failed: {failedChecks.Count} of {totalCount} checks failed. First failure at exchange {firstFailure.ExchangeIndex}: {firstFailure.ValidationType} - {firstFailure.Details}{errorDetail}"
                            )
                        );
                    }
                }

                return UnitResult.Success<SmartCardError>();
            },
            error =>
            {
                if (verbose)
                {
                    AnsiConsole.MarkupLine($"[red]Validation error: {error}[/]");
                }
                return UnitResult.Failure(error);
            }
        );

        return await Task.FromResult(validationResult);
    }

    private static void LinkOperationsToSessions(
        Dictionary<string, Operation> operations,
        List<SessionMetadata> sessions
    )
    {
        // Simple implementation: assign operations to sessions based on session operations list
        foreach (var kvp in operations)
        {
            var operation = kvp.Value;
            string operationName = kvp.Key;

            foreach (var session in sessions)
            {
                if (session.Operations.Contains(operationName))
                {
                    operation.SessionId = session.SessionId;
                    break;
                }
            }
        }
    }

    private static CryptoService.ScpVersion DetectScpVersionFromTrace(List<Exchange> exchanges)
    {
        // Find INITIALIZE UPDATE response to determine SCP version
        var initUpdateList = exchanges
            .Where(e => e.Description.Contains("INITIALIZE UPDATE") && e.Response.Length >= 66)
            .ToList();

        if (!initUpdateList.Any())
            return CryptoService.ScpVersion.Scp02; // Default if no INITIALIZE UPDATE found

        var initUpdate = initUpdateList.First();
        var responseData = initUpdate.Response.Replace(" ", "");

        if (responseData.Length >= 28 && responseData.EndsWith("9000"))
        {
            // SCP identifier is at byte 11 (position 22-23 in hex string)
            var scpId = responseData.Substring(22, 2);
            return scpId == "03" ? CryptoService.ScpVersion.Scp03 : CryptoService.ScpVersion.Scp02;
        }

        return CryptoService.ScpVersion.Scp02;
    }

    /// <summary>
    /// Extracts plaintext command from secure messaging wrapper.
    /// Handles C-MAC and C-ENC unwrapping based on security level.
    /// </summary>
    private static Maybe<byte[]> ExtractPlaintextCommand(
        byte[] wrappedCommand,
        SessionKeys sessionKeys,
        byte securityLevel,
        CryptoService.ScpVersion scpVersion,
        Maybe<byte[]> commandIcv
    )
    {
        if (wrappedCommand.Length < 5)
            return Maybe<byte[]>.None;

        byte cla = wrappedCommand[0];
        if ((cla & 0x04) == 0)
            return Maybe<byte[]>.From(wrappedCommand);

        byte plaintextCla = (byte)(cla & ~0x04);
        byte ins = wrappedCommand[1];
        byte p1 = wrappedCommand[2];
        byte p2 = wrappedCommand[3];

        if (wrappedCommand.Length == 4)
            return Maybe<byte[]>.From(new byte[] { plaintextCla, ins, p1, p2 });

        byte lc = wrappedCommand[4];
        if (wrappedCommand.Length < 5 + lc)
            return Maybe<byte[]>.None;

        bool hasCMac = (securityLevel & 0x01) != 0;
        bool hasCEnc = (securityLevel & 0x02) != 0;

        int macLength = hasCMac ? 8 : 0;
        int dataLength = lc - macLength;

        if (dataLength < 0)
            return Maybe<byte[]>.None;

        var data = wrappedCommand.Skip(5).Take(dataLength).ToArray();

        var decryptedData =
            hasCEnc && data.Length > 0
                ? scpVersion switch
                {
                    CryptoService.ScpVersion.Scp02
                        => CryptoService
                            .Cipher.Decrypt3DesCbc(
                                sessionKeys.SEnc,
                                new byte[8], // Always zero IV for SCP02 command encryption per GP spec E.3.1
                                data
                            )
                            .Map(RemovePadding)
                            .Match(
                                success => Maybe<byte[]>.From(success),
                                failure => Maybe<byte[]>.None
                            ),
                    CryptoService.ScpVersion.Scp03
                        => CryptoService
                            .Cipher.DecryptAesCbc(sessionKeys.SEnc, new byte[16], data)
                            .Map(RemovePadding)
                            .Match(
                                success => Maybe<byte[]>.From(success),
                                failure => Maybe<byte[]>.None
                            ),
                    _ => Maybe<byte[]>.None
                }
                : Maybe<byte[]>.From(data);

        return decryptedData.Map(plainData =>
        {
            var builder = ImmutableList.CreateBuilder<byte>();
            builder.Add(plaintextCla);
            builder.Add(ins);
            builder.Add(p1);
            builder.Add(p2);

            if (plainData.Length > 0)
            {
                builder.Add((byte)plainData.Length);
                builder.AddRange(plainData);
            }

            bool hasLe = wrappedCommand.Length > (5 + lc);
            if (hasLe)
                builder.Add(wrappedCommand[5 + lc]);

            return builder.ToArray();
        });
    }

    /// <summary>
    /// Extracts plaintext response from secure messaging wrapper.
    /// </summary>
    private static Maybe<byte[]> ExtractPlaintextResponse(
        byte[] wrappedResponse,
        SessionKeys sessionKeys,
        byte securityLevel,
        CryptoService.ScpVersion scpVersion,
        Maybe<byte[]> responseIcv
    )
    {
        if (wrappedResponse.Length < 2)
            return Maybe<byte[]>.None;

        var sw = wrappedResponse.Skip(wrappedResponse.Length - 2).Take(2).ToArray();

        bool hasRMac = (securityLevel & 0x10) != 0;
        bool hasREnc = (securityLevel & 0x20) != 0;

        int macLength = hasRMac ? 8 : 0;
        int dataEndIndex = wrappedResponse.Length - 2 - macLength;

        if (dataEndIndex < 0)
            return Maybe<byte[]>.None;

        var data = wrappedResponse.Take(dataEndIndex).ToArray();

        var decryptedData =
            hasREnc && data.Length > 0
                ? scpVersion switch
                {
                    CryptoService.ScpVersion.Scp02
                        => CryptoService
                            .Cipher.Decrypt3DesCbc(
                                sessionKeys.SEnc,
                                new byte[8], // Always zero IV for SCP02 response encryption per GP spec E.3.1
                                data
                            )
                            .Map(RemovePadding)
                            .Match(
                                success => Maybe<byte[]>.From(success),
                                failure => Maybe<byte[]>.None
                            ),
                    CryptoService.ScpVersion.Scp03
                        => CryptoService
                            .Cipher.DecryptAesCbc(sessionKeys.SEnc, new byte[16], data)
                            .Map(RemovePadding)
                            .Match(
                                success => Maybe<byte[]>.From(success),
                                failure => Maybe<byte[]>.None
                            ),
                    _ => Maybe<byte[]>.None
                }
                : Maybe<byte[]>.From(data);

        return decryptedData.Map(plainData => plainData.Concat(sw).ToArray());
    }

    /// <summary>
    /// Removes ISO 9797-1 Method 2 padding from decrypted data.
    /// Padding format: data || 0x80 || 0x00*
    /// </summary>
    private static byte[] RemovePadding(byte[] paddedData)
    {
        if (paddedData.Length == 0)
            return paddedData;

        // Find index of last non-zero byte from the end
        var nonZeroIndices = Enumerable
            .Range(0, paddedData.Length)
            .Reverse()
            .SkipWhile(i => paddedData[i] == 0x00)
            .ToList();

        if (nonZeroIndices.Count == 0)
            return paddedData;

        var lastNonZeroIndex = nonZeroIndices.First();

        // Check if it's the 0x80 padding marker
        return paddedData[lastNonZeroIndex] == 0x80
            ? paddedData.Take(lastNonZeroIndex).ToArray()
            : paddedData;
    }
}

/// <summary>
/// Analyzes APDU commands to extract semantic information.
/// </summary>
public class ApduAnalyzer
{
    private static readonly Dictionary<string, string> CommandDescriptions =
        new()
        {
            { "A4", "SELECT" },
            { "CA", "GET DATA" },
            { "F2", "GET STATUS" },
            { "50", "INITIALIZE UPDATE" },
            { "82", "EXTERNAL AUTHENTICATE" },
            { "E6", "INSTALL" },
            { "E8", "LOAD" },
            { "E4", "DELETE" },
        };

    private static readonly Dictionary<string, string> GetDataTags =
        new()
        {
            { "9F7F", "CPLC" },
            { "0042", "IIN" },
            { "0045", "CIN" },
            { "00CF", "KDD" },
            { "00C1", "SSC" },
            { "0066", "CARD DATA" },
            { "0067", "CARD CAPABILITIES" },
            { "00E0", "KEY INFORMATION" },
        };

    /// <summary>
    /// Derives a descriptive label for an APDU command.
    /// </summary>
    /// <param name="commandHex">Command APDU represented as a hexadecimal string.</param>
    /// <returns>
    /// Human-readable command description (for example <c>INSTALL [for load]</c>) or an
    /// <c>UNKNOWN</c> placeholder when the instruction cannot be mapped.
    /// </returns>
    public static string GetCommandDescription(string commandHex)
    {
        if (commandHex.Length < 4)
        {
            return "UNKNOWN";
        }

        string ins = commandHex.Substring(2, 2);

        if (CommandDescriptions.TryGetValue(ins, out string baseDesc))
        {
            switch (ins)
            {
                // Special handling for GET DATA
                case "CA" when commandHex.Length >= 8:
                {
                    string tag = commandHex.Substring(4, 4);
                    if (GetDataTags.TryGetValue(tag, out string tagDesc))
                    {
                        return $"GET {tagDesc}";
                    }

                    return $"GET DATA (tag {tag})";
                }

                // Special handling for INSTALL
                case "E6" when commandHex.Length >= 6:
                {
                    string p1 = commandHex.Substring(4, 2);
                    return p1 switch
                    {
                        "02" => "INSTALL [for load]",
                        "04" => "INSTALL [for install and make selectable]",
                        "0C" => "INSTALL [for install]",
                        _ => $"INSTALL (P1={p1})",
                    };
                }
                default:
                    return baseDesc;
            }
        }

        return $"UNKNOWN (INS={ins})";
    }

    /// <summary>
    /// Determines whether an APDU command uses secure messaging.
    /// </summary>
    /// <param name="commandHex">Command APDU represented as a hexadecimal string.</param>
    /// <returns>
    /// <see langword="true"/> when the CLA secure messaging bit is set; otherwise
    /// <see langword="false"/>.
    /// </returns>
    public static bool IsSecureMessaging(string commandHex)
    {
        if (commandHex.Length < 2)
        {
            return false;
        }

        byte cla = Convert.ToByte(commandHex.Substring(0, 2), 16);
        return (cla & 0x04) != 0;
    }

    /// <summary>
    /// Extracts secure-channel artifacts from an APDU pair.
    /// </summary>
    /// <param name="commandHex">Command APDU in hexadecimal form.</param>
    /// <param name="responseHex">Response APDU in hexadecimal form.</param>
    /// <param name="description">Previously derived description for the command.</param>
    /// <returns>
    /// A <see cref="Maybe{T}"/> containing <see cref="ScpData"/> when secure-channel markers are
    /// present; otherwise <see cref="Maybe{T}.None"/>.
    /// </returns>
    public static Maybe<ScpData> ExtractScpData(
        string commandHex,
        string responseHex,
        string description
    )
    {
        var scpData = new ScpData();
        bool hasData = false;

        if (description.Contains("INITIALIZE UPDATE"))
        {
            // Extract host challenge from command
            if (commandHex.Length >= 20)
            {
                scpData.HostChallenge = commandHex.Substring(10, 16);
                hasData = true;
            }

            // Extract data from response
            if (responseHex.Length >= 66 && responseHex.EndsWith("9000"))
            {
                string responseData = responseHex.Substring(0, responseHex.Length - 4);
                if (responseData.Length >= 64)
                {
                    scpData.KeyVersionMaybe = Maybe<int>.From(
                        Convert.ToInt32(responseData.Substring(20, 2), 16)
                    );
                    scpData.ScpId = responseData.Substring(22, 2);
                    scpData.CardChallenge = responseData.Substring(30, 16);
                    scpData.CardCryptogram = responseData.Substring(46, 16);
                    hasData = true;
                }
            }
        }
        else if (description.Contains("EXTERNAL AUTHENTICATE"))
        {
            // Extract host cryptogram from command
            if (commandHex.Length >= 44)
            {
                scpData.HostCryptogram = commandHex.Substring(12, 32);
                scpData.SessionEstablishedMaybe = Maybe<bool>.From(responseHex == "9000");
                hasData = true;
            }
        }

        return hasData ? Maybe<ScpData>.From(scpData) : Maybe<ScpData>.None;
    }
}

/// <summary>
/// Detects and categorizes high-level operations within a trace.
/// </summary>
/// <remarks>
/// Pattern detection powers the usage examples documented in the coverage playbook by grouping
/// related exchanges into semantic operations such as secure-channel establishment or applet
/// deployment.
/// </remarks>
public class OperationDetector
{
    private static readonly Dictionary<string, OperationPattern> OperationPatterns =
        new()
        {
            {
                "select_isd",
                new OperationPattern
                {
                    Indicators = ["SELECT"],
                    RequiredSequence = false,
                    CliTemplate = "gp4net card info",
                }
            },
            {
                "get_data",
                new OperationPattern
                {
                    Indicators =
                    [
                        "GET DATA",
                        "GET CPLC",
                        "GET CARD DATA",
                        "GET CARD CAPABILITIES",
                        "GET IIN",
                        "GET CIN",
                        "GET KDD",
                        "GET SSC",
                        "GET KEY INFORMATION",
                    ],
                    RequiredSequence = false,
                    CliTemplate = "gp4net card info",
                }
            },
            {
                "list",
                new OperationPattern
                {
                    Indicators = ["GET STATUS"],
                    RequiredSequence = false,
                    CliTemplate = "gp4net applet list",
                }
            },
            {
                "secure_channel_establish",
                new OperationPattern
                {
                    Indicators = ["INITIALIZE UPDATE", "EXTERNAL AUTHENTICATE"],
                    RequiredSequence = true,
                    CliTemplate = "gp4net card test-sc -k gp_test_keys",
                }
            },
            {
                "install_applet",
                new OperationPattern
                {
                    Indicators = ["INSTALL [for load]"],
                    RequiredSequence = false,
                    CliTemplate = "gp4net applet install {package}.cap",
                }
            },
            {
                "load_blocks",
                new OperationPattern
                {
                    Indicators = ["LOAD"],
                    RequiredSequence = false,
                    CliTemplate = "gp4net applet load",
                }
            },
            {
                "uninstall",
                new OperationPattern
                {
                    Indicators = ["DELETE"],
                    RequiredSequence = false,
                    CliTemplate = "gp4net applet delete {aid}",
                }
            },
        };

    private readonly Dictionary<string, int> _operationCounter = new();
    private readonly List<DetectedOperation> _detectedOperations = [];

    /// <summary>
    /// Analyzes a list of exchanges and produces labeled operations with CLI guidance.
    /// </summary>
    /// <param name="exchanges">Ordered exchanges parsed from the trace transcript.</param>
    /// <returns>
    /// Dictionary keyed by operation identifier with enriched <see cref="Operation"/> payloads.
    /// </returns>
    public Dictionary<string, Operation> AnalyzeTrace(List<Exchange> exchanges)
    {
        // First pass: detect all operations
        DetectAllOperations(exchanges);

        // Second pass: merge and refine operations
        var mergedOperations = MergeOperations();

        // Third pass: assign exchanges to operations
        AssignExchangesToOperations(exchanges, mergedOperations);

        return mergedOperations;
    }

    private void DetectAllOperations(List<Exchange> exchanges)
    {
        _detectedOperations.Clear();

        for (int i = 0; i < exchanges.Count; i++)
        {
            var exchange = exchanges[i];
            string detectedOp = DetectOperationType(exchange);

            if (detectedOp != "unknown")
            {
                // For LOAD operations, group consecutive ones immediately
                if (detectedOp == "load_blocks" && _detectedOperations.Count > 0)
                {
                    var lastOp = _detectedOperations[^1];
                    if (lastOp.Type == "load_blocks" && lastOp.EndIndex == i - 1)
                    {
                        // Extend the existing LOAD operation
                        lastOp.EndIndex = i;
                        if (!lastOp.Commands.Contains(exchange.Description))
                        {
                            lastOp.Commands.Add(exchange.Description);
                        }

                        continue;
                    }
                }

                _detectedOperations.Add(
                    new DetectedOperation
                    {
                        Type = detectedOp,
                        StartIndex = i,
                        EndIndex = i,
                        Commands = [exchange.Description],
                    }
                );
            }
        }
    }

    private Dictionary<string, Operation> MergeOperations()
    {
        // Handle operations that require specific sequences
        MergeSequentialOperations(
            "secure_channel_establish",
            ["INITIALIZE UPDATE", "EXTERNAL AUTHENTICATE"]
        );

        // Create operations from detected operations using functional composition
        return _detectedOperations.Aggregate(
            new Dictionary<string, Operation>(),
            (operations, detectedOp) =>
            {
                // Check if this operation overlaps with any existing operation
                var hasOverlap = operations.Values.Any(op =>
                    op.StartExchange - 1 <= detectedOp.EndIndex
                    && op.EndExchange - 1 >= detectedOp.StartIndex
                );

                if (hasOverlap)
                {
                    return operations; // Skip if already part of another operation
                }

                // Create operation
                string opName = GetUniqueOperationName(detectedOp.Type);
                var operation = new Operation
                {
                    Description = GetOperationDescription(detectedOp.Type),
                    SessionId = "session_1",
                    StartExchange = detectedOp.StartIndex + 1,
                    EndExchange = detectedOp.EndIndex + 1,
                    Commands = [.. detectedOp.Commands.Distinct()],
                    ExpectedCli =
                        OperationPatterns.GetValueOrDefault(detectedOp.Type)?.CliTemplate
                        ?? "gp4net unknown",
                };

                operations[opName] = operation;
                return operations;
            }
        );
    }

    private void MergeSequentialOperations(string operationType, string[] requiredCommands)
    {
        int i = 0;
        while (i < _detectedOperations.Count)
        {
            int sequenceStart = -1;
            int sequenceEnd = -1;
            List<string> foundCommands = [];

            // Look for the start of the sequence
            for (int j = i; j < _detectedOperations.Count && j < i + 10; j++) // Look ahead up to 10 exchanges
            {
                var op = _detectedOperations[j];
                if (requiredCommands.Any(cmd => op.Commands.Any(c => c.Contains(cmd))))
                {
                    if (sequenceStart == -1)
                    {
                        sequenceStart = j;
                    }

                    sequenceEnd = j;
                    foundCommands.AddRange(op.Commands);

                    // Check if we have all required commands
                    if (requiredCommands.All(cmd => foundCommands.Any(c => c.Contains(cmd))))
                    {
                        // Merge into a single operation
                        var mergedOp = new DetectedOperation
                        {
                            Type = operationType,
                            StartIndex = _detectedOperations[sequenceStart].StartIndex,
                            EndIndex = _detectedOperations[sequenceEnd].EndIndex,
                            Commands = [.. foundCommands.Distinct()],
                        };

                        // Replace the original operations
                        for (int k = sequenceEnd; k >= sequenceStart; k--)
                        {
                            _detectedOperations.RemoveAt(k);
                        }
                        _detectedOperations.Insert(sequenceStart, mergedOp);

                        i = sequenceStart + 1;
                        break;
                    }
                }
            }

            // Always increment to avoid infinite loop
            i++;
        }
    }

    private void AssignExchangesToOperations(
        List<Exchange> exchanges,
        Dictionary<string, Operation> operations
    )
    {
        foreach (var exchange in exchanges)
        {
            exchange.Operation = "";
            exchange.StepInOperation = 0;
        }

        foreach (var kvp in operations)
        {
            string opName = kvp.Key;
            var operation = kvp.Value;

            int stepCounter = 1;
            for (
                int i = operation.StartExchange - 1;
                i < operation.EndExchange && i < exchanges.Count;
                i++
            )
            {
                exchanges[i].Operation = opName;
                exchanges[i].StepInOperation = stepCounter++;
            }
        }
    }

    private static string DetectOperationType(Exchange exchange)
    {
        string description = exchange.Description;

        foreach (var kvp in OperationPatterns)
        {
            var pattern = kvp.Value;
            if (pattern.Indicators.Any(indicator => description.Contains(indicator)))
            {
                return kvp.Key;
            }
        }

        return "unknown";
    }

    private class DetectedOperation
    {
        public string Type { get; set; } = "";
        public int StartIndex { get; set; }
        public int EndIndex { get; set; }
        public List<string> Commands { get; set; } = [];
    }

    private string GetUniqueOperationName(string operationType)
    {
        if (!_operationCounter.ContainsKey(operationType))
        {
            _operationCounter[operationType] = 1;
            return operationType;
        }
        _operationCounter[operationType]++;
        return $"{operationType}{_operationCounter[operationType]}";
    }

    private static string GetOperationDescription(string operationType)
    {
        return operationType switch
        {
            "select_isd" => "SELECT ISD",
            "get_data" => "GET secure channel protocol details",
            "info" => "Card information gathering",
            "list" => "List applications on card",
            "secure_channel_establish" => "SCP authentication",
            "install_applet" => "Install application package",
            "load_blocks" => "Load CAP file blocks",
            "uninstall" => "Remove application",
            _ => "Unknown operation",
        };
    }

    private class OperationPattern
    {
        public string[] Indicators { get; set; } = [];
        public bool RequiredSequence { get; set; }
        public string CliTemplate { get; set; } = string.Empty;
    }
}

/// <summary>
/// Analyzes traces to detect and characterize secure channel sessions.
/// </summary>
public class SessionAnalyzer
{
    private int _sessionCounter = 1;

    /// <summary>
    /// Detects secure channel sessions from APDU exchanges using functional composition.
    /// </summary>
    /// <param name="exchanges">List of APDU exchanges to analyze.</param>
    /// <returns>List of detected session metadata.</returns>
    public List<SessionMetadata> DetectSessions(List<Exchange> exchanges)
    {
        var result = exchanges.Aggregate(
            new
            {
                CompletedSessions = ImmutableList<SessionMetadata>.Empty,
                CurrentSession = Maybe<SessionMetadata>.None,
            },
            (state, exchange) =>
            {
                // Detect new session start
                if (exchange.Description.Contains("INITIALIZE UPDATE"))
                {
                    // Add previous session to completed sessions if exists
                    var updatedCompletedSessions = state.CurrentSession.Match(
                        Some: session =>
                            state.CompletedSessions.Concat(new[] { session }).ToImmutableList(),
                        None: () => state.CompletedSessions
                    );

                    // Create new session
                    var newSession = CreateSessionFromInitUpdate(exchange);
                    return new
                    {
                        CompletedSessions = updatedCompletedSessions,
                        CurrentSession = Maybe<SessionMetadata>.From(newSession),
                    };
                }

                // Update current session with additional data
                return new
                {
                    state.CompletedSessions,
                    CurrentSession = state.CurrentSession.Map(session =>
                    {
                        UpdateSessionData(session, exchange);
                        return session;
                    }),
                };
            }
        );

        // Add final session if exists and return all sessions
        var finalSessionsList = result.CurrentSession.Match(
            Some: session => result.CompletedSessions.Concat(new[] { session }).ToImmutableList(),
            None: () => result.CompletedSessions
        );

        return finalSessionsList.ToList();
    }

    private static (int scpVersion, string scpImplementation) ParseScpInfoFromResponse(
        string response
    )
    {
        // Default values
        int scpVersion = 2;
        string scpImplementation = "i=00";

        var maybeResponse = Maybe<string>.From(response);

        return maybeResponse
            .Where(r => r.Length >= 28)
            .Map(r => r.EndsWith("9000") ? r.Substring(0, r.Length - 4) : r)
            .Where(r => r.Length >= 26)
            .Map(responseData =>
            {
                // Parse SCP identifier from byte 11 (chars 22-23)
                var scpIdResult = Result.Try(() =>
                {
                    string scpIdHex = responseData.Substring(22, 2);
                    return int.Parse(scpIdHex, System.Globalization.NumberStyles.HexNumber);
                });

                // Parse i-parameter from byte 12 (chars 24-25)
                var iParamResult = Result.Try(() =>
                {
                    string iParamHex = responseData.Substring(24, 2);
                    return int.Parse(iParamHex, System.Globalization.NumberStyles.HexNumber);
                });

                int version = scpIdResult.GetValueOrDefault(2);
                string impl = iParamResult.Match(value => $"i={value:X2}", _ => "i=00");

                return (version, impl);
            })
            .GetValueOrDefault((scpVersion, scpImplementation));
    }

    private SessionMetadata CreateSessionFromInitUpdate(Exchange exchange)
    {
        string sessionId = $"session_{_sessionCounter}";
        _sessionCounter++;

        var scpData = exchange.ScpData;

        // Parse SCP version and i-parameter from INITIALIZE UPDATE response
        var (scpVersion, scpImplementation) = ParseScpInfoFromResponse(exchange.Response);

        var derivationData = scpData.Match(
            Some: sd => new DerivationData
            {
                Kdd = "0370000000000000000001", // Default, should be extracted
                HostChallenge = sd.HostChallenge,
                CardChallenge = sd.CardChallenge,
                CardCryptogram = sd.CardCryptogram,
            },
            None: () =>
                new DerivationData
                {
                    Kdd = "",
                    HostChallenge = "",
                    CardChallenge = "",
                    CardCryptogram = "",
                }
        );

        return new SessionMetadata
        {
            SessionId = sessionId,
            ScpVersion = scpVersion,
            ScpImplementation = scpImplementation,
            KeyVersion = scpData.Match(
                Some: sd => sd.KeyVersionMaybe.Match(Some: v => v, None: () => 1),
                None: () => 1
            ),
            SecurityLevel = "C_MAC|R_MAC|C_ENC|R_ENC",
            KeyDiversification = "none",
            HostChallenge = scpData.Match(Some: sd => sd.HostChallenge, None: () => ""),
            CardChallenge = scpData.Match(Some: sd => sd.CardChallenge, None: () => ""),
            SequenceCounter = "000001",
            DerivationData = derivationData,
            Operations = [],
        };
    }

    private static void UpdateSessionData(SessionMetadata session, Exchange exchange)
    {
        // Update session ID in exchange
        exchange.SessionId = session.SessionId;

        // Add operation to session if not already present
        if (
            !string.IsNullOrEmpty(exchange.Operation)
            && !session.Operations.Contains(exchange.Operation)
        )
        {
            session.Operations.Add(exchange.Operation);
        }
    }
}

/// <summary>
/// Extracts metadata from parsed exchanges.
/// </summary>
public class MetadataExtractor
{
    /// <summary>
    /// Builds <see cref="TraceMetadata"/> from the parsed exchanges and conversion context.
    /// </summary>
    /// <param name="exchanges">Exchanges parsed from the trace transcript.</param>
    /// <param name="sourceFile">Original source file path.</param>
    /// <param name="formatType">Trace format (for example <c>gp_pro</c>).</param>
    /// <returns>
    /// Metadata object populated with provenance details and detected card information.
    /// </returns>
    public TraceMetadata ExtractAll(List<Exchange> exchanges, string sourceFile, string formatType)
    {
        return new TraceMetadata
        {
            Source = new SourceInfo
            {
                File = sourceFile,
                Type = formatType,
                Generated = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ToolVersion = "gp4net-1.0",
            },
            Card = ExtractCardInfo(exchanges),
            Sessions = [], // Will be populated by session analyzer
        };
    }

    private CardInfo ExtractCardInfo(List<Exchange> exchanges)
    {
        string atr = "3BD518FF8191FE1FC38073C821100A"; // Default ATR
        string isdAid = FindIsdAid(exchanges);
        var cplcData = FindCplcData(exchanges);

        return new CardInfo
        {
            Atr = atr,
            IsdAid = isdAid,
            CardType = DetectCardType(cplcData),
            Cplc = cplcData,
        };
    }

    private static string FindIsdAid(List<Exchange> exchanges)
    {
        foreach (var exchange in exchanges)
        {
            if (exchange.Description.Contains("SELECT") && exchange.Response.StartsWith("6F"))
            {
                // Simple extraction - look for known ISD AID
                if (exchange.Response.Contains("A000000151000000"))
                {
                    return "A000000151000000";
                }
            }
        }
        return "A000000151000000"; // Default ISD AID
    }

    /// <summary>
    /// Finds and parses CPLC data from GET CPLC command exchanges.
    /// </summary>
    /// <param name="exchanges">List of APDU exchanges to search.</param>
    /// <returns>Maybe containing CPLC data if found and valid.</returns>
    private static Maybe<CplcData> FindCplcData(List<Exchange> exchanges)
    {
        var validCplcExchanges = exchanges
            .Where(e =>
                e.Description.Contains("GET CPLC")
                && e.Response.Length > 20
                && e.Response.StartsWith("9F7F")
                && e.Response.EndsWith("9000")
            )
            .ToList();

        return validCplcExchanges.Any()
            ? ParseCplcFromResponse(validCplcExchanges.First().Response)
            : Maybe<CplcData>.None;
    }

    /// <summary>
    /// Parses CPLC data from a valid GET CPLC response.
    /// </summary>
    /// <param name="response">Response hex string containing CPLC data.</param>
    /// <returns>Maybe containing parsed CPLC data if valid length.</returns>
    private static Maybe<CplcData> ParseCplcFromResponse(string response)
    {
        // Parse CPLC data: Remove tag+length (6 chars) and SW (4 chars)
        string cplcHex = response.Substring(6, response.Length - 10);

        return cplcHex.Length >= 42
            ? Maybe<CplcData>.From(
                new CplcData
                {
                    IcFabricator = cplcHex.Substring(0, 4),
                    IcType = cplcHex.Substring(4, 4),
                    OsId = cplcHex.Substring(8, 4),
                    IcSerial = cplcHex.Substring(24, 8),
                }
            )
            : Maybe<CplcData>.None;
    }

    /// <summary>
    /// Detects card type from CPLC data IC fabricator code.
    /// </summary>
    /// <param name="cplcData">Maybe containing CPLC data.</param>
    /// <returns>Card type string based on IC fabricator.</returns>
    private static string DetectCardType(Maybe<CplcData> cplcData)
    {
        return cplcData.Match(
            Some: data => data.IcFabricator == "4790" ? "NXP_P71" : "UNKNOWN",
            None: () => "UNKNOWN"
        );
    }
}

/// <summary>
/// Generates usage examples for trace replay.
/// </summary>
public class UsageExampleGenerator
{
    public static List<UsageExample> GenerateExamples(Dictionary<string, Operation> operations)
    {
        // Single operation examples
        var singleOpExamples = operations.Select(kvp => new UsageExample
        {
            Description = $"{kvp.Value.Description} only",
            Command = $"{kvp.Value.ExpectedCli} -r 'virtual:trace.json?operations={kvp.Key}'",
        });

        // Workflow examples
        var opNames = operations.Keys.ToList();

        // Install workflow
        var installOps = opNames
            .Where(op => op.Contains("install") || op.Contains("secure_channel") || op == "info")
            .ToList();

        var installWorkflow =
            installOps.Count > 1
                ? new[]
                {
                    new UsageExample
                    {
                        Description = "Install workflow",
                        Command =
                            $"gp4net applet install app.cap -r 'virtual:trace.json?operations={string.Join(",", installOps)}'",
                    }
                }
                : Array.Empty<UsageExample>();

        // Full workflow
        var fullWorkflow =
            opNames.Count > 2
                ? new[]
                {
                    new UsageExample
                    {
                        Description = "Complete workflow",
                        Command =
                            $"gp4net script eval 'full_workflow()' -r 'virtual:trace.json?operations={string.Join(",", opNames)}'",
                    }
                }
                : Array.Empty<UsageExample>();

        return singleOpExamples.Concat(installWorkflow).Concat(fullWorkflow).ToList();
    }
}
