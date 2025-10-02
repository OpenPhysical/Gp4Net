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
/// Command to convert trace files to structured JSON format with rich metadata.
/// </summary>
[PublicAPI]
public class ConvertCommand : AsyncCommand<ConvertCommand.Settings>
{
    /// <summary>
    /// Settings for the convert command.
    /// </summary>
    public class Settings : CommandSettings
    {
        [CommandArgument(0, "<INPUT>")]
        [Description("Input trace file path")]
        public string InputFile { get; set; } = string.Empty;

        [CommandArgument(1, "<OUTPUT>")]
        [Description("Output JSON file path")]
        public string OutputFile { get; set; } = string.Empty;

        [CommandOption("-f|--format <FORMAT>")]
        [Description(
            "Trace format (gp_pro for GlobalPlatformPro, gpshell for GPShell/GlobalPlatform library)"
        )]
        public string Format { get; set; } = string.Empty;

        [CommandOption("--detect-operations")]
        [Description("Automatically detect operations in trace")]
        [DefaultValue(true)]
        public bool DetectOperations { get; set; } = true;

        [CommandOption("--verbose")]
        [Description("Enable verbose output")]
        [DefaultValue(false)]
        public bool Verbose { get; set; }

        [CommandOption("-k|--keyset <KEYSET>")]
        [Description("Keyset for validation (gp_test, hex key, or ENC:MAC:DEK)")]
        [DefaultValue("gp_test")]
        public string Keyset { get; set; } = "gp_test";
    }

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
/// Main trace data structure for JSON output.
/// </summary>
public class TraceData
{
    public TraceMetadata Metadata { get; set; } = new();
    public Dictionary<string, Operation> Operations { get; set; } = new();
    public List<UsageExample> UsageExamples { get; set; } = [];
    public List<Exchange> Exchanges { get; set; } = [];
}

/// <summary>
/// Metadata about the trace file and card.
/// </summary>
public class TraceMetadata
{
    public SourceInfo Source { get; set; } = new();
    public CardInfo Card { get; set; } = new();
    public List<SessionMetadata> Sessions { get; set; } = [];
}

/// <summary>
/// Information about the source trace file.
/// </summary>
public class SourceInfo
{
    public string File { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string Generated { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
    public string ToolVersion { get; set; } = "gp4net-1.0";
}

/// <summary>
/// Information about the card.
/// </summary>
public class CardInfo
{
    public string Atr { get; set; } = "3BD518FF8191FE1FC38073C821100A";
    public string IsdAid { get; set; } = "A000000151000000";
    public string CardType { get; set; } = "UNKNOWN";
    public Maybe<CplcData> Cplc { get; set; } = Maybe<CplcData>.None;
}

/// <summary>
/// CPLC (Card Production Life Cycle) data.
/// </summary>
public class CplcData
{
    public string IcFabricator { get; set; } = string.Empty;
    public string IcType { get; set; } = string.Empty;
    public string OsId { get; set; } = string.Empty;
    public string IcSerial { get; set; } = string.Empty;
}

/// <summary>
/// Session metadata for secure channel sessions.
/// </summary>
public class SessionMetadata
{
    public string SessionId { get; set; } = string.Empty;
    public int ScpVersion { get; set; } = 3;
    public string ScpImplementation { get; set; } = "i=70";
    public int KeyVersion { get; set; } = 1;
    public string SecurityLevel { get; set; } = "C_MAC|R_MAC|C_ENC|R_ENC";
    public string KeyDiversification { get; set; } = "none";
    public string HostChallenge { get; set; } = string.Empty;
    public string CardChallenge { get; set; } = string.Empty;
    public string SequenceCounter { get; set; } = "000001";
    public DerivationData DerivationData { get; set; }
    public List<string> Operations { get; set; } = [];
}

/// <summary>
/// Key derivation data for secure channel.
/// </summary>
public class DerivationData
{
    public string Kdd { get; set; } = string.Empty;
    public string HostChallenge { get; set; } = string.Empty;
    public string CardChallenge { get; set; } = string.Empty;
    public string CardCryptogram { get; set; } = string.Empty;
}

/// <summary>
/// Operation within a trace.
/// </summary>
public class Operation
{
    public string Description { get; set; } = string.Empty;
    public string SessionId { get; set; } = "session_1";
    public int StartExchange { get; set; }
    public int EndExchange { get; set; }
    public List<string> Commands { get; set; } = [];
    public string ExpectedCli { get; set; } = string.Empty;
    public string PackageAid { get; set; }
    public string AppletAid { get; set; }
    public string TargetAid { get; set; }
}

/// <summary>
/// Usage example for trace replay.
/// </summary>
public class UsageExample
{
    public string Description { get; set; } = string.Empty;
    public string Command { get; set; } = string.Empty;
}

/// <summary>
/// Individual APDU exchange.
/// </summary>
public class Exchange
{
    public int Index { get; set; }
    public string Operation { get; set; } = string.Empty;
    public string SessionId { get; set; } = string.Empty;
    public int StepInOperation { get; set; }
    public string Command { get; set; } = string.Empty;
    public string CommandPlaintext { get; set; } = string.Empty;
    public string Response { get; set; } = string.Empty;
    public string ResponsePlaintext { get; set; } = string.Empty;
    public int ResponseTimeMs { get; set; }
    public string Description { get; set; } = string.Empty;
    public int SourceLine { get; set; }
    public bool SecureMessaging { get; set; }
    public string SecurityLevel { get; set; } = "None"; // Track actual security level at this exchange
    public Maybe<ScpData> ScpData { get; set; }
    public ValidationInfo Validation { get; set; }
}

/// <summary>
/// SCP-specific data extracted from exchanges.
/// </summary>
public class ScpData
{
    public string HostChallenge { get; set; }
    public string CardChallenge { get; set; }
    public string CardCryptogram { get; set; }

    [JsonIgnore]
    public Maybe<int> KeyVersionMaybe { get; set; } = Maybe<int>.None;

    public int KeyVersion => KeyVersionMaybe.GetValueOrDefault(0);

    public string ScpId { get; set; }
    public string HostCryptogram { get; set; }

    [JsonIgnore]
    public Maybe<bool> SessionEstablishedMaybe { get; set; } = Maybe<bool>.None;

    public bool SessionEstablished => SessionEstablishedMaybe.GetValueOrDefault(false);
}

/// <summary>
/// Validation information for an exchange.
/// </summary>
public class ValidationInfo
{
    public string Type { get; set; } = string.Empty;
    public bool IsValid { get; set; }
    public string Details { get; set; } = string.Empty;
    public string Error { get; set; }
}

/// <summary>
/// Main trace converter class.
/// </summary>
public class TraceConverter
{
    private readonly ApduAnalyzer _apduAnalyzer = new();
    private readonly OperationDetector _operationDetector = new();
    private readonly SessionAnalyzer _sessionAnalyzer = new();
    private readonly MetadataExtractor _metadataExtractor = new();
    private readonly UsageExampleGenerator _usageGenerator = new();

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
                                    bool hasSecureMessaging = cmd.Length > 0 && (cmd[0] & 0x04) != 0;

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

        var decryptedData = hasCEnc && data.Length > 0
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

        var decryptedData = hasREnc && data.Length > 0
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

    public static bool IsSecureMessaging(string commandHex)
    {
        if (commandHex.Length < 2)
        {
            return false;
        }

        byte cla = Convert.ToByte(commandHex.Substring(0, 2), 16);
        return (cla & 0x04) != 0;
    }

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
/// Detects and categorizes operations within traces.
/// </summary>
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
        return _detectedOperations
            .Aggregate(
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
                        Some: session => state.CompletedSessions.Concat(new[] { session }).ToImmutableList(),
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
