using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
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
        [Description("Trace format (gp_pro, gpshell)")]
        [DefaultValue("gp_pro")]
        public string Format { get; set; } = "gp_pro";

        [CommandOption("--detect-operations")]
        [Description("Automatically detect operations in trace")]
        [DefaultValue(true)]
        public bool DetectOperations { get; set; } = true;

        [CommandOption("--verbose")]
        [Description("Enable verbose output")]
        [DefaultValue(false)]
        public bool Verbose { get; set; }
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings)
    {
        try
        {
            await ConvertTraceAsync(settings);
            return 0;
        }
        catch (Exception ex)
        {
            AnsiConsole.WriteException(ex);
            return 1;
        }
    }

    private async Task ConvertTraceAsync(Settings settings)
    {
        if (!File.Exists(settings.InputFile))
        {
            throw new FileNotFoundException($"Input file not found: {settings.InputFile}");
        }

        AnsiConsole.MarkupLine($"[green]Converting {settings.Format} trace:[/] {settings.InputFile}");

        var converter = new TraceConverter();
        var traceData = await converter.ConvertAsync(settings.InputFile, settings.Format, settings.Verbose);

        // Ensure output directory exists
        var outputDir = Path.GetDirectoryName(settings.OutputFile);
        if (!string.IsNullOrEmpty(outputDir) && !Directory.Exists(outputDir))
        {
            _ = Directory.CreateDirectory(outputDir);
        }

        // Write JSON with pretty formatting
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        await File.WriteAllTextAsync(settings.OutputFile, JsonSerializer.Serialize(traceData, options));

        // Display summary
        AnsiConsole.MarkupLine($"[green]✓ Generated JSON trace:[/] {settings.OutputFile}");
        DisplaySummary(traceData);
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
                AnsiConsole.MarkupLine($"  • [cyan]{op.Key}:[/] {op.Value.Description} (exchanges {op.Value.StartExchange}-{op.Value.EndExchange})");
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
    public CplcData Cplc { get; set; }
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
    public string Response { get; set; } = string.Empty;
    public int ResponseTimeMs { get; set; }
    public string Description { get; set; } = string.Empty;
    public int SourceLine { get; set; }
    public bool SecureMessaging { get; set; }
    public ScpData ScpData { get; set; }
}

/// <summary>
/// SCP-specific data extracted from exchanges.
/// </summary>
public class ScpData
{
    public string HostChallenge { get; set; }
    public string CardChallenge { get; set; }
    public string CardCryptogram { get; set; }
    public int? KeyVersion { get; set; }
    public string ScpId { get; set; }
    public string HostCryptogram { get; set; }
    public bool? SessionEstablished { get; set; }
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

    public async Task<TraceData> ConvertAsync(string inputFile, string format, bool verbose = false)
    {
        // Parse trace based on format
        var exchanges = format.ToLower() switch
        {
            "gp_pro" => await ParseGpProTraceAsync(inputFile, verbose),
            "gpshell" => await ParseGpShellTraceAsync(inputFile, verbose),
            _ => throw new ArgumentException($"Unsupported format: {format}")
        };

        if (verbose)
        {
            AnsiConsole.MarkupLine($"[dim]Found {exchanges.Count} APDU exchanges[/]");
        }

        // Detect operations
        var operations = _operationDetector.AnalyzeTrace(exchanges);
        if (verbose)
        {
            AnsiConsole.MarkupLine($"[dim]Detected operations: {string.Join(", ", operations.Keys)}[/]");
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

        return new TraceData
        {
            Metadata = metadata,
            Operations = operations,
            UsageExamples = usageExamples,
            Exchanges = exchanges
        };
    }

    private async Task<List<Exchange>> ParseGpProTraceAsync(string filename, bool verbose)
    {
        var exchanges = new List<Exchange>();
        var commandPattern = new Regex(@"^A>> T=\d+ \([\d+]+\) ([0-9A-F\s]+)$");
        var responsePattern = new Regex(@"^A<< \([\d+]+\) \((\d+)ms\) ([0-9A-F\s]+)$");

        string currentCommand = null;
        var currentLine = 0;

        var lines = await File.ReadAllLinesAsync(filename);
        for (var lineNum = 0; lineNum < lines.Length; lineNum++)
        {
            var line = lines[lineNum].Trim();

            // Skip empty lines and comments
            if (string.IsNullOrEmpty(line) || line.StartsWith('#') || line.StartsWith('[') || line.StartsWith("WARNING:"))
            {
                continue;
            }

            // Try to match command
            var cmdMatch = commandPattern.Match(line);
            if (cmdMatch.Success)
            {
                currentCommand = cmdMatch.Groups[1].Value.Trim().Replace(" ", "").ToUpper();
                currentLine = lineNum + 1;
                continue;
            }

            // Try to match response
            var respMatch = responsePattern.Match(line);
            if (respMatch.Success && currentCommand != null)
            {
                var responseTime = int.Parse(respMatch.Groups[1].Value);
                var responseData = respMatch.Groups[2].Value.Trim().Replace(" ", "").ToUpper();

                var exchange = CreateExchange(exchanges.Count + 1, currentCommand, responseData, responseTime, currentLine);
                exchanges.Add(exchange);

                currentCommand = null;
                currentLine = 0;
            }
        }

        return exchanges;
    }

    private async Task<List<Exchange>> ParseGpShellTraceAsync(string filename, bool verbose)
    {
        var exchanges = new List<Exchange>();
        var sendPattern = new Regex(@"Command --> ([0-9A-F\s]+)");
        var recvPattern = new Regex(@"Response <-- ([0-9A-F\s]+)");

        string currentCommand = null;
        var currentLine = 0;

        var lines = await File.ReadAllLinesAsync(filename);
        for (var lineNum = 0; lineNum < lines.Length; lineNum++)
        {
            var line = lines[lineNum].Trim();

            // Try to match command
            var sendMatch = sendPattern.Match(line);
            if (sendMatch.Success)
            {
                currentCommand = sendMatch.Groups[1].Value.Trim().Replace(" ", "").ToUpper();
                currentLine = lineNum + 1;
                continue;
            }

            // Try to match response
            var recvMatch = recvPattern.Match(line);
            if (recvMatch.Success && currentCommand != null)
            {
                var responseData = recvMatch.Groups[1].Value.Trim().Replace(" ", "").ToUpper();

                var exchange = CreateExchange(exchanges.Count + 1, currentCommand, responseData, 20, currentLine);
                exchanges.Add(exchange);

                currentCommand = null;
                currentLine = 0;
            }
        }

        return exchanges;
    }

    private Exchange CreateExchange(int index, string command, string response, int responseTime, int sourceLine)
    {
        var description = ApduAnalyzer.GetCommandDescription(command);
        var secureMessaging = ApduAnalyzer.IsSecureMessaging(command);
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
            ScpData = scpData
        };
    }

    private static void LinkOperationsToSessions(Dictionary<string, Operation> operations, List<SessionMetadata> sessions)
    {
        // Simple implementation: assign operations to sessions based on session operations list
        foreach (var kvp in operations)
        {
            var operation = kvp.Value;
            var operationName = kvp.Key;

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
}

/// <summary>
/// Analyzes APDU commands to extract semantic information.
/// </summary>
public class ApduAnalyzer
{
    private static readonly Dictionary<string, string> CommandDescriptions = new()
    {
        { "A4", "SELECT" },
        { "CA", "GET DATA" },
        { "F2", "GET STATUS" },
        { "50", "INITIALIZE UPDATE" },
        { "82", "EXTERNAL AUTHENTICATE" },
        { "E6", "INSTALL" },
        { "E8", "LOAD" },
        { "E4", "DELETE" }
    };

    private static readonly Dictionary<string, string> GetDataTags = new()
    {
        { "9F7F", "CPLC" },
        { "0042", "IIN" },
        { "0045", "CIN" },
        { "00CF", "KDD" },
        { "00C1", "SSC" },
        { "0066", "CARD DATA" },
        { "0067", "CARD CAPABILITIES" },
        { "00E0", "KEY INFORMATION" }
    };

    public static string GetCommandDescription(string commandHex)
    {
        if (commandHex.Length < 4)
        {
            return "UNKNOWN";
        }

        var ins = commandHex.Substring(2, 2);

        if (CommandDescriptions.TryGetValue(ins, out var baseDesc))
        {
            switch (ins)
            {
                // Special handling for GET DATA
                case "CA" when commandHex.Length >= 8:
                {
                    var tag = commandHex.Substring(4, 4);
                    if (GetDataTags.TryGetValue(tag, out var tagDesc))
                    {
                        return $"GET {tagDesc}";
                    }

                    return $"GET DATA (tag {tag})";
                }

                // Special handling for INSTALL
                case "E6" when commandHex.Length >= 6:
                {
                    var p1 = commandHex.Substring(4, 2);
                    return p1 switch
                    {
                        "02" => "INSTALL [for load]",
                        "04" => "INSTALL [for install and make selectable]",
                        "0C" => "INSTALL [for install]",
                        _ => $"INSTALL (P1={p1})"
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

        var cla = Convert.ToByte(commandHex.Substring(0, 2), 16);
        return (cla & 0x04) != 0;
    }

    public static ScpData ExtractScpData(string commandHex, string responseHex, string description)
    {
        var scpData = new ScpData();
        var hasData = false;

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
                var responseData = responseHex.Substring(0, responseHex.Length - 4);
                if (responseData.Length >= 64)
                {
                    scpData.KeyVersion = Convert.ToInt32(responseData.Substring(20, 2), 16);
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
                scpData.SessionEstablished = responseHex == "9000";
                hasData = true;
            }
        }

        return hasData ? scpData : null;
    }
}

/// <summary>
/// Detects and categorizes operations within traces.
/// </summary>
public class OperationDetector
{
    private static readonly Dictionary<string, OperationPattern> OperationPatterns = new()
    {
        {
            "select_isd", new OperationPattern
            {
                Indicators = ["SELECT"],
                RequiredSequence = false,
                CliTemplate = "gp4net card info"
            }
        },
        {
            "get_data", new OperationPattern
            {
                Indicators = ["GET DATA", "GET CPLC", "GET CARD DATA", "GET CARD CAPABILITIES", "GET IIN", "GET CIN", "GET KDD", "GET SSC", "GET KEY INFORMATION"],
                RequiredSequence = false,
                CliTemplate = "gp4net card info"
            }
        },
        {
            "list", new OperationPattern
            {
                Indicators = ["GET STATUS"],
                RequiredSequence = false,
                CliTemplate = "gp4net applet list"
            }
        },
        {
            "secure_channel_establish", new OperationPattern
            {
                Indicators = ["INITIALIZE UPDATE", "EXTERNAL AUTHENTICATE"],
                RequiredSequence = true,
                CliTemplate = "gp4net card test-sc -k gp_test_keys"
            }
        },
        {
            "install_applet", new OperationPattern
            {
                Indicators = ["INSTALL [for load]"],
                RequiredSequence = false,
                CliTemplate = "gp4net applet install {package}.cap"
            }
        },
        {
            "load_blocks", new OperationPattern
            {
                Indicators = ["LOAD"],
                RequiredSequence = false,
                CliTemplate = "gp4net applet load"
            }
        },
        {
            "uninstall", new OperationPattern
            {
                Indicators = ["DELETE"],
                RequiredSequence = false,
                CliTemplate = "gp4net applet delete {aid}"
            }
        }
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
        
        for (var i = 0; i < exchanges.Count; i++)
        {
            var exchange = exchanges[i];
            var detectedOp = DetectOperationType(exchange);
            
            if (detectedOp != "unknown")
            {
                // For LOAD operations, group consecutive ones immediately
                if (detectedOp == "load_blocks" && _detectedOperations.Count > 0)
                {
                    var lastOp = _detectedOperations[_detectedOperations.Count - 1];
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
                
                _detectedOperations.Add(new DetectedOperation
                {
                    Type = detectedOp,
                    StartIndex = i,
                    EndIndex = i,
                    Commands = [exchange.Description]
                });
            }
        }
    }
    
    private Dictionary<string, Operation> MergeOperations()
    {
        var operations = new Dictionary<string, Operation>();
        
        // Handle operations that require specific sequences
        MergeSequentialOperations("secure_channel_establish", ["INITIALIZE UPDATE", "EXTERNAL AUTHENTICATE"]);
        
        // Create operations from detected operations
        for (var i = 0; i < _detectedOperations.Count; i++)
        {
            var detectedOp = _detectedOperations[i];
            
            // Check if this operation is part of an existing operation (by checking overlap)
            var existingOp = operations.Values.FirstOrDefault(op => 
                op.StartExchange - 1 <= detectedOp.EndIndex && 
                op.EndExchange - 1 >= detectedOp.StartIndex);
                
            if (existingOp != null)
            {
                continue; // Skip if already part of another operation
            }

            // Create operation
            var opName = GetUniqueOperationName(detectedOp.Type);
            operations[opName] = new Operation
            {
                Description = GetOperationDescription(detectedOp.Type),
                SessionId = "session_1",
                StartExchange = detectedOp.StartIndex + 1,
                EndExchange = detectedOp.EndIndex + 1,
                Commands = detectedOp.Commands.Distinct().ToList(),
                ExpectedCli = OperationPatterns.GetValueOrDefault(detectedOp.Type)?.CliTemplate ?? "gp4net unknown"
            };
        }
        
        return operations;
    }
    
    private void MergeSequentialOperations(string operationType, string[] requiredCommands)
    {
        var i = 0;
        while (i < _detectedOperations.Count)
        {
            var sequenceStart = -1;
            var sequenceEnd = -1;
            var foundCommands = new List<string>();
            
            // Look for the start of the sequence
            for (var j = i; j < _detectedOperations.Count && j < i + 10; j++) // Look ahead up to 10 exchanges
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
                            Commands = foundCommands.Distinct().ToList()
                        };
                        
                        // Replace the original operations
                        for (var k = sequenceEnd; k >= sequenceStart; k--)
                        {
                            _detectedOperations.RemoveAt(k);
                        }
                        _detectedOperations.Insert(sequenceStart, mergedOp);
                        
                        i = sequenceStart + 1;
                        break;
                    }
                }
            }
            
            if (sequenceStart == -1)
            {
                i++;
            }
        }
    }
    
    private void AssignExchangesToOperations(List<Exchange> exchanges, Dictionary<string, Operation> operations)
    {
        foreach (var exchange in exchanges)
        {
            exchange.Operation = "";
            exchange.StepInOperation = 0;
        }
        
        foreach (var kvp in operations)
        {
            var opName = kvp.Key;
            var operation = kvp.Value;
            
            var stepCounter = 1;
            for (var i = operation.StartExchange - 1; i < operation.EndExchange && i < exchanges.Count; i++)
            {
                exchanges[i].Operation = opName;
                exchanges[i].StepInOperation = stepCounter++;
            }
        }
    }

    private static string DetectOperationType(Exchange exchange)
    {
        var description = exchange.Description;

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
        else
        {
            _operationCounter[operationType]++;
            return $"{operationType}{_operationCounter[operationType]}";
        }
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
            _ => "Unknown operation"
        };
    }

    private class OperationPattern
    {
        public string[] Indicators { get; set; } = [];
        public bool RequiredSequence { get; set; } = false;
        public string CliTemplate { get; set; } = string.Empty;
    }
}

/// <summary>
/// Analyzes traces to detect and characterize secure channel sessions.
/// </summary>
public class SessionAnalyzer
{
    private int _sessionCounter = 1;

    public List<SessionMetadata> DetectSessions(List<Exchange> exchanges)
    {
        var sessions = new List<SessionMetadata>();
        SessionMetadata currentSession = null;

        foreach (var exchange in exchanges)
        {
            // Detect new session start
            if (exchange.Description.Contains("INITIALIZE UPDATE"))
            {
                if (currentSession != null)
                {
                    sessions.Add(currentSession);
                }

                currentSession = CreateSessionFromInitUpdate(exchange);
            }

            // Update session with additional data
            if (currentSession != null)
            {
                UpdateSessionData(currentSession, exchange);
            }
        }

        // Add final session
        if (currentSession != null)
        {
            sessions.Add(currentSession);
        }

        return sessions;
    }

    private SessionMetadata CreateSessionFromInitUpdate(Exchange exchange)
    {
        var sessionId = $"session_{_sessionCounter}";
        _sessionCounter++;

        var scpData = exchange.ScpData;
        DerivationData derivationData = null;

        if (scpData != null)
        {
            derivationData = new DerivationData
            {
                Kdd = "0370000000000000000001", // Default, should be extracted
                HostChallenge = scpData.HostChallenge ?? "",
                CardChallenge = scpData.CardChallenge ?? "",
                CardCryptogram = scpData.CardCryptogram ?? ""
            };
        }

        return new SessionMetadata
        {
            SessionId = sessionId,
            ScpVersion = 3,
            ScpImplementation = "i=70",
            KeyVersion = scpData?.KeyVersion ?? 1,
            SecurityLevel = "C_MAC|R_MAC|C_ENC|R_ENC",
            KeyDiversification = "none",
            HostChallenge = scpData?.HostChallenge ?? "",
            CardChallenge = scpData?.CardChallenge ?? "",
            SequenceCounter = "000001",
            DerivationData = derivationData,
            Operations = []
        };
    }

    private static void UpdateSessionData(SessionMetadata session, Exchange exchange)
    {
        // Update session ID in exchange
        exchange.SessionId = session.SessionId;

        // Add operation to session if not already present
        if (!string.IsNullOrEmpty(exchange.Operation) && !session.Operations.Contains(exchange.Operation))
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
                ToolVersion = "gp4net-1.0"
            },
            Card = ExtractCardInfo(exchanges),
            Sessions = [] // Will be populated by session analyzer
        };
    }

    private CardInfo ExtractCardInfo(List<Exchange> exchanges)
    {
        var atr = "3BD518FF8191FE1FC38073C821100A"; // Default ATR
        var isdAid = FindIsdAid(exchanges);
        var cplcData = FindCplcData(exchanges);

        return new CardInfo
        {
            Atr = atr,
            IsdAid = isdAid,
            CardType = DetectCardType(cplcData),
            Cplc = cplcData
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

    private static CplcData FindCplcData(List<Exchange> exchanges)
    {
        foreach (var exchange in exchanges)
        {
            if (exchange.Description.Contains("GET CPLC") && exchange.Response.Length > 20)
            {
                var responseData = exchange.Response;
                if (responseData.StartsWith("9F7F") && responseData.EndsWith("9000"))
                {
                    // Parse CPLC data
                    var cplcHex = responseData.Substring(6, responseData.Length - 10); // Remove tag+length and SW
                    if (cplcHex.Length >= 42) // Minimum CPLC length
                    {
                        return new CplcData
                        {
                            IcFabricator = cplcHex.Substring(0, 4),
                            IcType = cplcHex.Substring(4, 4),
                            OsId = cplcHex.Substring(8, 4),
                            IcSerial = cplcHex.Substring(24, 8)
                        };
                    }
                }
            }
        }
        return null;
    }

    private static string DetectCardType(CplcData cplcData)
    {
        if (cplcData?.IcFabricator == "4790")
        {
            return "NXP_P71";
        }
        return "UNKNOWN";
    }
}

/// <summary>
/// Generates usage examples for trace replay.
/// </summary>
public class UsageExampleGenerator
{
    public static List<UsageExample> GenerateExamples(Dictionary<string, Operation> operations)
    {
        var examples = new List<UsageExample>();

        // Single operation examples
        foreach (var kvp in operations)
        {
            examples.Add(new UsageExample
            {
                Description = $"{kvp.Value.Description} only",
                Command = $"{kvp.Value.ExpectedCli} -r 'lua:trace.lua?operations={kvp.Key}'"
            });
        }

        // Workflow examples
        var opNames = operations.Keys.ToList();

        // Install workflow
        var installOps = opNames.Where(op => op.Contains("install") || op.Contains("secure_channel") || op == "info").ToList();
        if (installOps.Count > 1)
        {
            examples.Add(new UsageExample
            {
                Description = "Install workflow",
                Command = $"gp4net applet install app.cap -r 'lua:trace.lua?operations={string.Join(",", installOps)}'"
            });
        }

        // Full workflow
        if (opNames.Count > 2)
        {
            examples.Add(new UsageExample
            {
                Description = "Complete workflow",
                Command = $"gp4net script eval 'full_workflow()' -r 'lua:trace.lua?operations={string.Join(",", opNames)}'"
            });
        }

        return examples;
    }
}