using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Core;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Generates comprehensive test cases from trace operations targeting 50% coverage.
/// Analyzes trace files to identify critical paths and creates focused test scenarios.
/// </summary>
public static class TraceBasedTestGenerator
{
    private const double TARGET_COVERAGE_PERCENTAGE = 50.0;
    private const string TRACE_DIRECTORY = "TestData/Traces";

    /// <summary>
    /// Analyzes all trace files and generates test cases to achieve 50% coverage.
    /// </summary>
    /// <param name="testDirectory">Base test directory path.</param>
    /// <returns>Collection of generated test cases with coverage analysis.</returns>
    public static Result<GeneratedTestSuite, SmartCardError> GenerateTestsForCoverage(string testDirectory)
    {
        var traceDirectory = Path.Combine(testDirectory, TRACE_DIRECTORY);
        
        if (!Directory.Exists(traceDirectory))
        {
            return Result.Failure<GeneratedTestSuite, SmartCardError>(
                SmartCardError.InvalidData($"Trace directory not found: {traceDirectory}"));
        }

        return AnalyzeTraceFiles(traceDirectory)
            .Bind(analysis => GenerateOptimalTestCases(analysis))
            .Map(testCases => new GeneratedTestSuite(testCases, CalculateExpectedCoverage(testCases)));
    }

    /// <summary>
    /// Analyzes all trace files to understand available operations and paths.
    /// </summary>
    private static Result<TraceAnalysis, SmartCardError> AnalyzeTraceFiles(string traceDirectory)
    {
        try
        {
            var traceFiles = Directory.GetFiles(traceDirectory, "*.json", SearchOption.AllDirectories);
            
            var analysisResults = traceFiles
                .Select(LoadAndAnalyzeTrace)
                .Where(result => result.IsSuccess)
                .Select(result => result.Value)
                .ToImmutableList();

            var allOperations = analysisResults
                .SelectMany(analysis => analysis.AvailableOperations)
                .ToImmutableHashSet();

            var allProtocols = analysisResults
                .SelectMany(analysis => analysis.SupportedProtocols)
                .ToImmutableHashSet();

            var complexityScores = analysisResults
                .ToImmutableDictionary(analysis => analysis.FilePath, analysis => analysis.ComplexityScore);

            return Result.Success<TraceAnalysis, SmartCardError>(new TraceAnalysis(
                analysisResults,
                allOperations,
                allProtocols,
                complexityScores
            ));
        }
        catch (Exception ex)
        {
            return Result.Failure<TraceAnalysis, SmartCardError>(
                SmartCardError.UnexpectedError($"Failed to analyze trace files: {ex.Message}", Maybe<Exception>.From(ex)));
        }
    }

    /// <summary>
    /// Loads and analyzes a single trace file.
    /// </summary>
    private static Result<TraceFileAnalysis, SmartCardError> LoadAndAnalyzeTrace(string filePath)
    {
        try
        {
            var json = File.ReadAllText(filePath);
            var trace = JsonSerializer.Deserialize<TraceData>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            });

            if (trace == null)
            {
                return Result.Failure<TraceFileAnalysis, SmartCardError>(
                    SmartCardError.InvalidData($"Failed to deserialize trace file: {filePath}"));
            }

            trace.FilePath = filePath;

            var operations = trace.Exchanges != null 
                ? ExtractOperationsFromExchanges(trace.Exchanges)
                : ImmutableHashSet<string>.Empty;
            
            var protocols = trace.Sessions != null
                ? ExtractProtocolsFromSessions(trace.Sessions)
                : ImmutableHashSet<string>.Empty;
                
            var complexityScore = CalculateTraceComplexity(operations, protocols);

            return Result.Success<TraceFileAnalysis, SmartCardError>(new TraceFileAnalysis(
                filePath,
                Path.GetFileNameWithoutExtension(filePath),
                operations,
                protocols,
                complexityScore,
                trace
            ));
        }
        catch (Exception ex)
        {
            return Result.Failure<TraceFileAnalysis, SmartCardError>(
                SmartCardError.UnexpectedError($"Failed to load trace file {filePath}: {ex.Message}", Maybe<Exception>.From(ex)));
        }
    }

    /// <summary>
    /// Extracts operations from trace exchanges using functional approach.
    /// </summary>
    private static ImmutableHashSet<string> ExtractOperationsFromExchanges(IList<TraceExchange> exchanges)
    {
        return exchanges
            .Where(exchange => !string.IsNullOrEmpty(exchange.Command) && exchange.Command.Length >= 4)
            .Select(exchange => exchange.Command.Substring(0, 4).ToUpperInvariant())
            .Select(ClassifyOperation)
            .Where(operation => !string.IsNullOrEmpty(operation))
            .ToImmutableHashSet();
    }

    /// <summary>
    /// Extracts protocols from trace sessions using functional approach.
    /// </summary>
    private static ImmutableHashSet<string> ExtractProtocolsFromSessions(IDictionary<string, SessionInfo> sessions)
    {
        return sessions.Values
            .Select(session => DetermineProtocol(session.ScpVersion))
            .ToImmutableHashSet();
    }

    /// <summary>
    /// Calculates trace complexity score based on operations and protocols.
    /// </summary>
    private static int CalculateTraceComplexity(ImmutableHashSet<string> operations, ImmutableHashSet<string> protocols)
    {
        var operationScore = operations.Sum(GetOperationComplexity);
        var protocolScore = protocols.Sum(GetProtocolComplexity);
        return operationScore + protocolScore;
    }

    /// <summary>
    /// Classifies APDU commands into operation categories.
    /// </summary>
    private static string ClassifyOperation(string claIns)
    {
        return claIns switch
        {
            "00A4" => "SELECT",
            "8050" => "INITIALIZE_UPDATE",
            "8482" or "0482" => "EXTERNAL_AUTHENTICATE",
            "80F2" or "00F2" => "GET_STATUS",
            "80E6" => "INSTALL",
            "80E4" => "DELETE",
            "80E8" => "LOAD",
            "80CA" => "GET_DATA",
            "80DA" => "PUT_DATA",
            _ => string.Empty
        };
    }

    /// <summary>
    /// Determines protocol from SCP version.
    /// </summary>
    private static string DetermineProtocol(int scpVersion)
    {
        return scpVersion switch
        {
            2 or 0x02 => "SCP02",
            3 or 0x03 => "SCP03",
            _ => "NONE"
        };
    }

    /// <summary>
    /// Gets complexity score for an operation (higher = more important for coverage).
    /// </summary>
    private static int GetOperationComplexity(string operation)
    {
        return operation switch
        {
            "SELECT" => 5,
            "INITIALIZE_UPDATE" => 10,
            "EXTERNAL_AUTHENTICATE" => 10,
            "GET_STATUS" => 7,
            "INSTALL" => 15,
            "DELETE" => 12,
            "LOAD" => 15,
            "GET_DATA" => 3,
            "PUT_DATA" => 5,
            _ => 1
        };
    }

    /// <summary>
    /// Gets complexity score for a protocol.
    /// </summary>
    private static int GetProtocolComplexity(string protocol)
    {
        return protocol switch
        {
            "SCP02" => 10,
            "SCP03" => 15,
            "NONE" => 1,
            _ => 1
        };
    }

    /// <summary>
    /// Generates optimal test cases to achieve target coverage.
    /// </summary>
    private static Result<ImmutableList<GeneratedTestCase>, SmartCardError> GenerateOptimalTestCases(TraceAnalysis analysis)
    {
        try
        {
            // Priority 1: Core operations that must be covered for 50% target
            var coreOperations = new[] { "SELECT", "INITIALIZE_UPDATE", "EXTERNAL_AUTHENTICATE", "GET_STATUS" };
            var coreProtocols = new[] { "SCP02", "SCP03" };

            var coreTestCases = GenerateCoreTestCases(analysis, coreOperations, coreProtocols);
            var complexTestCases = GenerateComplexTestCases(analysis);

            var allTestCases = coreTestCases.Concat(complexTestCases).ToImmutableList();

            return Result.Success<ImmutableList<GeneratedTestCase>, SmartCardError>(allTestCases);
        }
        catch (Exception ex)
        {
            return Result.Failure<ImmutableList<GeneratedTestCase>, SmartCardError>(
                SmartCardError.UnexpectedError($"Failed to generate test cases: {ex.Message}", Maybe<Exception>.From(ex)));
        }
    }

    /// <summary>
    /// Generates core test cases for essential operation/protocol combinations.
    /// </summary>
    private static ImmutableList<GeneratedTestCase> GenerateCoreTestCases(
        TraceAnalysis analysis, 
        string[] coreOperations, 
        string[] coreProtocols)
    {
        return coreOperations
            .SelectMany(operation => coreProtocols
                .Where(protocol => analysis.AllProtocols.Contains(protocol))
                .Select(protocol => new { Operation = operation, Protocol = protocol }))
            .Select(combo => FindBestTraceForOperation(analysis, combo.Operation, combo.Protocol)
                .Map(trace => new GeneratedTestCase(
                    $"Test_{combo.Operation}_{combo.Protocol}",
                    combo.Operation,
                    combo.Protocol,
                    trace.FilePath,
                    GetOperationComplexity(combo.Operation) + GetProtocolComplexity(combo.Protocol),
                    GenerateTestDescription(combo.Operation, combo.Protocol)
                )))
            .Where(result => result.HasValue)
            .Select(result => result.Value)
            .ToImmutableList();
    }

    /// <summary>
    /// Generates additional test cases for complex operations.
    /// </summary>
    private static ImmutableList<GeneratedTestCase> GenerateComplexTestCases(TraceAnalysis analysis)
    {
        var complexOperations = new[] { "INSTALL", "DELETE", "LOAD" };
        
        return complexOperations
            .Where(operation => analysis.AllOperations.Contains(operation))
            .Select(operation => FindBestTraceForOperation(analysis, operation, "SCP02")
                .Where(trace => trace.ComplexityScore > 20) // Only include if trace is comprehensive
                .Map(trace => new GeneratedTestCase(
                    $"Test_{operation}_Comprehensive",
                    operation,
                    "SCP02",
                    trace.FilePath,
                    trace.ComplexityScore,
                    GenerateTestDescription(operation, "SCP02")
                )))
            .Where(result => result.HasValue)
            .Select(result => result.Value)
            .ToImmutableList();
    }

    /// <summary>
    /// Finds the best trace file for a specific operation and protocol combination.
    /// </summary>
    private static Maybe<TraceFileAnalysis> FindBestTraceForOperation(TraceAnalysis analysis, string operation, string protocol)
    {
        var candidates = analysis.TraceFiles
            .Where(trace => trace.AvailableOperations.Contains(operation) && 
                           trace.SupportedProtocols.Contains(protocol))
            .OrderByDescending(trace => trace.ComplexityScore)
            .ToImmutableList();

        return candidates.Any() 
            ? Maybe<TraceFileAnalysis>.From(candidates.First())
            : Maybe<TraceFileAnalysis>.None;
    }

    /// <summary>
    /// Generates a human-readable test description.
    /// </summary>
    private static string GenerateTestDescription(string operation, string protocol)
    {
        return operation switch
        {
            "SELECT" => $"Verifies SELECT command functionality using {protocol} protocol",
            "INITIALIZE_UPDATE" => $"Tests INITIALIZE UPDATE and session key derivation with {protocol}",
            "EXTERNAL_AUTHENTICATE" => $"Validates EXTERNAL AUTHENTICATE and secure channel establishment with {protocol}",
            "GET_STATUS" => $"Tests GET STATUS command over secure channel with {protocol}",
            "INSTALL" => $"Comprehensive INSTALL command testing with {protocol} secure channel",
            "DELETE" => $"DELETE command verification with {protocol} security",
            "LOAD" => $"LOAD command testing with {protocol} protocol",
            _ => $"Generic {operation} command testing with {protocol}"
        };
    }

    /// <summary>
    /// Calculates expected coverage percentage from generated test cases.
    /// </summary>
    private static double CalculateExpectedCoverage(ImmutableList<GeneratedTestCase> testCases)
    {
        // Define all possible critical paths for GlobalPlatform
        var allCriticalPaths = new[]
        {
            "SELECT", "INITIALIZE_UPDATE_SCP02", "INITIALIZE_UPDATE_SCP03",
            "EXTERNAL_AUTHENTICATE_SCP02", "EXTERNAL_AUTHENTICATE_SCP03",
            "GET_STATUS_SCP02", "GET_STATUS_SCP03",
            "INSTALL_SCP02", "DELETE_SCP02", "LOAD_SCP02"
        };

        var coveredPaths = testCases
            .Select(tc => $"{tc.Operation}_{tc.Protocol}")
            .Distinct()
            .Count(path => allCriticalPaths.Any(critical => critical.Contains(path.Split('_')[0])));

        return Math.Min(100.0, (double)coveredPaths / allCriticalPaths.Length * 100.0);
    }

    public const double TargetCoveragePercentage = TARGET_COVERAGE_PERCENTAGE;
}

/// <summary>
/// Analysis of all trace files in a directory.
/// </summary>
public record TraceAnalysis(
    ImmutableList<TraceFileAnalysis> TraceFiles,
    ImmutableHashSet<string> AllOperations,
    ImmutableHashSet<string> AllProtocols,
    ImmutableDictionary<string, int> ComplexityScores
);

/// <summary>
/// Analysis of a single trace file.
/// </summary>
public record TraceFileAnalysis(
    string FilePath,
    string TraceName,
    ImmutableHashSet<string> AvailableOperations,
    ImmutableHashSet<string> SupportedProtocols,
    int ComplexityScore,
    TraceData TraceData
);

/// <summary>
/// A generated test case for coverage testing.
/// </summary>
public record GeneratedTestCase(
    string TestName,
    string Operation,
    string Protocol,
    string TraceFilePath,
    int Priority,
    string Description
);

/// <summary>
/// Complete suite of generated test cases with coverage information.
/// </summary>
public record GeneratedTestSuite(
    ImmutableList<GeneratedTestCase> TestCases,
    double ExpectedCoverage
)
{
    /// <summary>
    /// Checks if the test suite meets the 50% coverage target.
    /// </summary>
    public bool MeetsCoverageTarget => ExpectedCoverage >= TraceBasedTestGenerator.TargetCoveragePercentage;

    /// <summary>
    /// Generates a summary report of the test suite.
    /// </summary>
    public string GenerateReport()
    {
        var reportLines = new[]
        {
            "=== Generated Test Suite Report ===",
            $"Total Test Cases: {TestCases.Count}",
            $"Expected Coverage: {ExpectedCoverage:F1}%",
            $"Meets 50% Target: {(MeetsCoverageTarget ? "✓ Yes" : "✗ No")}",
            "",
            "Generated Test Cases:"
        }
        .Concat(TestCases
            .OrderByDescending(tc => tc.Priority)
            .Select(tc => $"  [{tc.Priority:D2}] {tc.TestName}: {tc.Description}")
        );

        return string.Join(Environment.NewLine, reportLines);
    }
}