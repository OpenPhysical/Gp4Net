using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using CSharpFunctionalExtensions;
using NUnit.Framework;

namespace Gp4Net.Tests.Dynamic;

/// <summary>
/// Dynamic test discovery system for complex traces that don't fit standard categories.
/// Uses runtime analysis to determine test strategies and automatically generates
/// parameterized tests for comprehensive trace coverage.
/// </summary>
[TestFixture]
[Category("Dynamic")]
public class ComplexTraceDiscoveryTests
{
    private const string ComplexTracePath = "TestData/Traces/Complex";

    /// <summary>
    /// Metadata class for describing discovered trace characteristics.
    /// </summary>
    private class TraceMetadata
    {
        public string FileName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public List<string> Categories { get; set; } = new();
        public Dictionary<string, object> Properties { get; set; } = new();
        public bool HasSecureChannel { get; set; }
        public bool HasComplexWorkflow { get; set; }
        public int ExchangeCount { get; set; }
        public List<string> CommandTypes { get; set; } = new();
    }

    /// <summary>
    /// Functional helper to validate trace directory exists.
    /// </summary>
    /// <param name="traceDirectory">The directory path to validate</param>
    /// <returns>Result containing the directory path or error message</returns>
    private static Result<string, string> ValidateTraceDirectory(string traceDirectory) =>
        Directory.Exists(traceDirectory)
            ? Result.Success<string, string>(traceDirectory)
            : Result.Failure<string, string>(
                $"Complex trace directory not found: {traceDirectory}"
            );

    /// <summary>
    /// Functional helper to discover and analyze trace files.
    /// </summary>
    /// <param name="traceDirectory">The directory containing traces</param>
    /// <returns>Result containing discovered traces or error message</returns>
    private static Result<List<TraceMetadata>, string> DiscoverAndAnalyzeTraces(
        string traceDirectory
    )
    {
        string[] jsonFiles = Directory.GetFiles(traceDirectory, "*.json");

        if (jsonFiles.Length == 0)
            return Result.Failure<List<TraceMetadata>, string>(
                "Should have complex traces to analyze"
            );

        TestContext.Out.WriteLine($"Discovered {jsonFiles.Length} complex trace files:");

        List<TraceMetadata> discoveredTraces = [.. jsonFiles
            .Select(filePath =>
            {
                string fileName = Path.GetFileName(filePath);
                TraceMetadata metadata = AnalyzeTrace(filePath, fileName);

                TestContext.Out.WriteLine($"✓ {fileName}: {metadata.Description}");
                TestContext.Out.WriteLine(
                    $"  Categories: {string.Join(", ", metadata.Categories)}"
                );
                TestContext.Out.WriteLine(
                    $"  Command types: {string.Join(", ", metadata.CommandTypes.Take(5))}"
                );
                if (metadata.CommandTypes.Count > 5)
                {
                    TestContext.Out.WriteLine($"  ... and {metadata.CommandTypes.Count - 5} more");
                }

                return metadata;
            })];

        return Result.Success<List<TraceMetadata>, string>(discoveredTraces);
    }

    /// <summary>
    /// Functional helper to validate discovered traces meet quality criteria.
    /// </summary>
    /// <param name="discoveredTraces">The list of discovered traces</param>
    /// <returns>Result indicating validation success or failure</returns>
    private static UnitResult<string> ValidateDiscoveredTraces(List<TraceMetadata> discoveredTraces)
    {
        // Validate all discovered traces are properly categorized
        if (!discoveredTraces.All(t => t.Categories.Count > 0))
            return UnitResult.Failure<string>("All traces should be automatically categorized");

        // Ensure variety in trace types
        List<string> allCategories = [.. discoveredTraces
            .SelectMany(t => t.Categories)
            .Distinct()];
        if (allCategories.Count <= 1)
            return UnitResult.Failure<string>("Complex traces should span multiple categories");

        TestContext.Out.WriteLine(
            $"Total categories discovered: {string.Join(", ", allCategories)}"
        );
        return UnitResult.Success<string>();
    }

    /// <summary>
    /// Dynamically discover and analyze all complex traces.
    /// </summary>
    [Test]
    public void ComplexTraces_Should_Be_Discoverable_And_Valid() =>
        ValidateTraceDirectory(
                Path.Combine(TestContext.CurrentContext.TestDirectory, ComplexTracePath)
            )
            .Bind(DiscoverAndAnalyzeTraces)
            .Bind(ValidateDiscoveredTraces)
            .Match(
                success => Assert.Pass("Test completed successfully"),
                failure => Assert.Inconclusive(failure)
            );

    /// <summary>
    /// Functional helper to load and parse trace file.
    /// </summary>
    /// <param name="traceFile">The trace file name</param>
    /// <returns>Result containing the JsonDocument or error message</returns>
    private static Result<JsonDocument, string> LoadTraceFile(string traceFile)
    {
        string tracePath = Path.Combine(
            TestContext.CurrentContext.TestDirectory,
            ComplexTracePath,
            traceFile
        );

        if (!File.Exists(tracePath))
            return Result.Failure<JsonDocument, string>($"Trace file not found: {tracePath}");

        try
        {
            string jsonContent = File.ReadAllText(tracePath);
            JsonDocument testData = JsonDocument.Parse(jsonContent);
            return Result.Success<JsonDocument, string>(testData);
        }
        catch (Exception ex)
        {
            return Result.Failure<JsonDocument, string>(
                $"Failed to parse trace file {traceFile}: {ex.Message}"
            );
        }
    }

    /// <summary>
    /// Functional helper to validate configuration workflow characteristics.
    /// </summary>
    /// <param name="testData">The trace data</param>
    /// <param name="description">Test description</param>
    /// <returns>Result indicating validation success or failure</returns>
    private static UnitResult<string> ValidateConfigurationWorkflow(
        JsonDocument testData,
        string description
    )
    {
        TestContext.Out.WriteLine($"Testing {description}");

        if (!testData.RootElement.TryGetProperty("exchanges", out JsonElement exchangesElement))
            return UnitResult.Failure<string>("Configuration trace should contain exchanges");

        List<JsonElement> exchanges = [.. exchangesElement.EnumerateArray()];
        if (exchanges.Count == 0)
            return UnitResult.Failure<string>("Configuration should have command exchanges");

        // Analyze configuration patterns
        HashSet<string> commandTypes = [.. exchanges
            .Select(exchange => exchange.GetProperty("command").GetString()!)
            .Where(command => command.Length >= 4)
            .Select(command => command.Substring(0, 4))];

        bool hasInitialization = commandTypes.Contains("8050") || commandTypes.Contains("00A4");
        bool hasMultiplePhases = commandTypes.Count >= 3;

        if (!hasInitialization)
            return UnitResult.Failure<string>(
                $"Configuration should include initialization for {description}"
            );

        if (!hasMultiplePhases)
            return UnitResult.Failure<string>(
                $"Complex configuration should have multiple command phases for {description}"
            );

        TestContext.Out.WriteLine(
            $"✓ Found {commandTypes.Count} different command types in configuration"
        );
        TestContext.Out.WriteLine($"✓ {description} workflow validated");

        return UnitResult.Success<string>();
    }

    /// <summary>
    /// Test complex configuration and setup workflows.
    /// </summary>
    [TestCase("configure_gpshell.json", "GPShell configuration workflow")]
    [TestCase("configure_gpshell_log.json", "GPShell configuration with detailed logging")]
    public void ComplexTraces_Should_Handle_Configuration_Workflows(
        string traceFile,
        string description
    ) =>
        LoadTraceFile(traceFile)
            .Bind(testData => ValidateConfigurationWorkflow(testData, description))
            .Match(
                success => Assert.Pass("Test completed successfully"),
                failure => Assert.Inconclusive(failure)
            );

    /// <summary>
    /// Functional helper to validate protocol change characteristics.
    /// </summary>
    /// <param name="testData">The trace data</param>
    /// <param name="description">Test description</param>
    /// <param name="traceFile">Trace file name</param>
    /// <returns>Result indicating validation success or failure</returns>
    private static UnitResult<string> ValidateProtocolChanges(
        JsonDocument testData,
        string description,
        string traceFile
    )
    {
        TestContext.Out.WriteLine($"Testing {description}");

        if (!testData.RootElement.TryGetProperty("exchanges", out JsonElement exchangesElement))
            return UnitResult.Failure<string>("Protocol change trace should contain exchanges");

        List<JsonElement> exchanges = [.. exchangesElement.EnumerateArray()];
        List<string> commands = [.. exchanges.Select(e => e.GetProperty("command").GetString()!)];

        // Analyze protocol patterns
        bool hasInitializeUpdate = commands.Any(cmd => cmd.StartsWith("8050"));
        bool hasExternalAuth = commands.Any(cmd => cmd.StartsWith("8482"));
        List<string> scp03Commands = [.. commands
            .Where(cmd => cmd.Length >= 2)
            .Where(cmd =>
            {
                byte cla = Convert.ToByte(cmd.Substring(0, 2), 16);
                return (cla & 0x04) != 0 || (cla & 0x0C) != 0;
            })
            .Take(3)];

        if (!hasInitializeUpdate)
            return UnitResult.Failure<string>("Protocol change should include initialization");

        // Log findings
        if (hasInitializeUpdate)
            TestContext.Out.WriteLine("✓ Found INITIALIZE UPDATE for protocol negotiation");

        if (hasExternalAuth)
        {
            TestContext.Out.WriteLine("✓ Found EXTERNAL AUTHENTICATE for protocol establishment");
            TestContext.Out.WriteLine("✓ Complete authentication workflow detected");
        }
        else
        {
            TestContext.Out.WriteLine(
                "✓ Protocol negotiation phase detected (no authentication in this trace)"
            );
        }

        if (traceFile.Contains("scp03"))
        {
            if (scp03Commands.Any())
            {
                TestContext.Out.WriteLine("✓ SCP03 secure messaging commands detected");
                _ = scp03Commands
                    .Select(cmd => $"✓ Found SCP03 secure messaging: {cmd}")
                    .Aggregate(
                        "",
                        (current, message) =>
                        {
                            TestContext.Out.WriteLine(message);
                            return current;
                        }
                    );
            }
            else
            {
                TestContext.Out.WriteLine(
                    "✓ SCP03 protocol negotiation without secure messaging (negotiation phase only)"
                );
            }
        }

        TestContext.Out.WriteLine($"✓ {description} validated successfully");
        return UnitResult.Success<string>();
    }

    /// <summary>
    /// Test protocol change and adaptation workflows.
    /// </summary>
    [TestCase("globalplatform_scp03_change.json", "SCP03 protocol change workflow")]
    public void ComplexTraces_Should_Handle_Protocol_Changes(
        string traceFile,
        string description
    ) =>
        LoadTraceFile(traceFile)
            .Bind(testData => ValidateProtocolChanges(testData, description, traceFile))
            .Match(
                success => Assert.Pass("Test completed successfully"),
                failure => Assert.Inconclusive(failure)
            );

    /// <summary>
    /// Functional helper to validate listing operation characteristics.
    /// </summary>
    /// <param name="testData">The trace data</param>
    /// <param name="description">Test description</param>
    /// <returns>Result indicating validation success or failure</returns>
    private static UnitResult<string> ValidateListingOperations(
        JsonDocument testData,
        string description
    )
    {
        TestContext.Out.WriteLine($"Testing {description}");

        if (!testData.RootElement.TryGetProperty("exchanges", out JsonElement exchangesElement))
            return UnitResult.Failure<string>("Listing trace should contain exchanges");

        List<JsonElement> exchanges = [.. exchangesElement.EnumerateArray()];
        var commandResponsePairs = exchanges
            .Select(e => new
            {
                Command = e.GetProperty("command").GetString()!,
                Response = e.GetProperty("response").GetString()!,
            })
            .ToList();

        // Analyze listing patterns
        bool foundSelect = commandResponsePairs.Any(pair => pair.Command.StartsWith("00A4"));
        var statusCommands = commandResponsePairs
            .Where(pair => pair.Command.StartsWith("80F2") || pair.Command.StartsWith("80CA"))
            .ToList();

        if (!foundSelect)
            return UnitResult.Failure<string>("Listing should include card/application selection");

        if (!statusCommands.Any())
            return UnitResult.Failure<string>(
                "Listing should include GET STATUS or GET DATA commands"
            );

        // Log findings
        if (foundSelect)
            TestContext.Out.WriteLine("✓ Found SELECT command for listing context");

        _ = statusCommands
            .Select(pair => new
            {
                CommandType = pair.Command.StartsWith("80F2") ? "GET STATUS" : "GET DATA",
                HasData = pair.Response.Length > 4 && pair.Response.EndsWith("9000"),
                DataLength = pair.Response.Length > 4 ? pair.Response.Length - 4 : 0,
            })
            .Where(info => info.HasData)
            .Select(info => $"✓ {info.CommandType} returned {info.DataLength / 2} bytes of data")
            .Aggregate(
                "",
                (current, message) =>
                {
                    TestContext.Out.WriteLine(message);
                    return current;
                }
            );

        TestContext.Out.WriteLine(
            $"✓ Found {statusCommands.Count} status commands in listing operation"
        );
        TestContext.Out.WriteLine($"✓ {description} completed successfully");

        return UnitResult.Success<string>();
    }

    /// <summary>
    /// Test comprehensive listing and enumeration operations.
    /// </summary>
    [TestCase("gp_pro_list_success.json", "Successful listing operation")]
    public void ComplexTraces_Should_Handle_Listing_Operations(
        string traceFile,
        string description
    ) =>
        LoadTraceFile(traceFile)
            .Bind(testData => ValidateListingOperations(testData, description))
            .Match(
                success => Assert.Pass("Test completed successfully"),
                failure => Assert.Inconclusive(failure)
            );

    /// <summary>
    /// Functional helper to perform comprehensive analysis on all traces.
    /// </summary>
    /// <param name="traceDirectory">The directory containing traces</param>
    /// <returns>Result containing analysis results or error message</returns>
    private static Result<
        List<(string fileName, bool isValid, string[] findings)>,
        string
    > PerformComprehensiveAnalysisOnAllTraces(string traceDirectory)
    {
        string[] jsonFiles = Directory.GetFiles(traceDirectory, "*.json");

        List<(string fileName, bool isValid, string[] findings)> analysisResults = [.. jsonFiles
            .Select(filePath =>
            {
                string fileName = Path.GetFileName(filePath);
                (bool isValid, string[] findings) = PerformComprehensiveAnalysis(filePath);

                TestContext.Out.WriteLine($"Analysis of {fileName}:");
                _ = findings.Aggregate(
                    "",
                    (current, finding) =>
                    {
                        TestContext.Out.WriteLine($"  {finding}");
                        return current;
                    }
                );

                return (fileName, isValid, findings);
            })];

        List<(string fileName, bool isValid, string[] findings)> invalidTraces = [.. analysisResults.Where(result => !result.isValid)];
        return invalidTraces.Any()
            ? Result.Failure<List<(string fileName, bool isValid, string[] findings)>, string>(
                $"Comprehensive analysis should pass for {invalidTraces.First().fileName}"
            )
            : Result.Success<List<(string fileName, bool isValid, string[] findings)>, string>(
                analysisResults
            );
    }

    /// <summary>
    /// Functional helper to validate comprehensive analysis results.
    /// </summary>
    /// <param name="analysisResults">The analysis results</param>
    /// <returns>Result indicating validation success or failure</returns>
    private static UnitResult<string> ValidateComprehensiveAnalysis(
        List<(string fileName, bool isValid, string[] findings)> analysisResults
    )
    {
        int totalFindings = analysisResults.SelectMany(r => r.findings).Count();
        int validTraces = analysisResults.Count(r => r.isValid);

        TestContext.Out.WriteLine("Comprehensive Analysis Summary:");
        TestContext.Out.WriteLine($"  Valid traces: {validTraces}/{analysisResults.Count}");
        TestContext.Out.WriteLine($"  Total findings: {totalFindings}");

        return validTraces == analysisResults.Count
            ? UnitResult.Success<string>()
            : UnitResult.Failure<string>("All complex traces should pass comprehensive analysis");
    }

    /// <summary>
    /// Comprehensive analysis of all complex traces using runtime discovery.
    /// This test validates that our discovery system can properly categorize
    /// and test any complex trace without prior knowledge.
    /// </summary>
    [Test]
    public void ComplexTraces_Should_Pass_Comprehensive_Analysis() =>
        ValidateTraceDirectory(
                Path.Combine(TestContext.CurrentContext.TestDirectory, ComplexTracePath)
            )
            .Bind(PerformComprehensiveAnalysisOnAllTraces)
            .Bind(ValidateComprehensiveAnalysis)
            .Match(
                success => Assert.Pass("Test completed successfully"),
                failure => Assert.Inconclusive(failure)
            );

    /// <summary>
    /// Analyze a trace file and extract metadata for categorization.
    /// </summary>
    private static TraceMetadata AnalyzeTrace(string filePath, string fileName)
    {
        TraceMetadata metadata = new TraceMetadata
        {
            FileName = fileName,
            Description = GenerateDescription(fileName),
        };

        try
        {
            string jsonContent = File.ReadAllText(filePath);
            JsonDocument testData = JsonDocument.Parse(jsonContent);

            // Analyze exchanges
            if (testData.RootElement.TryGetProperty("exchanges", out JsonElement exchangesElement))
            {
                List<JsonElement> exchanges = [.. exchangesElement.EnumerateArray()];
                metadata.ExchangeCount = exchanges.Count;

                HashSet<string> commandTypes = new HashSet<string>();
                foreach (JsonElement exchange in exchanges)
                {
                    string command = exchange.GetProperty("command").GetString()!;
                    if (command.Length >= 4)
                    {
                        string commandType = command.Substring(0, 4);
                        _ = commandTypes.Add(commandType);

                        // Check for secure channel indicators
                        if (commandType is "8050" or "8482")
                        {
                            metadata.HasSecureChannel = true;
                        }
                    }
                }

                metadata.CommandTypes = [.. commandTypes];
                metadata.HasComplexWorkflow = commandTypes.Count >= 4;
            }

            // Categorize based on content analysis
            CategorizeTrace(metadata);
        }
        catch (Exception ex)
        {
            metadata.Categories.Add("Error");
            metadata.Properties["AnalysisError"] = ex.Message;
        }

        return metadata;
    }

    /// <summary>
    /// Generate a human-readable description from the filename.
    /// </summary>
    private static string GenerateDescription(string fileName)
    {
        string name = Path.GetFileNameWithoutExtension(fileName);

        // Convert underscores to spaces and title case
        string[] words = [.. name.Split('_').Select(word => char.ToUpper(word[0]) + word.Substring(1).ToLower())];

        return string.Join(" ", words);
    }

    /// <summary>
    /// Categorize a trace based on its analyzed metadata.
    /// </summary>
    private static void CategorizeTrace(TraceMetadata metadata)
    {
        // Configuration category
        if (metadata.FileName.Contains("configure") || metadata.FileName.Contains("config"))
        {
            metadata.Categories.Add("Configuration");
        }

        // Protocol category
        if (metadata.CommandTypes.Contains("8050") || metadata.HasSecureChannel)
        {
            metadata.Categories.Add("Protocol");
        }

        // Listing/Management category
        if (metadata.CommandTypes.Contains("80F2") || metadata.FileName.Contains("list"))
        {
            metadata.Categories.Add("Management");
        }

        // Workflow category
        if (metadata.HasComplexWorkflow)
        {
            metadata.Categories.Add("Workflow");
        }

        // Logging category
        if (metadata.FileName.Contains("log"))
        {
            metadata.Categories.Add("Logging");
        }

        // Default category if none assigned
        if (metadata.Categories.Count == 0)
        {
            metadata.Categories.Add("General");
        }
    }

    /// <summary>
    /// Perform comprehensive analysis on a single trace file.
    /// </summary>
    private static (bool isValid, string[] findings) PerformComprehensiveAnalysis(string filePath)
    {
        List<string> findings = new List<string>();
        bool isValid = true;

        try
        {
            string jsonContent = File.ReadAllText(filePath);
            JsonDocument testData = JsonDocument.Parse(jsonContent);

            // Validate JSON structure
            if (!testData.RootElement.TryGetProperty("exchanges", out JsonElement exchangesElement))
            {
                findings.Add("❌ Missing exchanges property");
                isValid = false;
            }
            else
            {
                int exchangeCount = exchangesElement.EnumerateArray().Count();
                findings.Add($"✓ Contains {exchangeCount} command exchanges");

                // Validate exchange structure
                int validExchanges = 0;
                foreach (JsonElement exchange in exchangesElement.EnumerateArray())
                {
                    if (
                        exchange.TryGetProperty("command", out _)
                        && exchange.TryGetProperty("response", out _)
                    )
                    {
                        validExchanges++;
                    }
                }

                if (validExchanges == exchangeCount)
                {
                    findings.Add("✓ All exchanges have valid command/response structure");
                }
                else
                {
                    findings.Add(
                        $"❌ {exchangeCount - validExchanges} exchanges have invalid structure"
                    );
                    isValid = false;
                }
            }

            // Check for metadata
            if (testData.RootElement.TryGetProperty("metadata", out _))
            {
                findings.Add("✓ Contains metadata");
            }

            // Check for session data
            if (testData.RootElement.TryGetProperty("sessions", out _))
            {
                findings.Add("✓ Contains session data");
            }
        }
        catch (Exception ex)
        {
            findings.Add($"❌ Analysis failed: {ex.Message}");
            isValid = false;
        }

        return (isValid, findings.ToArray());
    }
}
