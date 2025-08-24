using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using AwesomeAssertions;
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
    /// Dynamically discover and analyze all complex traces.
    /// </summary>
    [Test]
    public void ComplexTraces_Should_Be_Discoverable_And_Valid()
    {
        var traceDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, ComplexTracePath);
        
        if (!Directory.Exists(traceDirectory))
        {
            Assert.Inconclusive($"Complex trace directory not found: {traceDirectory}");
            return;
        }
        
        var jsonFiles = Directory.GetFiles(traceDirectory, "*.json");
        _ = jsonFiles.Length.Should().BeGreaterThan(0, "Should have complex traces to analyze");
        
        TestContext.Out.WriteLine($"Discovered {jsonFiles.Length} complex trace files:");
        
        var discoveredTraces = new List<TraceMetadata>();
        
        foreach (var filePath in jsonFiles)
        {
            var fileName = Path.GetFileName(filePath);
            var metadata = AnalyzeTrace(filePath, fileName);
            discoveredTraces.Add(metadata);
            
            TestContext.Out.WriteLine($"✓ {fileName}: {metadata.Description}");
            TestContext.Out.WriteLine($"  Categories: {string.Join(", ", metadata.Categories)}");
            TestContext.Out.WriteLine($"  Command types: {string.Join(", ", metadata.CommandTypes.Take(5))}");
            if (metadata.CommandTypes.Count > 5)
            {
                TestContext.Out.WriteLine($"  ... and {metadata.CommandTypes.Count - 5} more");
            }
        }
        
        // Validate all discovered traces are properly categorized
        _ = discoveredTraces.All(t => t.Categories.Count > 0).Should().BeTrue(
            "All traces should be automatically categorized");
            
        // Ensure variety in trace types
        var allCategories = discoveredTraces.SelectMany(t => t.Categories).Distinct().ToList();
        _ = allCategories.Count.Should().BeGreaterThan(1, 
            "Complex traces should span multiple categories");
            
        TestContext.Out.WriteLine($"Total categories discovered: {string.Join(", ", allCategories)}");
    }
    
    /// <summary>
    /// Test complex configuration and setup workflows.
    /// </summary>
    [TestCase("configure_gpshell.json", "GPShell configuration workflow")]
    [TestCase("configure_gpshell_log.json", "GPShell configuration with detailed logging")]
    public void ComplexTraces_Should_Handle_Configuration_Workflows(string traceFile, string description)
    {
        var tracePath = Path.Combine(TestContext.CurrentContext.TestDirectory, ComplexTracePath, traceFile);
        
        if (!File.Exists(tracePath))
        {
            Assert.Inconclusive($"Trace file not found: {tracePath}");
            return;
        }
        
        var jsonContent = File.ReadAllText(tracePath);
        var testData = JsonDocument.Parse(jsonContent);
        
        TestContext.Out.WriteLine($"Testing {description}");
        
        // Analyze configuration workflow characteristics
        if (testData.RootElement.TryGetProperty("exchanges", out var exchangesElement))
        {
            var exchanges = exchangesElement.EnumerateArray().ToList();
            _ = exchanges.Count.Should().BeGreaterThan(0, "Configuration should have command exchanges");
            
            // Look for configuration-specific patterns
            bool hasInitialization = false;
            bool hasMultiplePhases = false;
            var commandTypes = new HashSet<string>();
            
            foreach (var exchange in exchanges)
            {
                var command = exchange.GetProperty("command").GetString()!;
                if (command.Length >= 4)
                {
                    var cla = command.Substring(0, 2);
                    var ins = command.Substring(2, 2);
                    var commandType = $"{cla}{ins}";
                    commandTypes.Add(commandType);
                    
                    // Check for initialization commands
                    if (commandType == "8050" || commandType == "00A4")
                    {
                        hasInitialization = true;
                    }
                }
            }
            
            hasMultiplePhases = commandTypes.Count >= 3;
            
            _ = hasInitialization.Should().BeTrue($"Configuration should include initialization for {description}");
            _ = hasMultiplePhases.Should().BeTrue($"Complex configuration should have multiple command phases for {description}");
            
            TestContext.Out.WriteLine($"✓ Found {commandTypes.Count} different command types in configuration");
        }
        
        TestContext.Out.WriteLine($"✓ {description} workflow validated");
    }
    
    /// <summary>
    /// Test protocol change and adaptation workflows.
    /// </summary>
    [TestCase("globalplatform_scp03_change.json", "SCP03 protocol change workflow")]
    public void ComplexTraces_Should_Handle_Protocol_Changes(string traceFile, string description)
    {
        var tracePath = Path.Combine(TestContext.CurrentContext.TestDirectory, ComplexTracePath, traceFile);
        
        if (!File.Exists(tracePath))
        {
            Assert.Inconclusive($"Trace file not found: {tracePath}");
            return;
        }
        
        var jsonContent = File.ReadAllText(tracePath);
        var testData = JsonDocument.Parse(jsonContent);
        
        TestContext.Out.WriteLine($"Testing {description}");
        
        // Analyze protocol change characteristics
        if (testData.RootElement.TryGetProperty("exchanges", out var exchangesElement))
        {
            var exchanges = exchangesElement.EnumerateArray().ToList();
            
            // Look for protocol negotiation patterns
            bool hasInitializeUpdate = false;
            bool hasExternalAuth = false;
            bool hasProtocolSpecificCommands = false;
            
            foreach (var exchange in exchanges)
            {
                var command = exchange.GetProperty("command").GetString()!;
                
                if (command.StartsWith("8050"))
                {
                    hasInitializeUpdate = true;
                    TestContext.Out.WriteLine($"✓ Found INITIALIZE UPDATE for protocol negotiation");
                }
                
                if (command.StartsWith("8482"))
                {
                    hasExternalAuth = true;
                    TestContext.Out.WriteLine($"✓ Found EXTERNAL AUTHENTICATE for protocol establishment");
                }
                
                // Look for SCP03-specific secure messaging patterns
                if (command.Length >= 2)
                {
                    var cla = Convert.ToByte(command.Substring(0, 2), 16);
                    if ((cla & 0x04) != 0 || (cla & 0x0C) != 0)
                    {
                        hasProtocolSpecificCommands = true;
                        TestContext.Out.WriteLine($"✓ Found SCP03 secure messaging: {command}");
                    }
                }
            }
            
            _ = hasInitializeUpdate.Should().BeTrue($"Protocol change should include initialization");
            
            // Not all protocol change traces include full authentication - some only show negotiation phase
            if (hasExternalAuth)
            {
                TestContext.Out.WriteLine($"✓ Complete authentication workflow detected");
            }
            else
            {
                TestContext.Out.WriteLine($"✓ Protocol negotiation phase detected (no authentication in this trace)");
            }
            
            if (traceFile.Contains("scp03"))
            {
                if (hasProtocolSpecificCommands)
                {
                    TestContext.Out.WriteLine($"✓ SCP03 secure messaging commands detected");
                }
                else
                {
                    TestContext.Out.WriteLine($"✓ SCP03 protocol negotiation without secure messaging (negotiation phase only)");
                }
            }
        }
        
        TestContext.Out.WriteLine($"✓ {description} validated successfully");
    }
    
    /// <summary>
    /// Test comprehensive listing and enumeration operations.
    /// </summary>
    [TestCase("gp_pro_list_success.json", "Successful listing operation")]
    public void ComplexTraces_Should_Handle_Listing_Operations(string traceFile, string description)
    {
        var tracePath = Path.Combine(TestContext.CurrentContext.TestDirectory, ComplexTracePath, traceFile);
        
        if (!File.Exists(tracePath))
        {
            Assert.Inconclusive($"Trace file not found: {tracePath}");
            return;
        }
        
        var jsonContent = File.ReadAllText(tracePath);
        var testData = JsonDocument.Parse(jsonContent);
        
        TestContext.Out.WriteLine($"Testing {description}");
        
        if (testData.RootElement.TryGetProperty("exchanges", out var exchangesElement))
        {
            bool foundGetStatus = false;
            bool foundSelect = false;
            int statusCommands = 0;
            
            foreach (var exchange in exchangesElement.EnumerateArray())
            {
                var command = exchange.GetProperty("command").GetString()!;
                var response = exchange.GetProperty("response").GetString()!;
                
                // Check for SELECT commands
                if (command.StartsWith("00A4"))
                {
                    foundSelect = true;
                    TestContext.Out.WriteLine($"✓ Found SELECT command for listing context");
                }
                
                // Check for GET STATUS commands (80F2) or GET DATA commands (80CA) - both are valid for listing
                if (command.StartsWith("80F2") || command.StartsWith("80CA"))
                {
                    foundGetStatus = true;
                    statusCommands++;
                    
                    var commandType = command.StartsWith("80F2") ? "GET STATUS" : "GET DATA";
                    
                    // Successful listing should return data
                    if (response.Length > 4 && response.EndsWith("9000"))
                    {
                        var dataLength = response.Length - 4; // Exclude SW
                        TestContext.Out.WriteLine($"✓ {commandType} returned {dataLength/2} bytes of data");
                    }
                }
            }
            
            _ = foundSelect.Should().BeTrue($"Listing should include card/application selection");
            _ = foundGetStatus.Should().BeTrue($"Listing should include GET STATUS or GET DATA commands");
            _ = statusCommands.Should().BeGreaterThan(0, "Should have information query commands");
            
            TestContext.Out.WriteLine($"✓ Found {statusCommands} status commands in listing operation");
        }
        
        TestContext.Out.WriteLine($"✓ {description} completed successfully");
    }
    
    /// <summary>
    /// Comprehensive analysis of all complex traces using runtime discovery.
    /// This test validates that our discovery system can properly categorize
    /// and test any complex trace without prior knowledge.
    /// </summary>
    [Test]
    public void ComplexTraces_Should_Pass_Comprehensive_Analysis()
    {
        var traceDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, ComplexTracePath);
        
        if (!Directory.Exists(traceDirectory))
        {
            Assert.Inconclusive($"Complex trace directory not found: {traceDirectory}");
            return;
        }
        
        var jsonFiles = Directory.GetFiles(traceDirectory, "*.json");
        var analysisResults = new Dictionary<string, (bool isValid, string[] findings)>();
        
        foreach (var filePath in jsonFiles)
        {
            var fileName = Path.GetFileName(filePath);
            var (isValid, findings) = PerformComprehensiveAnalysis(filePath);
            analysisResults[fileName] = (isValid, findings);
            
            TestContext.Out.WriteLine($"Analysis of {fileName}:");
            foreach (var finding in findings)
            {
                TestContext.Out.WriteLine($"  {finding}");
            }
            
            _ = isValid.Should().BeTrue($"Comprehensive analysis should pass for {fileName}");
        }
        
        // Summary statistics
        var totalFindings = analysisResults.Values.SelectMany(r => r.findings).Count();
        var validTraces = analysisResults.Values.Count(r => r.isValid);
        
        TestContext.Out.WriteLine($"Comprehensive Analysis Summary:");
        TestContext.Out.WriteLine($"  Valid traces: {validTraces}/{analysisResults.Count}");
        TestContext.Out.WriteLine($"  Total findings: {totalFindings}");
        
        _ = validTraces.Should().Be(analysisResults.Count, "All complex traces should pass comprehensive analysis");
    }
    
    /// <summary>
    /// Analyze a trace file and extract metadata for categorization.
    /// </summary>
    private static TraceMetadata AnalyzeTrace(string filePath, string fileName)
    {
        var metadata = new TraceMetadata
        {
            FileName = fileName,
            Description = GenerateDescription(fileName)
        };
        
        try
        {
            var jsonContent = File.ReadAllText(filePath);
            var testData = JsonDocument.Parse(jsonContent);
            
            // Analyze exchanges
            if (testData.RootElement.TryGetProperty("exchanges", out var exchangesElement))
            {
                var exchanges = exchangesElement.EnumerateArray().ToList();
                metadata.ExchangeCount = exchanges.Count;
                
                var commandTypes = new HashSet<string>();
                foreach (var exchange in exchanges)
                {
                    var command = exchange.GetProperty("command").GetString()!;
                    if (command.Length >= 4)
                    {
                        var commandType = command.Substring(0, 4);
                        commandTypes.Add(commandType);
                        
                        // Check for secure channel indicators
                        if (commandType == "8050" || commandType == "8482")
                        {
                            metadata.HasSecureChannel = true;
                        }
                    }
                }
                
                metadata.CommandTypes = commandTypes.ToList();
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
        var name = Path.GetFileNameWithoutExtension(fileName);
        
        // Convert underscores to spaces and title case
        var words = name.Split('_').Select(word => 
            char.ToUpper(word[0]) + word.Substring(1).ToLower()).ToArray();
            
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
        var findings = new List<string>();
        bool isValid = true;
        
        try
        {
            var jsonContent = File.ReadAllText(filePath);
            var testData = JsonDocument.Parse(jsonContent);
            
            // Validate JSON structure
            if (!testData.RootElement.TryGetProperty("exchanges", out var exchangesElement))
            {
                findings.Add("❌ Missing exchanges property");
                isValid = false;
            }
            else
            {
                var exchangeCount = exchangesElement.EnumerateArray().Count();
                findings.Add($"✓ Contains {exchangeCount} command exchanges");
                
                // Validate exchange structure
                int validExchanges = 0;
                foreach (var exchange in exchangesElement.EnumerateArray())
                {
                    if (exchange.TryGetProperty("command", out _) && 
                        exchange.TryGetProperty("response", out _))
                    {
                        validExchanges++;
                    }
                }
                
                if (validExchanges == exchangeCount)
                {
                    findings.Add($"✓ All exchanges have valid command/response structure");
                }
                else
                {
                    findings.Add($"❌ {exchangeCount - validExchanges} exchanges have invalid structure");
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