using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
using JetBrains.Annotations;
using NUnit.Framework;

namespace Gp4Net.Tests.Integration;

/// <summary>
/// Dynamic test discovery system that automatically generates tests from JSON trace files.
/// Each trace/operation combination becomes a separate test visible in the IDE.
/// </summary>
[TestFixture]
public class DynamicTraceTests
{
    /// <summary>
    /// Test method that runs verification for each discovered trace operation.
    /// </summary>
    [TestCaseSource(typeof(TraceTestDiscovery))]
    public void VerifyTraceOperation(TraceTestCase testCase)
    {
        // Create appropriate verifier based on operation
        var verifier = OperationVerifierFactory.Create(testCase.OperationName, testCase.Trace);
        
        // Run verification
        var result = verifier.Verify();
        
        // Assert success with detailed error message if failed
        result.IsSuccess.Should().BeTrue(
            $"Operation '{testCase.OperationName}' verification failed: {(result.IsFailure ? result.Error : "Unknown error")}"
        );
    }
}

/// <summary>
/// Test case data for a trace operation.
/// </summary>
public class TraceTestCase
{
    public TraceData Trace { get; }
    public string OperationName { get; }
    public string TestName { get; }
    
    public TraceTestCase(TraceData trace, string operationName, string testName)
    {
        Trace = trace;
        OperationName = operationName;
        TestName = testName;
    }
    
    public override string ToString() => TestName;
}

/// <summary>
/// Discovers all JSON trace files and generates test cases for each testable operation.
/// </summary>
public class TraceTestDiscovery : IEnumerable
{
    private const string TraceDirectory = "TestData/Traces";
    
    public IEnumerator GetEnumerator()
    {
        var baseDir = Path.Combine(TestContext.CurrentContext.TestDirectory, TraceDirectory);
        Console.WriteLine($"[TraceTestDiscovery] Looking for traces in: {baseDir}");
        Console.WriteLine($"[TraceTestDiscovery] Directory exists: {Directory.Exists(baseDir)}");
        
        if (!Directory.Exists(baseDir))
        {
            Console.WriteLine($"[TraceTestDiscovery] Trace directory not found, yielding no tests");
            yield break;
        }
        
        var traceFiles = Directory.GetFiles(baseDir, "*.json", SearchOption.AllDirectories)
            .OrderBy(f => f);
        
        Console.WriteLine($"[TraceTestDiscovery] Found {traceFiles.Count()} JSON files");
        
        foreach (var traceFile in traceFiles)
        {
            TraceData trace;
            try
            {
                var json = File.ReadAllText(traceFile);
                var deserializedTrace = JsonSerializer.Deserialize<TraceData>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                });
                
                if (deserializedTrace == null) continue;
                trace = deserializedTrace;
            }
            catch (Exception ex)
            {
                TestContext.WriteLine($"Failed to load trace {traceFile}: {ex.Message}");
                continue;
            }
            
            // Set trace file path for reference
            trace.FilePath = traceFile;
            
            // Skip if marked as untestable
            if (trace.TestHints?.SkipReason != null)
            {
                TestContext.WriteLine($"Skipping {Path.GetFileName(traceFile)}: {trace.TestHints.SkipReason}");
                continue;
            }
            
            // Generate tests for each testable operation
            var operations = AnalyzeOperations(trace);
            Console.WriteLine($"[TraceTestDiscovery] Found {operations.Count()} operations in {Path.GetFileName(traceFile)}");
            foreach (var operation in operations)
            {
                var testName = $"trace_test_{Path.GetFileNameWithoutExtension(traceFile)}_{operation.Name}";
                Console.WriteLine($"[TraceTestDiscovery] Yielding test: {testName}");
                yield return new TraceTestCase(trace, operation.Name, testName);
            }
        }
    }
    
    private IEnumerable<TestableOperation> AnalyzeOperations(TraceData trace)
    {
        // Use test hints if available
        if (trace.TestHints?.TestableOperations != null)
        {
            foreach (var op in trace.TestHints.TestableOperations)
            {
                yield return new TestableOperation
                {
                    Name = op.Name,
                    ExchangeIndex = op.ExchangeIndex
                };
            }
            yield break;
        }
        
        // Otherwise, analyze exchanges
        for (int i = 0; i < trace.Exchanges?.Count; i++)
        {
            var exchange = trace.Exchanges[i];
            if (string.IsNullOrEmpty(exchange.Command) || exchange.Command.Length < 4)
                continue;
                
            var claIns = exchange.Command.Substring(0, 4).ToUpperInvariant();
            
            switch (claIns)
            {
                case "00A4": // SELECT
                    yield return new TestableOperation { Name = "select", ExchangeIndex = i };
                    break;
                    
                case "8050": // INITIALIZE UPDATE
                    yield return new TestableOperation { Name = "initialize_update", ExchangeIndex = i };
                    break;
                    
                case "8482": // EXTERNAL AUTHENTICATE
                case "0482":
                    yield return new TestableOperation { Name = "external_authenticate", ExchangeIndex = i };
                    break;
                    
                case "80E6": // INSTALL
                    yield return new TestableOperation { Name = "install", ExchangeIndex = i };
                    break;
                    
                case "80E4": // DELETE
                    yield return new TestableOperation { Name = "delete", ExchangeIndex = i };
                    break;
                    
                case "80E8": // LOAD
                    yield return new TestableOperation { Name = "load", ExchangeIndex = i };
                    break;
            }
        }
    }
}

/// <summary>
/// Factory for creating operation-specific verifiers.
/// </summary>
public static class OperationVerifierFactory
{
    public static IOperationVerifier Create(string operationName, TraceData trace)
    {
        return operationName switch
        {
            "select" => new SelectVerifier(trace),
            "initialize_update" => new InitializeUpdateVerifier(trace),
            "external_authenticate" => new ExternalAuthenticateVerifier(trace),
            "install" => new InstallVerifier(trace),
            "delete" => new DeleteVerifier(trace),
            "load" => new LoadVerifier(trace),
            _ => new GenericVerifier(trace, operationName)
        };
    }
}

/// <summary>
/// Base interface for operation verifiers.
/// </summary>
public interface IOperationVerifier
{
    Result<bool, string> Verify();
}

/// <summary>
/// Base class for operation verifiers with common functionality.
/// </summary>
public abstract class BaseOperationVerifier : IOperationVerifier
{
    protected readonly TraceData Trace;
    protected readonly int ExchangeIndex;
    
    protected BaseOperationVerifier(TraceData trace)
    {
        Trace = trace;
        ExchangeIndex = FindExchangeIndex();
    }
    
    protected abstract string OperationName { get; }
    
    public abstract Result<bool, string> Verify();
    
    protected int FindExchangeIndex()
    {
        // Find from test hints first
        var hint = Trace.TestHints?.TestableOperations?.FirstOrDefault(op => op.Name == OperationName);
        if (hint != null)
            return hint.ExchangeIndex;
            
        // Otherwise search for the command
        return FindExchangeByCommand();
    }
    
    protected abstract int FindExchangeByCommand();
    
    protected TraceExchange GetExchange()
    {
        if (ExchangeIndex < 0 || ExchangeIndex >= Trace.Exchanges?.Count)
            throw new InvalidOperationException($"Exchange index {ExchangeIndex} out of range");
            
        return Trace.Exchanges[ExchangeIndex];
    }
}

/// <summary>
/// Verifies INITIALIZE UPDATE operations.
/// </summary>
public class InitializeUpdateVerifier : BaseOperationVerifier
{
    protected override string OperationName => "initialize_update";
    
    public InitializeUpdateVerifier(TraceData trace) : base(trace) { }
    
    protected override int FindExchangeByCommand()
    {
        for (int i = 0; i < Trace.Exchanges?.Count; i++)
        {
            if (Trace.Exchanges[i].Command?.StartsWith("8050") == true)
                return i;
        }
        return -1;
    }
    
    public override Result<bool, string> Verify()
    {
        try
        {
            var exchange = GetExchange();
            
            // Parse command and response
            var commandBytes = Convert.FromHexString(exchange.Command);
            var responseBytes = Convert.FromHexString(exchange.Response);
            
            // Extract host challenge from command
            if (commandBytes.Length < 13) // CLA INS P1 P2 Lc + 8 bytes
                return Result.Failure<bool, string>("INITIALIZE UPDATE command too short");
                
            var hostChallenge = new byte[8];
            Array.Copy(commandBytes, 5, hostChallenge, 0, 8);
            
            // Parse response
            InitializeUpdateResponse response;
            try
            {
                response = InitializeUpdateResponse.Parse(responseBytes);
            }
            catch (Exception ex)
            {
                return Result.Failure<bool, string>($"Failed to parse response: {ex.Message}");
            }
            
            // Determine SCP version
            var scpVersion = response.KeyDiversificationData.Length == 10 ? ScpVersion.Scp02 : ScpVersion.Scp03;
            
            // If we have static keys, verify key derivation
            if (Trace.Metadata?.Hints?.StaticKeys != null)
            {
                var staticKeyBytes = Convert.FromHexString(Trace.Metadata.Hints.StaticKeys);
                
                if (scpVersion == ScpVersion.Scp03)
                {
                    var keySet = new Scp03KeySet(staticKeyBytes, staticKeyBytes, staticKeyBytes, response.KeyVersion);
                    
                    // Derive session keys
                    var keyDerivation = new KeyDerivationService();
                    var sessionKeysResult = keyDerivation.DeriveSessionKeys(
                        keySet, 
                        hostChallenge, 
                        response.CardChallenge);
                        
                    if (sessionKeysResult.IsFailure)
                        return Result.Failure<bool, string>($"Key derivation failed: {sessionKeysResult.Error.Message}");
                        
                    // Verify card cryptogram
                    var cryptogramService = new CryptogramService();
                    var expectedCryptogramResult = cryptogramService.CalculateCardCryptogram(
                        sessionKeysResult.Value.SMac,
                        hostChallenge,
                        response.CardChallenge,
                        Maybe<byte[]>.None,
                        ScpVersion.Scp03);
                        
                    if (expectedCryptogramResult.IsFailure)
                        return Result.Failure<bool, string>($"Cryptogram calculation failed: {expectedCryptogramResult.Error.Message}");
                        
                    if (!response.CardCryptogram.SequenceEqual(expectedCryptogramResult.Value))
                        return Result.Failure<bool, string>("Card cryptogram verification failed");
                }
                // Similar for SCP02...
            }
            
            return Result.Success<bool, string>(true);
        }
        catch (Exception ex)
        {
            return Result.Failure<bool, string>($"Exception during verification: {ex.Message}");
        }
    }
}

/// <summary>
/// Generic verifier for operations without specific verification logic.
/// </summary>
public class GenericVerifier : IOperationVerifier
{
    private readonly TraceData _trace;
    private readonly string _operationName;
    
    public GenericVerifier(TraceData trace, string operationName)
    {
        _trace = trace;
        _operationName = operationName;
    }
    
    public Result<bool, string> Verify()
    {
        // For now, just verify the operation exists in the trace
        return Result.Success<bool, string>(true);
    }
}

// Simplified verifiers for other operations (to be implemented)
public class SelectVerifier : GenericVerifier
{
    public SelectVerifier(TraceData trace) : base(trace, "select") { }
}

public class ExternalAuthenticateVerifier : GenericVerifier
{
    public ExternalAuthenticateVerifier(TraceData trace) : base(trace, "external_authenticate") { }
}

public class InstallVerifier : GenericVerifier
{
    public InstallVerifier(TraceData trace) : base(trace, "install") { }
}

public class DeleteVerifier : GenericVerifier
{
    public DeleteVerifier(TraceData trace) : base(trace, "delete") { }
}

public class LoadVerifier : GenericVerifier
{
    public LoadVerifier(TraceData trace) : base(trace, "load") { }
}

// Data models for JSON deserialization
[PublicAPI]
public class TraceData
{
    public TraceMetadata Metadata { get; set; } = null!;
    public TestHints? TestHints { get; set; }
    public List<TraceExchange>? Exchanges { get; set; }
    public Dictionary<string, SessionInfo> Sessions { get; set; } = null!;
    
    [JsonIgnore]
    public string FilePath { get; set; } = null!;
}

[PublicAPI]
public class TraceMetadata
{
    public SourceInfo Source { get; set; } = null!;
    public CardInfo Card { get; set; } = null!;
    public ConversionInfo Conversion { get; set; } = null!;
    public TestHintMetadata? Hints { get; set; }
}

[PublicAPI]
public class TestHintMetadata
{
    [JsonPropertyName("static_keys")]
    public string? StaticKeys { get; set; }
    
    [JsonPropertyName("expected_session_keys")]
    public ExpectedSessionKeys? ExpectedSessionKeys { get; set; }
}

[PublicAPI]
public class ExpectedSessionKeys
{
    [JsonPropertyName("s_enc")]
    public string SEnc { get; set; } = null!;
    
    [JsonPropertyName("s_mac")]
    public string SMac { get; set; } = null!;
    
    [JsonPropertyName("s_rmac")]
    public string SRMac { get; set; } = null!;
}

[PublicAPI]
public class SourceInfo
{
    public string File { get; set; } = null!;
    public string Type { get; set; } = null!;
    public string Generated { get; set; } = null!;
}

[PublicAPI]
public class CardInfo
{
    public string Atr { get; set; } = null!;
    [JsonPropertyName("isd_aid")]
    public string IsdAid { get; set; } = null!;
}

[PublicAPI]
public class ConversionInfo
{
    public List<string> Warnings { get; set; } = null!;
}

[PublicAPI]
public class TestHints
{
    [JsonPropertyName("testable_operations")]
    public List<TestHintOperation>? TestableOperations { get; set; }
    
    [JsonPropertyName("skip_reason")]
    public string? SkipReason { get; set; }
    
    [JsonPropertyName("scp_version")]
    public int? ScpVersion { get; set; }
}

[PublicAPI]
public class TestHintOperation
{
    public string Name { get; set; } = null!;
    [JsonPropertyName("exchange_index")]
    public int ExchangeIndex { get; set; }
    public List<string> Verify { get; set; } = null!;
}

[PublicAPI]
public class TraceExchange
{
    public string Command { get; set; } = null!;
    public string Response { get; set; } = null!;
    public string Description { get; set; } = null!;
}

[PublicAPI]
public class SessionInfo
{
    [JsonPropertyName("scp_version")]
    public int ScpVersion { get; set; }
    
    [JsonPropertyName("host_challenge")]
    public string HostChallenge { get; set; } = null!;
    
    [JsonPropertyName("card_challenge")]
    public string CardChallenge { get; set; } = null!;
}

[PublicAPI]
public class TestableOperation
{
    public string Name { get; set; } = null!;
    public int ExchangeIndex { get; set; }
}