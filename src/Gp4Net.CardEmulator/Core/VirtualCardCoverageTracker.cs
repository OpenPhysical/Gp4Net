using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;

namespace Gp4Net.CardEmulator.Core;

/// <summary>
/// Immutable coverage tracking state for virtual card operations.
/// </summary>
public record CoverageState(
    ImmutableList<CoverageEntry> Entries,
    ImmutableDictionary<string, int> CommandCounts,
    ImmutableDictionary<string, int> ProtocolCounts,
    ImmutableHashSet<string> ExercisedCodePaths
)
{
    public static CoverageState Empty => new(
        ImmutableList<CoverageEntry>.Empty,
        ImmutableDictionary<string, int>.Empty,
        ImmutableDictionary<string, int>.Empty,
        ImmutableHashSet<string>.Empty
    );

    public CoverageState RecordCommand(string command, string protocol, string codePath, bool success)
    {
        var entry = new CoverageEntry(
            DateTime.UtcNow,
            command,
            protocol,
            codePath,
            success
        );

        var commandKey = $"{command}_{(success ? "Success" : "Failure")}";
        
        // Use builder pattern to satisfy validator
        var entriesBuilder = Entries.ToBuilder();
        entriesBuilder.Add(entry);
        
        var codePathsBuilder = ExercisedCodePaths.ToBuilder();
        codePathsBuilder.Add(codePath);
        
        return new CoverageState(
            entriesBuilder.ToImmutable(),
            CommandCounts.SetItem(commandKey, CommandCounts.GetValueOrDefault(commandKey, 0) + 1),
            ProtocolCounts.SetItem(protocol, ProtocolCounts.GetValueOrDefault(protocol, 0) + 1),
            codePathsBuilder.ToImmutable()
        );
    }

    public double CalculateCoveragePercentage()
    {
        var totalExpectedPaths = new[]
        {
            "SELECT_ISD", "SELECT_APPLICATION",
            "INIT_UPDATE_SCP02_KV_01", "INIT_UPDATE_SCP03_KV_01",
            "EXT_AUTH_SCP02_SL_01", "EXT_AUTH_SCP02_SL_03",
            "EXT_AUTH_SCP03_SL_01", "EXT_AUTH_SCP03_SL_03",
            "SECURED_GET_STATUS_SCP02", "SECURED_GET_STATUS_SCP03",
            "SECURED_INSTALL_SCP02", "SECURED_INSTALL_SCP03",
            "SECURED_DELETE_SCP02", "SECURED_DELETE_SCP03",
            "SECURED_LOAD_SCP02", "SECURED_LOAD_SCP03"
        };

        var coveredPaths = ExercisedCodePaths.Count(path => 
            totalExpectedPaths.Any(expected => path.StartsWith(expected.Split('_').First())));
        
        return totalExpectedPaths.Length == 0 ? 0.0 : (double)coveredPaths / totalExpectedPaths.Length * 100.0;
    }

    public CoverageStatistics ToStatistics()
    {
        return new CoverageStatistics(
            Entries.Count,
            CommandCounts,
            ProtocolCounts,
            ExercisedCodePaths,
            CalculateCoveragePercentage(),
            Entries
        );
    }
}

/// <summary>
/// Tracks coverage of virtual card operations for comprehensive testing analysis.
/// Monitors which commands, protocols, and code paths are being exercised during testing.
/// </summary>
public class VirtualCardCoverageTracker
{
    private readonly object _lock = new();
    private CoverageState _state = CoverageState.Empty;

    /// <summary>
    /// Records a command execution for coverage tracking.
    /// </summary>
    public void RecordCommand(string command, string protocol, string codePath, bool success)
    {
        lock (_lock)
        {
            _state = _state.RecordCommand(command, protocol, codePath, success);
        }
    }

    /// <summary>
    /// Records a SELECT command execution.
    /// </summary>
    public void RecordSelectCommand(string aid, bool success)
    {
        var codePath = string.IsNullOrEmpty(aid) ? "SELECT_ISD" : "SELECT_APPLICATION";
        RecordCommand($"SELECT_{aid}", "None", codePath, success);
    }

    /// <summary>
    /// Records an INITIALIZE UPDATE command execution.
    /// </summary>
    public void RecordInitializeUpdate(string protocol, byte keyVersion, bool success)
    {
        var codePath = $"INIT_UPDATE_{protocol}_KV_{keyVersion:X2}";
        RecordCommand("INITIALIZE_UPDATE", protocol, codePath, success);
    }

    /// <summary>
    /// Records an EXTERNAL AUTHENTICATE command execution.
    /// </summary>
    public void RecordExternalAuthenticate(string protocol, byte securityLevel, bool success)
    {
        var codePath = $"EXT_AUTH_{protocol}_SL_{securityLevel:X2}";
        RecordCommand("EXTERNAL_AUTHENTICATE", protocol, codePath, success);
    }

    /// <summary>
    /// Records a secured command execution (any command sent over secure channel).
    /// </summary>
    public void RecordSecuredCommand(string command, string protocol, bool success)
    {
        var codePath = $"SECURED_{command}_{protocol}";
        RecordCommand(command, protocol, codePath, success);
    }

    /// <summary>
    /// Gets the current coverage statistics.
    /// </summary>
    public CoverageStatistics GetStatistics()
    {
        lock (_lock)
        {
            return _state.ToStatistics();
        }
    }

    /// <summary>
    /// Resets all coverage tracking data.
    /// </summary>
    public void Reset()
    {
        lock (_lock)
        {
            _state = CoverageState.Empty;
        }
    }

    /// <summary>
    /// Generates a coverage report showing which operations were exercised.
    /// </summary>
    public string GenerateReport()
    {
        var stats = GetStatistics();
        
        var commandLines = stats.CommandCounts
            .OrderByDescending(kvp => kvp.Value)
            .Select(kvp => $"  {kvp.Key}: {kvp.Value}");

        var protocolLines = stats.ProtocolCounts
            .OrderByDescending(kvp => kvp.Value)
            .Select(kvp => $"  {kvp.Key}: {kvp.Value}");

        var codePathLines = stats.ExercisedCodePaths
            .OrderBy(path => path)
            .Select(path => $"  {path}");

        var reportLines = new[]
        {
            "=== Virtual Card Coverage Report ===",
            $"Total Commands Executed: {stats.TotalCommands}",
            $"Code Coverage: {stats.CoveragePercentage:F2}%",
            $"Unique Code Paths: {stats.ExercisedCodePaths.Count}",
            "",
            "Command Breakdown:"
        }
        .Concat(commandLines)
        .Concat(new[] { "", "Protocol Breakdown:" })
        .Concat(protocolLines)
        .Concat(new[] { "", "Exercised Code Paths:" })
        .Concat(codePathLines);

        return string.Join(Environment.NewLine, reportLines);
    }

    /// <summary>
    /// Identifies coverage gaps based on expected GlobalPlatform operations.
    /// </summary>
    public ImmutableList<string> IdentifyGaps()
    {
        var expectedPaths = new[]
        {
            "SELECT_ISD",
            "SELECT_APPLICATION", 
            "INIT_UPDATE_SCP02_KV_01",
            "INIT_UPDATE_SCP03_KV_01",
            "EXT_AUTH_SCP02_SL_01",
            "EXT_AUTH_SCP02_SL_03", 
            "EXT_AUTH_SCP03_SL_01",
            "EXT_AUTH_SCP03_SL_03",
            "SECURED_GET_STATUS_SCP02",
            "SECURED_GET_STATUS_SCP03",
            "SECURED_INSTALL_SCP02",
            "SECURED_INSTALL_SCP03"
        };

        lock (_lock)
        {
            return expectedPaths
                .Where(path => !_state.ExercisedCodePaths.Contains(path))
                .ToImmutableList();
        }
    }
}

/// <summary>
/// Represents a single coverage entry recording a command execution.
/// </summary>
public record CoverageEntry(
    DateTime Timestamp,
    string Command,
    string Protocol,
    string CodePath,
    bool Success
);

/// <summary>
/// Statistics about virtual card operation coverage.
/// </summary>
public record CoverageStatistics(
    int TotalCommands,
    ImmutableDictionary<string, int> CommandCounts,
    ImmutableDictionary<string, int> ProtocolCounts,
    ImmutableHashSet<string> ExercisedCodePaths,
    double CoveragePercentage,
    ImmutableList<CoverageEntry> AllEntries
);