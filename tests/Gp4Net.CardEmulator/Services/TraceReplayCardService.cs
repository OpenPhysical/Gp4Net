using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Gp4Net.CardEmulator.Cards;
using Gp4Net.CardEmulator.Core;
using Gp4Net.CardEmulator.Trace;

namespace Gp4Net.CardEmulator.Services;

/// <summary>
/// Card service that replays APDU traces for testing.
/// </summary>
public class TraceReplayCardService : VirtualCardService
{
    private readonly GpShellTraceParser _parser;
    private TraceReplayCard? _currentCard;
    private string _readerName = "Trace Replay Reader";

    /// <summary>
    /// Gets the current trace replay card if loaded.
    /// </summary>
    public TraceReplayCard? CurrentCard => _currentCard;

    /// <summary>
    /// Gets or sets options for trace replay.
    /// </summary>
    public TraceReplayOptions ReplayOptions { get; set; } = new TraceReplayOptions();

    /// <summary>
    /// Initializes a new instance of the TraceReplayCardService class.
    /// </summary>
    public TraceReplayCardService()
        : base()
    {
        _parser = new GpShellTraceParser();
    }

    /// <summary>
    /// Loads a trace from a file and creates a virtual card.
    /// </summary>
    public void LoadTraceFromFile(string filePath, string? readerName = null)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException($"Trace file not found: {filePath}", filePath);

        var trace = _parser.ParseFile(filePath);
        LoadTrace(trace, readerName);
    }

    /// <summary>
    /// Loads a trace from a string and creates a virtual card.
    /// </summary>
    public void LoadTraceFromString(string traceContent, string? readerName = null)
    {
        if (string.IsNullOrWhiteSpace(traceContent))
            throw new ArgumentException("Trace content cannot be empty", nameof(traceContent));

        var trace = _parser.ParseString(traceContent);
        LoadTrace(trace, readerName);
    }

    /// <summary>
    /// Loads a pre-parsed trace and creates a virtual card.
    /// </summary>
    public void LoadTrace(ApduTrace trace, string? readerName = null)
    {
        ArgumentNullException.ThrowIfNull(trace);

        // Remove any existing trace replay readers
        RemoveTraceReplayReaders();

        // Use reader name from trace metadata if available
        _readerName = readerName ?? trace.Metadata.ReaderName ?? "Trace Replay Reader";

        // Create replay card
        _currentCard = new TraceReplayCard(trace, ReplayOptions.StrictMode);

        // Create virtual reader and insert card
        var reader = new VirtualCardReader(_readerName);
        reader.InsertCard(_currentCard);

        ReaderManager.AddReader(reader);
    }

    /// <summary>
    /// Gets the trace comparison results for the current session.
    /// </summary>
    public TraceComparisonResult CompareWithOriginalTrace()
    {
        if (_currentCard == null)
            throw new InvalidOperationException("No trace loaded");

        return new TraceComparisonResult(_currentCard);
    }

    /// <summary>
    /// Transmits an APDU command (compatibility method for tests).
    /// </summary>
    /// <param name="command">The APDU command bytes.</param>
    /// <returns>The response from the virtual card.</returns>
    public CardResponse Transmit(byte[] command)
    {
        return SendCommand(command);
    }

    /// <summary>
    /// Removes all trace replay readers.
    /// </summary>
    public void RemoveTraceReplayReaders()
    {
        var replayReaders = ReaderManager
            .GetReaderNames()
            .Where(r => r.StartsWith("Trace Replay", StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var reader in replayReaders)
        {
            ReaderManager.RemoveReader(reader);
        }

        _currentCard = null;
    }

    /// <summary>
    /// Creates a detailed report of the executed vs expected exchanges.
    /// </summary>
    public string GenerateComparisonReport()
    {
        if (_currentCard == null)
            return "No trace loaded";

        var result = CompareWithOriginalTrace();
        return result.GenerateReport();
    }
}

/// <summary>
/// Results of comparing executed exchanges with original trace.
/// </summary>
public class TraceComparisonResult
{
    private readonly TraceReplayCard _card;

    /// <summary>
    /// Gets the number of executed exchanges.
    /// </summary>
    public int ExecutedCount => _card.ExecutedExchanges.Count;

    /// <summary>
    /// Gets whether all exchanges matched.
    /// </summary>
    public bool AllMatched { get; private set; } = true;

    /// <summary>
    /// Gets the list of mismatches.
    /// </summary>
    public List<TraceMismatch> Mismatches { get; } = new List<TraceMismatch>();

    public TraceComparisonResult(TraceReplayCard card)
    {
        _card = card ?? throw new ArgumentNullException(nameof(card));
        AnalyzeExchanges();
    }

    private void AnalyzeExchanges()
    {
        // For now, just check if responses were found
        // Could be enhanced to compare with original trace order
        foreach (var exchange in _card.ExecutedExchanges)
        {
            if (exchange.Response?.StatusWord == 0x6D00)
            {
                AllMatched = false;
                Mismatches.Add(
                    new TraceMismatch
                    {
                        Index = Array.IndexOf(_card.ExecutedExchanges.ToArray(), exchange),
                        Command = exchange.GetCommandString(),
                        Issue = "Command not found in trace",
                    }
                );
            }
        }
    }

    /// <summary>
    /// Generates a detailed comparison report.
    /// </summary>
    public string GenerateReport()
    {
        var report = new StringWriter();

        report.WriteLine("=== Trace Replay Comparison Report ===");
        report.WriteLine($"Executed exchanges: {ExecutedCount}");
        report.WriteLine($"All matched: {AllMatched}");

        if (Mismatches.Count > 0)
        {
            report.WriteLine($"\nMismatches found: {Mismatches.Count}");
            foreach (var mismatch in Mismatches)
            {
                report.WriteLine($"\n[{mismatch.Index}] {mismatch.Issue}");
                report.WriteLine($"  Command: {mismatch.Command}");
                if (!string.IsNullOrEmpty(mismatch.ExpectedResponse))
                {
                    report.WriteLine($"  Expected: {mismatch.ExpectedResponse}");
                }
                if (!string.IsNullOrEmpty(mismatch.ActualResponse))
                {
                    report.WriteLine($"  Actual: {mismatch.ActualResponse}");
                }
            }
        }

        report.WriteLine("\n=== Exchange Details ===");
        foreach (var exchange in _card.ExecutedExchanges)
        {
            var index = Array.IndexOf(_card.ExecutedExchanges.ToArray(), exchange);
            report.WriteLine($"\n[{index}] {exchange.GetCommandString()}");
            report.WriteLine($"     {exchange.GetResponseString()}");
        }

        return report.ToString();
    }
}

/// <summary>
/// Represents a mismatch between expected and actual APDU exchanges.
/// </summary>
public class TraceMismatch
{
    /// <summary>
    /// Gets or sets the exchange index.
    /// </summary>
    public int Index { get; set; }

    /// <summary>
    /// Gets or sets the command that caused the mismatch.
    /// </summary>
    public string Command { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the description of the issue.
    /// </summary>
    public string Issue { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the expected response if applicable.
    /// </summary>
    public string ExpectedResponse { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the actual response if applicable.
    /// </summary>
    public string ActualResponse { get; set; } = string.Empty;
}