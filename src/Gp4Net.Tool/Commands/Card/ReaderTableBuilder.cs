using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Pure functional table builder for card reader information display.
/// Uses semantic row types and functional composition per CLAUDE.md patterns.
/// Eliminates imperative table building and ensures consistent formatting.
/// </summary>
public static class ReaderTableBuilder
{
    #region Semantic Row Types

    /// <summary>
    /// Base type for all reader display rows, enabling type-safe UI composition.
    /// </summary>
    public abstract record ReaderRow;

    /// <summary>
    /// Row displaying reader information with standard columns.
    /// </summary>
    public record ReaderDataRow(
        string Index,
        string Name,
        string Status = "Available"
    ) : ReaderRow;

    /// <summary>
    /// Header row indicating the start of a section.
    /// </summary>
    public record SectionHeaderRow(string Title) : ReaderRow;

    /// <summary>
    /// Summary information row.
    /// </summary>
    public record SummaryRow(string Message) : ReaderRow;

    /// <summary>
    /// Warning or informational message row.
    /// </summary>
    public record InfoRow(string Message, string Severity = "info") : ReaderRow;

    #endregion

    /// <summary>
    /// Main entry point to build all reader information rows using functional composition.
    /// Returns semantic row types that can be rendered by any UI framework.
    /// </summary>
    /// <param name="readers">List of reader names to display</param>
    /// <param name="showSummary">Whether to include summary information</param>
    /// <returns>Sequence of semantic reader rows</returns>
    public static IEnumerable<ReaderRow> BuildReaderRows(
        IReadOnlyList<string> readers,
        bool showSummary = true)
    {
        if (readers.Count == 0)
        {
            yield return new InfoRow("No card readers found", "warning");
            yield break;
        }

        // Build reader data rows
        for (var i = 0; i < readers.Count; i++)
        {
            yield return new ReaderDataRow(
                Index: i.ToString(),
                Name: readers[i],
                Status: "Available"
            );
        }

        if (showSummary)
        {
            yield return new SummaryRow($"Total: {readers.Count} reader(s) found");
        }
    }

    /// <summary>
    /// Exports readers to JSON format using pure functions.
    /// </summary>
    public static string ToJson(IReadOnlyList<string> readers)
    {
        var data = readers.Select((reader, index) => new
        {
            index = index,
            name = reader,
            status = "Available"
        });

        return JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>
    /// Exports readers to CSV format using pure functions.
    /// </summary>
    public static string ToCsv(IReadOnlyList<string> readers)
    {
        var lines = new List<string>
        {
            "Index,Name,Status"
        };

        lines.AddRange(readers.Select((reader, index) =>
            $"{index},\"{reader}\",Available"
        ));

        return string.Join(Environment.NewLine, lines);
    }
}