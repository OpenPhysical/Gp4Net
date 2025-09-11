using System.Collections.Generic;
using System.Linq;
using Spectre.Console;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Pure functional renderer for semantic reader rows.
/// Transforms semantic row types into Spectre.Console table display.
/// Follows the same pattern as ApplicationTableRenderer.
/// </summary>
public static class ReaderTableRenderer
{
    /// <summary>
    /// Renders semantic reader rows to a Spectre.Console table.
    /// </summary>
    /// <param name="rows">Sequence of semantic reader rows</param>
    public static void RenderToTable(IEnumerable<ReaderTableBuilder.ReaderRow> rows)
    {
        var table = CreateTable();

        foreach (var row in rows)
        {
            RenderSemanticRow(table, row);
        }

        AnsiConsole.Write(table);
    }

    /// <summary>
    /// Renders semantic reader rows directly to console using pattern matching.
    /// </summary>
    /// <param name="rows">Sequence of semantic reader rows</param>
    public static void RenderToConsole(IEnumerable<ReaderTableBuilder.ReaderRow> rows)
    {
        foreach (var row in rows)
        {
            switch (row)
            {
                case ReaderTableBuilder.SectionHeaderRow(var title):
                    AnsiConsole.WriteLine();
                    AnsiConsole.MarkupLine($"[bold]{title}[/]");
                    break;

                case ReaderTableBuilder.SummaryRow(var message):
                    AnsiConsole.WriteLine();
                    AnsiConsole.MarkupLine($"[dim]{message}[/]");
                    break;

                case ReaderTableBuilder.InfoRow(var message, var severity):
                    string color = severity switch
                    {
                        "warning" => "yellow",
                        "error" => "red",
                        "success" => "green",
                        _ => "blue",
                    };
                    AnsiConsole.MarkupLine($"[{color}]{message}[/]");
                    break;

                case ReaderTableBuilder.ReaderDataRow dataRow:
                    // For console output, display as a simple line
                    AnsiConsole.MarkupLine($"{dataRow.Index}: {dataRow.Name}");
                    break;
            }
        }
    }

    /// <summary>
    /// Creates a properly configured table for reader display.
    /// </summary>
    private static Table CreateTable()
    {
        var table = new Table();

        // Reader table columns
        _ = table.AddColumn("Index");
        _ = table.AddColumn("Reader Name");

        return table;
    }

    /// <summary>
    /// Renders a single semantic row using pattern matching.
    /// </summary>
    private static void RenderSemanticRow(Table table, ReaderTableBuilder.ReaderRow row)
    {
        switch (row)
        {
            case ReaderTableBuilder.ReaderDataRow(var index, var name, var status):
                _ = table.AddRow(index, name);
                break;

            case ReaderTableBuilder.SectionHeaderRow(var title):
                // Add empty row before section header for spacing
                if (table.Rows.Count > 0)
                {
                    _ = table.AddRow("", "");
                }

                // Add header row with bold formatting
                _ = table.AddRow($"[bold]{title}[/]", "");
                break;

            case ReaderTableBuilder.SummaryRow(var message):
                // Summary rows are typically displayed separately after the table
                break;

            case ReaderTableBuilder.InfoRow(var message, var severity):
                // Info rows are typically displayed separately
                break;
        }
    }

    /// <summary>
    /// Renders only summary and info rows that should appear after the main table.
    /// </summary>
    public static void RenderPostTableRows(IEnumerable<ReaderTableBuilder.ReaderRow> rows)
    {
        var postTableRows = rows.Where(r =>
            r is ReaderTableBuilder.SummaryRow or ReaderTableBuilder.InfoRow
        );

        foreach (var row in postTableRows)
        {
            switch (row)
            {
                case ReaderTableBuilder.SummaryRow(var message):
                    AnsiConsole.WriteLine();
                    AnsiConsole.MarkupLine($"[dim]{message}[/]");
                    break;

                case ReaderTableBuilder.InfoRow(var message, var severity):
                    string color = severity switch
                    {
                        "warning" => "yellow",
                        "error" => "red",
                        "success" => "green",
                        _ => "blue",
                    };
                    AnsiConsole.MarkupLine($"[{color}]{message}[/]");
                    break;
            }
        }
    }
}
