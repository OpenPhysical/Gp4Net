using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Spectre.Console;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Pure functional renderer for semantic application rows.
/// Transforms semantic row types into Spectre.Console table display.
/// Follows the same pattern as CardInfoTableBuilder renderer.
/// </summary>
public static class ApplicationTableRenderer
{
    /// <summary>
    /// Renders semantic application rows to a Spectre.Console table.
    /// </summary>
    /// <param name="rows">Sequence of semantic application rows</param>
    /// <param name="showExtended">Whether to include extended columns</param>
    public static void RenderToTable(IEnumerable<ApplicationTableBuilder.ApplicationRow> rows, bool showExtended = false)
    {
        var table = CreateTable(showExtended);
        
        foreach (var row in rows)
        {
            RenderSemanticRow(table, row, showExtended);
        }
        
        AnsiConsole.Write(table);
    }

    /// <summary>
    /// Renders semantic application rows directly to console using pattern matching.
    /// </summary>
    /// <param name="rows">Sequence of semantic application rows</param>
    public static void RenderToConsole(IEnumerable<ApplicationTableBuilder.ApplicationRow> rows)
    {
        foreach (var row in rows)
        {
            switch (row)
            {
                case ApplicationTableBuilder.SectionHeaderRow(var title):
                    AnsiConsole.WriteLine();
                    AnsiConsole.MarkupLine($"[bold]{title}[/]");
                    break;
                    
                case ApplicationTableBuilder.SummaryRow(var message):
                    AnsiConsole.WriteLine();
                    AnsiConsole.MarkupLine($"[dim]{message}[/]");
                    break;
                    
                case ApplicationTableBuilder.InfoRow(var message, var severity):
                    var color = severity switch
                    {
                        "warning" => "yellow",
                        "error" => "red",
                        "success" => "green",
                        _ => "blue"
                    };
                    AnsiConsole.MarkupLine($"[{color}]{message}[/]");
                    break;
                    
                case ApplicationTableBuilder.ApplicationDataRow dataRow:
                    // For console output, display as a simple line
                    var version = dataRow.Version.GetValueOrDefault("");
                    var versionDisplay = !string.IsNullOrEmpty(version) ? $" v{version}" : "";
                    AnsiConsole.MarkupLine($"{dataRow.Type} {dataRow.Aid}{versionDisplay} - {dataRow.State}");
                    break;
            }
        }
    }

    /// <summary>
    /// Creates a properly configured table based on display options.
    /// </summary>
    private static Table CreateTable(bool showExtended)
    {
        var table = new Table();

        // Basic columns
        _ = table.AddColumn("Type");
        _ = table.AddColumn("AID");
        _ = table.AddColumn("State");
        _ = table.AddColumn("Privileges");
        
        // Extended columns
        if (showExtended)
        {
            _ = table.AddColumn("Version");
            _ = table.AddColumn("Assoc. SD");
        }
        
        return table;
    }

    /// <summary>
    /// Renders a single semantic row using pattern matching.
    /// </summary>
    private static void RenderSemanticRow(Table table, ApplicationTableBuilder.ApplicationRow row, bool showExtended)
    {
        switch (row)
        {
            case ApplicationTableBuilder.ApplicationDataRow(var type, var aid, var state, var privileges, var version, var associatedSd):
                var columns = new List<string> { type, aid, state, privileges };
                
                if (showExtended)
                {
                    columns.Add(version.GetValueOrDefault("-"));
                    columns.Add(associatedSd.GetValueOrDefault("-"));
                }

                _ = table.AddRow(columns.ToArray());
                break;
                
            case ApplicationTableBuilder.SectionHeaderRow(var title):
                // Add empty row before section header for spacing
                if (table.Rows.Count > 0)
                {
                    var emptyCols = Enumerable.Repeat("", table.Columns.Count).ToArray();
                    _ = table.AddRow(emptyCols);
                }
                
                // Add header row with bold formatting
                var headerCols = new string[table.Columns.Count];
                headerCols[0] = $"[bold]{title}[/]";
                for (int i = 1; i < headerCols.Length; i++)
                {
                    headerCols[i] = "";
                }
                _ = table.AddRow(headerCols);
                break;
                
            case ApplicationTableBuilder.SummaryRow(var message):
                // Summary rows are typically displayed separately after the table
                break;
                
            case ApplicationTableBuilder.InfoRow(var message, var severity):
                // Info rows are typically displayed separately
                break;
        }
    }

    /// <summary>
    /// Renders only summary and info rows that should appear after the main table.
    /// </summary>
    public static void RenderPostTableRows(IEnumerable<ApplicationTableBuilder.ApplicationRow> rows)
    {
        var postTableRows = rows.Where(r => r is ApplicationTableBuilder.SummaryRow or ApplicationTableBuilder.InfoRow);
        
        foreach (var row in postTableRows)
        {
            switch (row)
            {
                case ApplicationTableBuilder.SummaryRow(var message):
                    AnsiConsole.WriteLine();
                    AnsiConsole.MarkupLine($"[dim]{message}[/]");
                    break;
                    
                case ApplicationTableBuilder.InfoRow(var message, var severity):
                    var color = severity switch
                    {
                        "warning" => "yellow",
                        "error" => "red", 
                        "success" => "green",
                        _ => "blue"
                    };
                    AnsiConsole.MarkupLine($"[{color}]{message}[/]");
                    break;
            }
        }
    }
}