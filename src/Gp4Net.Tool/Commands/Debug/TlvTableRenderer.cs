using System.Collections.Generic;
using Spectre.Console;

namespace Gp4Net.Tool.Commands.Debug;

/// <summary>
/// Pure functional renderer for semantic TLV rows.
/// Transforms semantic row types into console display with proper indentation.
/// Preserves hierarchical structure while using functional composition.
/// </summary>
public static class TlvTableRenderer
{
    /// <summary>
    /// Renders semantic TLV rows to console with hierarchical formatting.
    /// </summary>
    /// <param name="rows">Sequence of semantic TLV rows</param>
    public static void RenderToConsole(IEnumerable<TlvTableBuilder.TlvRow> rows)
    {
        foreach (var row in rows)
        {
            RenderSemanticRow(row);
        }
    }

    /// <summary>
    /// Renders a single semantic row using pattern matching.
    /// </summary>
    private static void RenderSemanticRow(TlvTableBuilder.TlvRow row)
    {
        switch (row)
        {
            case TlvTableBuilder.TlvDataRow(var elementIndex, var depth, var tagInfo, var lengthInfo, var content, var asciiContent, var rawBytes):
                var indent = new string(' ', depth * 2);
                
                // Main element info
                AnsiConsole.MarkupLine($"{indent}[cyan]Element {elementIndex}[/]: [white]{tagInfo}[/]");
                AnsiConsole.MarkupLine($"{indent}  Length: {lengthInfo}");
                
                // Content display
                if (content.HasValue)
                {
                    var contentColor = content.Value.Contains("(empty)") ? "dim" : "yellow";
                    AnsiConsole.MarkupLine($"{indent}  [{contentColor}]{content.Value}[/]");
                }
                
                // ASCII content if available
                if (asciiContent.HasValue)
                {
                    AnsiConsole.MarkupLine($"{indent}  [dim]{asciiContent.Value}[/]");
                }
                
                // Raw bytes if available
                if (rawBytes.HasValue)
                {
                    AnsiConsole.MarkupLine($"{indent}  [dim]{rawBytes.Value}[/]");
                }
                break;

            case TlvTableBuilder.NestedTlvHeaderRow(var depth, var message):
                var nestedIndent = new string(' ', depth * 2);
                AnsiConsole.MarkupLine($"{nestedIndent}[magenta]{message}[/]");
                break;

            case TlvTableBuilder.TagInterpretationRow(var depth, var interpretation):
                var interpIndent = new string(' ', depth * 2);
                AnsiConsole.MarkupLine($"{interpIndent}[green]{interpretation}[/]");
                break;

            case TlvTableBuilder.SummaryRow(var message):
                AnsiConsole.MarkupLine($"[green]{message}[/]");
                break;

            case TlvTableBuilder.InfoRow(var message, var severity):
                var color = severity switch
                {
                    "warning" => "yellow",
                    "error" => "red",
                    "success" => "green",
                    _ => "dim"
                };
                AnsiConsole.MarkupLine($"[{color}]{message}[/]");
                AnsiConsole.WriteLine();
                break;
        }
    }

    /// <summary>
    /// Renders TLV rows in table format (simplified view).
    /// </summary>
    public static void RenderToTable(IEnumerable<TlvTableBuilder.TlvRow> rows)
    {
        var table = new Table();
        _ = table.AddColumn("Element");
        _ = table.AddColumn("Tag");
        _ = table.AddColumn("Length");
        _ = table.AddColumn("Content");

        foreach (var row in rows)
        {
            switch (row)
            {
                case TlvTableBuilder.TlvDataRow(var elementIndex, var depth, var tagInfo, var lengthInfo, var content, var asciiContent, var rawBytes):
                    var indent = new string(' ', depth * 2);
                    _ = table.AddRow(
                        $"{indent}{elementIndex}",
                        StripMarkup(tagInfo),
                        lengthInfo,
                        StripMarkup(content.GetValueOrDefault("-"))
                    );
                    break;

                case TlvTableBuilder.NestedTlvHeaderRow(var depth, var message):
                    var nestedIndent = new string(' ', depth * 2);
                    _ = table.AddRow(
                        "",
                        $"{nestedIndent}Nested TLV",
                        "",
                        ""
                    );
                    break;

                case TlvTableBuilder.TagInterpretationRow(var depth, var interpretation):
                    var interpIndent = new string(' ', depth * 2);
                    _ = table.AddRow(
                        "",
                        $"{interpIndent}Interpretation",
                        "",
                        StripMarkup(interpretation)
                    );
                    break;
                    
                case TlvTableBuilder.SummaryRow(var summaryMessage):
                case TlvTableBuilder.InfoRow(var infoMessage, var severity):
                    // Skip summary/info rows in table format
                    break;
            }
        }

        AnsiConsole.Write(table);
    }

    /// <summary>
    /// Strips markup from text for table display.
    /// </summary>
    private static string StripMarkup(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text;
        }

        // Simple markup removal - replace [color]text[/] with text
        var result = text;
        while (true)
        {
            var start = result.IndexOf('[');
            var end = result.IndexOf(']', start + 1);
            if (start == -1 || end == -1) break;
            
            var tag = result.Substring(start, end - start + 1);
            if (tag == "[/]")
            {
                result = result.Remove(start, tag.Length);
            }
            else
            {
                result = result.Remove(start, tag.Length);
            }
        }
        
        return result;
    }
}