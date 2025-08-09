using System;
using System.Collections.Generic;
using Spectre.Console;

namespace Gp4Net.Tool.Commands.Debug;

/// <summary>
/// Pure functional renderer for semantic ASN.1 rows.
/// Transforms semantic row types into console display with proper indentation.
/// Preserves hierarchical structure while using functional composition.
/// </summary>
public static class Asn1TableRenderer
{
    /// <summary>
    /// Renders semantic ASN.1 rows to console with hierarchical formatting.
    /// </summary>
    /// <param name="rows">Sequence of semantic ASN.1 rows</param>
    public static void RenderToConsole(IEnumerable<Asn1TableBuilder.Asn1Row> rows)
    {
        foreach (var row in rows)
        {
            RenderSemanticRow(row);
        }
    }

    /// <summary>
    /// Renders a single semantic row using pattern matching.
    /// </summary>
    private static void RenderSemanticRow(Asn1TableBuilder.Asn1Row row)
    {
        switch (row)
        {
            case Asn1TableBuilder.Asn1DataRow(var depth, var offset, var typeInfo, var value, var rawBytes):
                var indent = new string(' ', depth * 2);
                
                // Build the main line with offset and type info
                var mainLine = string.IsNullOrEmpty(offset) 
                    ? $"{indent}{FormatTypeInfo(typeInfo)}"
                    : $"{indent}[cyan]{offset}[/] {FormatTypeInfo(typeInfo)}";
                    
                AnsiConsole.MarkupLine(mainLine);
                
                // Show raw bytes if available
                if (rawBytes.HasValue)
                {
                    AnsiConsole.MarkupLine($"{indent}  [dim]{rawBytes.Value}[/]");
                }
                
                // Show value if available
                if (value.HasValue)
                {
                    AnsiConsole.MarkupLine($"{indent}  [yellow]{value.Value}[/]");
                }
                break;

            case Asn1TableBuilder.ContainerHeaderRow(var depth, var containerType, var elementCount):
                var containerIndent = new string(' ', depth * 2);
                AnsiConsole.MarkupLine($"{containerIndent}  [blue]{containerType} with {elementCount} elements:[/]");
                break;

            case Asn1TableBuilder.ElementHeaderRow(var depth, var elementIndex, var description):
                var elementIndent = new string(' ', depth * 2);
                AnsiConsole.MarkupLine($"{elementIndent}[dim]{description}[/]");
                break;

            case Asn1TableBuilder.NestedAsn1HeaderRow(var depth, var message):
                var nestedIndent = new string(' ', depth * 2);
                AnsiConsole.MarkupLine($"{nestedIndent}[magenta]{message}[/]");
                break;

            case Asn1TableBuilder.SummaryRow(var message):
                AnsiConsole.MarkupLine($"[green]{message}[/]");
                break;

            case Asn1TableBuilder.InfoRow(var message, var severity):
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
    /// Formats type information with appropriate colors and structure.
    /// </summary>
    private static string FormatTypeInfo(string typeInfo)
    {
        // Parse the type info to apply proper coloring
        // Format: "Universal DerSequence (tag=30, constructed=True, length=123)"
        
        var parts = typeInfo.Split(' ', 3);
        if (parts.Length < 2)
        {
            return $"[white]{typeInfo}[/]";
        }

        var tagClass = parts[0];
        var typeName = parts[1];
        var details = parts.Length > 2 ? parts[2] : "";

        return $"[white]{tagClass}[/] [green]{typeName}[/] {details}";
    }

    /// <summary>
    /// Renders ASN.1 rows in table format (simplified view).
    /// </summary>
    public static void RenderToTable(IEnumerable<Asn1TableBuilder.Asn1Row> rows)
    {
        var table = new Table();
        table.AddColumn("Offset");
        table.AddColumn("Type");
        table.AddColumn("Value");

        foreach (var row in rows)
        {
            switch (row)
            {
                case Asn1TableBuilder.Asn1DataRow(var depth, var offset, var typeInfo, var value, var rawBytes):
                    var indent = new string(' ', depth * 2);
                    table.AddRow(
                        offset,
                        $"{indent}{StripMarkup(typeInfo)}",
                        StripMarkup(value.GetValueOrDefault("-"))
                    );
                    break;

                case Asn1TableBuilder.ContainerHeaderRow(var depth, var containerType, var elementCount):
                    var containerIndent = new string(' ', depth * 2);
                    table.AddRow(
                        "",
                        $"{containerIndent}{containerType}",
                        $"{elementCount} elements"
                    );
                    break;
                    
                case Asn1TableBuilder.SummaryRow(var summaryMessage):
                case Asn1TableBuilder.InfoRow(var infoMessage, var severity):
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