using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Tool.Commands.Card;
using Spectre.Console;

namespace Gp4Net.Tool.Services;

/// <summary>
/// Tool service for displaying card information with consistent formatting.
/// Contains reusable display logic for card info across commands.
/// </summary>
public static class CardInfoDisplayService
{
    /// <summary>
    /// Displays card information table with semantic row rendering.
    /// </summary>
    /// <param name="rows">Semantic table rows from CardInfoTableBuilder</param>
    /// <param name="title">Panel title</param>
    /// <param name="borderColor">Panel border color</param>
    public static void DisplayCardInfoTable(
        IEnumerable<CardInfoTableBuilder.TableRow> rows,
        string title = "Card Information",
        Maybe<Color> borderColor = default
    )
    {
        Table table = new Table()
            .AddColumn(new TableColumn("Property").NoWrap())
            .AddColumn(new TableColumn("Value"));

        // Render semantic rows using functional composition
        RenderSemanticRows(table, rows);

        // Display with consistent styling
        var panel = new Panel(table).Header($"[bold]{title}[/]");
        var styledPanel = borderColor.Match(
            color => panel.BorderColor(color),
            () => panel.BorderColor(Color.Aqua)
        );
        AnsiConsole.Write(styledPanel);
    }

    /// <summary>
    /// Displays keyset suggestions when secure channel is not established.
    /// </summary>
    /// <param name="isSecureChannelEstablished">Whether secure channel is active</param>
    public static void DisplayKeysetSuggestions(bool isSecureChannelEstablished)
    {
        if (isSecureChannelEstablished)
            return;

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[yellow]More information is available with a secure channel.[/]");
        AnsiConsole.MarkupLine("[dim]Try: gp4net card info --keyset <KEYSET_NAME>[/]");
    }

    /// <summary>
    /// Pure function to render semantic rows to Spectre.Console table using functional composition.
    /// Uses pattern matching to apply appropriate formatting per row type.
    /// </summary>
    private static void RenderSemanticRows(
        Table table,
        IEnumerable<CardInfoTableBuilder.TableRow> rows
    )
    {
        // Use functional composition with Select to transform rows to side effects, then execute
        List<Table> _ = [.. rows.Select(row => RenderSingleRow(table, row))]; // Execute the side effects
    }

    /// <summary>
    /// Renders a single semantic row to the table using pattern matching.
    /// </summary>
    private static Table RenderSingleRow(Table table, CardInfoTableBuilder.TableRow row)
    {
        return row switch
        {
            CardInfoTableBuilder.PropertyRow(var name, var value) => table.AddRow(name, value),

            CardInfoTableBuilder.SectionHeader(var title) => table
                .AddEmptyRow()
                .AddRow($"[bold]{title}[/]", ""),

            CardInfoTableBuilder.StatusRow(var name, var isAvailable, var details) => table.AddRow(
                $"{(isAvailable ? "[green]✓[/]" : "[red]✗[/]")} {name}",
                details.Length > 0 ? details
                    : isAvailable ? "Available"
                    : "Not Available"
            ),

            CardInfoTableBuilder.ErrorRow(var name, var message) => table.AddRow(
                $"[red]{name}[/]",
                $"[red]{message}[/]"
            ),

            CardInfoTableBuilder.InfoRow(var message) => table.AddRow("", $"[dim]{message}[/]"),

            _ => table,
        };
    }
}
