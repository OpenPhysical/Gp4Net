using System;
using Gp4Net.Domain;
using JetBrains.Annotations;
using Spectre.Console;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Default implementation of IDisplay using Spectre.Console.
/// </summary>
[PublicAPI]
public class ConsoleDisplay : IDisplay
{
    private readonly bool _verboseMode;
    private readonly IAnsiConsole _console;

    public ConsoleDisplay(bool verboseMode = false)
        : this(AnsiConsole.Console, verboseMode) { }

    public ConsoleDisplay(IAnsiConsole console, bool verboseMode = false)
    {
        _console = console;
        _verboseMode = verboseMode;
    }

    public void Success(string message)
    {
        _console.MarkupLine($"[green]✓ {message}[/]");
    }

    public void Error(string message)
    {
        _console.MarkupLine($"[red]✗ {message}[/]");
    }

    public void Warning(string message)
    {
        _console.MarkupLine($"[yellow]⚠ {message}[/]");
    }

    public void Info(string message)
    {
        _console.MarkupLine($"[blue]ℹ {message}[/]");
    }

    public void Verbose(string message)
    {
        if (_verboseMode)
        {
            _console.MarkupLine($"[dim]🔍 {message}[/]");
        }
    }

    public void Exception(Exception exception)
    {
        _console.WriteException(exception);
    }

    public void CardInfo(Atr atr)
    {
        _console.MarkupLine($"[green]Card ATR:[/] {atr}");
    }

    public void Markup(string markup)
    {
        _console.MarkupLine(markup);
    }
}
