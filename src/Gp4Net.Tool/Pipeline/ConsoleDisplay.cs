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
        : this(CreateStandardErrorConsole(), verboseMode) { }

    public ConsoleDisplay(IAnsiConsole console, bool verboseMode = false)
    {
        _console = console;
        _verboseMode = verboseMode;
    }

    public void Success(string message)
    {
        _console.MarkupLine($"[green]✓ {Spectre.Console.Markup.Escape(message)}[/]");
    }

    public void Error(string message)
    {
        _console.MarkupLine($"[red]✗ {Spectre.Console.Markup.Escape(message)}[/]");
    }

    public void Warning(string message)
    {
        _console.MarkupLine($"[yellow]⚠ {Spectre.Console.Markup.Escape(message)}[/]");
    }

    public void Info(string message)
    {
        _console.MarkupLine($"[blue]ℹ {Spectre.Console.Markup.Escape(message)}[/]");
    }

    public void Verbose(string message)
    {
        if (_verboseMode)
        {
            _console.MarkupLine($"[dim]🔍 {Spectre.Console.Markup.Escape(message)}[/]");
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

    private static IAnsiConsole CreateStandardErrorConsole() =>
        AnsiConsole.Create(
            new AnsiConsoleSettings { Out = new AnsiConsoleOutput(Console.Error) }
        );
}
