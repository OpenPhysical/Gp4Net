using System;
using JetBrains.Annotations;
using Spectre.Console;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Default implementation of IDisplayService using Spectre.Console.
/// </summary>
[PublicAPI]
public class DisplayService : IDisplayService
{
    private readonly bool _verboseMode;

    public DisplayService(bool verboseMode = false)
    {
        _verboseMode = verboseMode;
    }

    public void Success(string message)
    {
        AnsiConsole.MarkupLine($"[green]✓ {message}[/]");
    }

    public void Error(string message)
    {
        AnsiConsole.MarkupLine($"[red]✗ {message}[/]");
    }

    public void Warning(string message)
    {
        AnsiConsole.MarkupLine($"[yellow]⚠ {message}[/]");
    }

    public void Info(string message)
    {
        AnsiConsole.MarkupLine($"[blue]ℹ {message}[/]");
    }

    public void Verbose(string message)
    {
        if (_verboseMode)
        {
            AnsiConsole.MarkupLine($"[dim]🔍 {message}[/]");
        }
    }

    public void Exception(Exception exception)
    {
        AnsiConsole.WriteException(exception);
    }

    public void CardInfo(byte[] atr)
    {
        if (atr != null)
        {
            AnsiConsole.MarkupLine($"[green]Card ATR:[/] {Convert.ToHexString(atr)}");
        }
    }

    public void Markup(string markup)
    {
        AnsiConsole.MarkupLine(markup);
    }
}