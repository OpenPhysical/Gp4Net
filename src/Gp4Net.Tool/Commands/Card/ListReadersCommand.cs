using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Command to list available card readers.
/// </summary>
[PublicAPI]
[CliCommand("list-readers", "List available card readers", "card")]
[CommandHandler(Description = "List available card readers")]
public class ListReadersCommand : IPipelineCommand<ListReadersCommand.Settings>
{
    /// <summary>
    /// Executes the list readers command to enumerate available smart card readers.
    /// </summary>
    public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
    {
        try
        {
            return await context
                .WithVerbose(settings.Verbose)
                .ExecuteAsync(async ctx =>
                {
                    var readersResult = await ctx.CardService.GetReadersAsync();
                    string[] readers = readersResult.Match(success => success, error => []);

                    // Build semantic rows using pure functional composition
                    List<ReaderTableBuilder.ReaderRow> semanticRows =
                    [
                        .. ReaderTableBuilder.BuildReaderRows(readers, showSummary: true),
                    ];

                    // Check if we have any readers to display
                    if (!semanticRows.OfType<ReaderTableBuilder.ReaderDataRow>().Any())
                    {
                        ctx.Display.Warning("No card readers found");
                        return 0;
                    }

                    ctx.Display.Success($"Found {readers.Length} card reader(s):");

                    // Render using semantic table renderer
                    ReaderTableRenderer.RenderToTable(semanticRows);
                    ReaderTableRenderer.RenderPostTableRows(semanticRows);

                    return 0;
                });
        }
        catch (Exception)
        {
            return 1;
        }
    }

    /// <summary>
    /// Settings for the list readers command.
    /// </summary>
    public class Settings : StandardCommandSettings { }
}
