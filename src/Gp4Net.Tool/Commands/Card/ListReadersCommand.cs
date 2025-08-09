using System.Linq;
using System.Threading.Tasks;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Command to list available card readers.
/// </summary>
[PublicAPI]
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
                .ExecuteAsync(ctx =>
                {
                    var readers = ctx.CardService.GetReaders();

                    // Build semantic rows using pure functional composition
                    var semanticRows = ReaderTableBuilder.BuildReaderRows(
                        readers,
                        showSummary: true
                    ).ToList();

                    // Check if we have any readers to display
                    if (!semanticRows.OfType<ReaderTableBuilder.ReaderDataRow>().Any())
                    {
                        ctx.Display.Warning("No card readers found");
                        return 0;
                    }

                    ctx.Display.Success($"Found {readers.Count} card reader(s):");

                    // Render using semantic table renderer
                    ReaderTableRenderer.RenderToTable(semanticRows);
                    ReaderTableRenderer.RenderPostTableRows(semanticRows);
                    
                    return 0;
                });
        }
        catch (System.Exception)
        {
            return 1;
        }
    }

    /// <summary>
    /// Settings for the list readers command.
    /// </summary>
    public class Settings : StandardCommandSettings { }
}