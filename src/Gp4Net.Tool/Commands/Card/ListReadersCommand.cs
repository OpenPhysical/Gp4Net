using System.Threading.Tasks;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card
{
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

                        if (readers.Count == 0)
                        {
                            ctx.Display.Warning("No card readers found");
                            return 0;
                        }

                        ctx.Display.Success($"Found {readers.Count} card reader(s):");

                        var table = new Table().AddColumn("Index").AddColumn("Reader Name");

                        for (int i = 0; i < readers.Count; i++)
                        {
                            _ = table.AddRow(i.ToString(), readers[i]);
                        }

                        AnsiConsole.Write(table);
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
}
