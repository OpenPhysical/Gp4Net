using System.Threading.Tasks;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card
{
    /// <summary>
    /// Command to list available card readers.
    /// </summary>
    [PublicAPI]
    public class ListReadersCommand : BaseCommand<ListReadersCommand.Settings>
    {
        /// <summary>
        /// Initializes a new instance of the ListReadersCommand class.
        /// </summary>
        public ListReadersCommand(ICardService cardService, IGlobalPlatformService globalPlatformService)
            : base(cardService, globalPlatformService)
        {
        }

        /// <inheritdoc />
        protected override Task<int> ExecuteCommandAsync(CommandContext context, Settings settings)
        {
            var readers = CardService.GetReaders();

            if (readers.Count == 0)
            {
                AnsiConsole.MarkupLine("[yellow]No card readers found[/]");
                return Task.FromResult(0);
            }

            AnsiConsole.MarkupLine($"[green]Found {readers.Count} card reader(s):[/]");
            
            var table = new Table()
                .AddColumn("Index")
                .AddColumn("Reader Name");

            for (int i = 0; i < readers.Count; i++)
            {
                table.AddRow(i.ToString(), readers[i]);
            }

            AnsiConsole.Write(table);
            return Task.FromResult(0);
        }

        /// <summary>
        /// Settings for the list readers command.
        /// </summary>
        public class Settings : BaseCommandSettings
        {
        }
    }
}