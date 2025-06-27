using System.Threading.Tasks;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card
{
    /// <summary>
    /// Command to connect to a smart card.
    /// </summary>
    [PublicAPI]
    public class ConnectCommand : BaseCommand<ConnectCommand.Settings>
    {
        /// <summary>
        /// Initializes a new instance of the ConnectCommand class.
        /// </summary>
        public ConnectCommand(ICardService cardService, IGlobalPlatformService globalPlatformService)
            : base(cardService, globalPlatformService)
        {
        }

        /// <inheritdoc />
        protected override Task<int> ExecuteCommandAsync(CommandContext context, Settings settings)
        {
            if (!EnsureCardConnection(settings))
            {
                return Task.FromResult(1);
            }

            AnsiConsole.MarkupLine("[green]Successfully connected to card[/]");

            if (!settings.NoCardInfo)
            {
                DisplayCardInfo();

                // Try to select ISD and get basic card information
                try
                {
                    var selectResponse = GlobalPlatformService.SelectIsd();
                    AnsiConsole.MarkupLine("[green]✓ ISD successfully selected[/]");
                    
                    if (selectResponse.RawData != null && selectResponse.RawData.Length > 0)
                    {
                        AnsiConsole.MarkupLine($"[dim]Response data: {System.Convert.ToHexString(selectResponse.RawData)}[/]");
                    }
                    
                    if (selectResponse.Fci?.CardData != null && selectResponse.Fci.CardData.Length > 0)
                    {
                        AnsiConsole.MarkupLine($"[dim]Card data: {System.Convert.ToHexString(selectResponse.Fci.CardData)}[/]");
                    }
                }
                catch (System.Exception ex)
                {
                    AnsiConsole.MarkupLine($"[yellow]⚠ Error selecting ISD: {ex.Message}[/]");
                }
            }

            return Task.FromResult(0);
        }

        /// <summary>
        /// Settings for the connect command.
        /// </summary>
        public class Settings : BaseCommandSettings
        {
        }
    }
}