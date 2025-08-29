using System.Collections.Generic;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Services;
using Gp4Net.Tool.Commands.Card;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Command to display detailed card information using library services.
/// </summary>
[PublicAPI]
[CliCommand("info", "Display detailed card information", "card")]
[System.ComponentModel.Description("Display detailed card information")]
public class InfoCommand : AsyncCommand<InfoCommand.Settings>
{
    private readonly IGlobalPlatformService _globalPlatformService;

    /// <summary>
    /// Initializes a new instance of the InfoCommand class.
    /// </summary>
    public InfoCommand(IGlobalPlatformService globalPlatformService)
    {
        _globalPlatformService = globalPlatformService;
    }

    /// <summary>
    /// Executes the info command using library service for data and tool for display.
    /// </summary>
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings)
    {
        AnsiConsole.MarkupLine("[yellow]Retrieving card information...[/]");

        // Clean architecture: Library -> Tool -> Display
        return await GetCardInformation()
            .Bind(cardInfo => BuildTableRows(cardInfo, settings))
            .Match(
                rows => 
                {
                    DisplayCardInfo(rows, settings);
                    return 0;
                },
                error => HandleError(error));
    }

    /// <summary>
    /// Gets card information from library service.
    /// </summary>
    private async Task<Result<CardInformation, SmartCardError>> GetCardInformation()
    {
        return await _globalPlatformService.GetCardInfoAsync();
    }

    /// <summary>
    /// Builds semantic table rows using tool services.
    /// </summary>
    private async Task<Result<IEnumerable<CardInfoTableBuilder.TableRow>, SmartCardError>> BuildTableRows(
        CardInformation cardInfo, Settings settings)
    {
        // Check secure channel status for enhanced display
        bool isSecureChannelEstablished = false; // Can be enhanced later
        
        IEnumerable<CardInfoTableBuilder.TableRow> rows = CardInfoTableBuilder.BuildCardInfoRows(cardInfo, isSecureChannelEstablished);
        return Result.Success<IEnumerable<CardInfoTableBuilder.TableRow>, SmartCardError>(rows);
    }

    /// <summary>
    /// Displays card information using tool display service.
    /// </summary>
    private static void DisplayCardInfo(IEnumerable<CardInfoTableBuilder.TableRow> rows, Settings settings)
    {
        CardInfoDisplayService.DisplayCardInfoTable(rows);
        CardInfoDisplayService.DisplayKeysetSuggestions(false); // Can be enhanced based on secure channel status
    }

    /// <summary>
    /// Handles errors with functional error display.
    /// </summary>
    private static int HandleError(SmartCardError error)
    {
        AnsiConsole.MarkupLine($"[red]Failed to get card information: {error.Message}[/]");
        return 1;
    }

    /// <summary>
    /// Settings for the info command.
    /// </summary>
    public class Settings : CardCommandSettings 
    {
        /// <summary>
        /// Gets or sets whether to show verbose information.
        /// </summary>
        [System.ComponentModel.Description("Show verbose information")]
        public bool Verbose { get; set; }
    }
}
