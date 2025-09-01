using System.Collections.Generic;
using System.ComponentModel;
using System.Text;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Services;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;
using CardInformation = Gp4Net.Services.CardInformation;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Command to display detailed card information using library services.
/// </summary>
[PublicAPI]
[CliCommand("info", "Display detailed card information", "card")]
[Description("Display detailed card information")]
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
                error => HandleError(error)
            );
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
    private async Task<
        Result<IEnumerable<CardInfoTableBuilder.TableRow>, SmartCardError>
    > BuildTableRows(CardInformation cardInfo, Settings settings)
    {
        // Check secure channel status for enhanced display
        bool isSecureChannelEstablished = false; // Can be enhanced later

        Domain.CardInfo.CardInformation domainCardInfo = ConvertToDomainCardInfo(cardInfo);
        IEnumerable<CardInfoTableBuilder.TableRow> rows = CardInfoTableBuilder.BuildCardInfoRows(
            domainCardInfo,
            isSecureChannelEstablished
        );
        return Result.Success<IEnumerable<CardInfoTableBuilder.TableRow>, SmartCardError>(rows);
    }

    /// <summary>
    /// Converts Services.CardInformation to Domain.CardInfo.CardInformation.
    /// </summary>
    private static Domain.CardInfo.CardInformation ConvertToDomainCardInfo(
        CardInformation serviceCardInfo
    )
    {
        return new Domain.CardInfo.CardInformation(
            Atr: serviceCardInfo.Atr.Map(atr => Encoding.UTF8.GetBytes(atr ?? "")),
            Cplc: serviceCardInfo.Cplc,
            Capabilities: Maybe<CardCapabilities>.None, // Not available in service type
            KeyInfo: Maybe<KeyInformationTemplate>.None, // Not available in service type
            CardData: Maybe<CardDataInfo>.None, // Not available in service type
            ScpInfo: Maybe<ScpInformation>.None, // Not available in service type
            SecurityStatus: Maybe<SecurityDomainStatus>.None, // Not available in service type
            DiversificationData: Maybe<byte[]>.None, // Not available in service type
            IsdInfo: serviceCardInfo.IsdInfo,
            ChipDetails: Maybe<ChipInfo>.None // Not available in service type
        );
    }

    /// <summary>
    /// Displays card information using tool display service.
    /// </summary>
    private static void DisplayCardInfo(
        IEnumerable<CardInfoTableBuilder.TableRow> rows,
        Settings settings
    )
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
        [Description("Show verbose information")]
        public bool Verbose { get; set; }
    }
}
