using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.DataObjects;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using Gp4Net.Services.GlobalPlatform;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Command to display detailed card information using static services.
/// </summary>
[PublicAPI]
[CliCommand("info", "Display detailed card information", "card")]
[Description("Display detailed card information")]
public class InfoCommand : AsyncCommand<InfoCommand.Settings>
{
    private readonly ILoggerFactory _loggerFactory;

    /// <summary>
    /// Initializes a new instance of the InfoCommand class.
    /// </summary>
    public InfoCommand()
    {
        _loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
    }

    /// <summary>
    /// Executes the info command using static services for data gathering and tool for display.
    /// </summary>
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings)
    {
        return await settings.GetReaderName()
            .ToResult(SmartCardError.InvalidArgument("Reader name is required. Use --reader option."))
            .Bind(readerName => CreateSmartCardService(readerName, settings))
            .Bind(service => GetCardInformation(service, settings.GetReaderName().GetValueOrDefault()))
            .Bind(info => DisplayCardInformation(info).Match(
                () => Result.Success<CardDisplayInfo, SmartCardError>(info),
                error => Result.Failure<CardDisplayInfo, SmartCardError>(error)))
            .Match(
                async info =>
                {
                    // Save virtual card state if requested
                    await settings.GetSaveFile()
                        .Match(
                            async saveFile =>
                            {
                                AnsiConsole.MarkupLine($"[dim]Card state would be saved to: {saveFile}[/]");
                                await Task.CompletedTask;
                            },
                            () => Task.CompletedTask
                        );

                    return 0;
                },
                async error => HandleError(error)
            );
    }

    /// <summary>
    /// Creates a SmartCardService for the specified reader.
    /// </summary>
    private async Task<Result<ISmartCardService, SmartCardError>> CreateSmartCardService(
        string readerName,
        Settings settings
    )
    {
        var logger = _loggerFactory.CreateLogger<SmartCardService>();

        // Check if this is a virtual reader
        if (readerName.StartsWith("virtual:", System.StringComparison.OrdinalIgnoreCase))
        {
            return await VirtualCardConnectionService.CreateServiceAsync(
                readerName,
                logger,
                CancellationToken.None
            );
        }

        // Physical card connection via WSCT
        return await PhysicalCardConnectionService.CreateServiceAsync(
            readerName,
            logger,
            CancellationToken.None
        );
    }

    /// <summary>
    /// Gets card information from the smart card service.
    /// </summary>
    private async Task<Result<CardDisplayInfo, SmartCardError>> GetCardInformation(
        ISmartCardService service,
        string readerName
    )
    {
        // Detect and select the ISD
        var selectResult = await Discovery.DetectAndSelectIsdAsync(
            (command, ct) => service.ExecuteCommandAsync(command, ct),
            CancellationToken.None
        );

        return selectResult.Map(selectResponse => new CardDisplayInfo
        {
            ReaderName = readerName,
            IsVirtual = readerName.StartsWith("virtual:", System.StringComparison.OrdinalIgnoreCase),
            SelectResponse = selectResponse,
            CardConnected = true
        });
    }

    /// <summary>
    /// Displays card information in a formatted table.
    /// </summary>
    private UnitResult<SmartCardError> DisplayCardInformation(CardDisplayInfo info)
    {
        var table = new Table()
            .Border(TableBorder.Rounded)
            .Title("[bold]Card Information[/]")
            .AddColumn("Property")
            .AddColumn("Value");

        // Basic info
        table.AddRow("Reader", info.ReaderName);
        table.AddRow("Type", info.IsVirtual ? "Virtual Card" : "Physical Card");
        table.AddRow("Status", info.CardConnected ? "[green]Connected[/]" : "[red]Not Connected[/]");

        // ISD Selection Response info
        info.SelectResponse.Match(
            response =>
            {
                // Display FCI data if available
                response.Fci.Match(
                    fci =>
                    {
                        if (fci.ApplicationAid.Length > 0)
                        {
                            table.AddRow("ISD AID", Convert.ToHexString(fci.ApplicationAid));
                        }

                        fci.ApplicationLabel.Match(
                            label => table.AddRow("Label", label),
                            () => { }
                        );

                        fci.MaxCommandDataLength.Match(
                            maxLen => table.AddRow("Max Command Length", maxLen.ToString()),
                            () => { }
                        );

                        fci.MaxResponseDataLength.Match(
                            maxLen => table.AddRow("Max Response Length", maxLen.ToString()),
                            () => { }
                        );
                    },
                    () => table.AddRow("FCI Data", "Not available")
                );

                // Display additional FCI information if available
                response.Fci.Match(
                    fci =>
                    {
                        if (fci.CardData.Length > 0)
                        {
                            table.AddRow("Card Data", Convert.ToHexString(fci.CardData));
                        }

                        if (fci.DiscretionaryData.Length > 0)
                        {
                            table.AddRow("Discretionary Data", Convert.ToHexString(fci.DiscretionaryData));
                        }
                    },
                    () => { }
                );
            },
            () => table.AddRow("ISD Selection", "Failed")
        );

        AnsiConsole.Write(table);

        if (info.IsVirtual)
        {
            AnsiConsole.MarkupLine("");
            AnsiConsole.MarkupLine("[green]✓[/] Virtual card successfully connected and responding to commands");
        }

        return UnitResult.Success<SmartCardError>();
    }

    /// <summary>
    /// Handles errors with enhanced error translation using ErrorTranslationService.
    /// </summary>
    private static int HandleError(SmartCardError error)
    {
        var humanReadableMessage = ErrorTranslationService.TranslateStatusWord(error);
        var errorDetails = ErrorTranslationService.GetHumanReadableError(error);

        AnsiConsole.MarkupLine($"[red]Failed to get card information: {humanReadableMessage}[/]");

        // Display possible causes
        if (errorDetails.PossibleCauses.Any())
        {
            AnsiConsole.MarkupLine("[yellow]Possible causes:[/]");
            var causeMessages = errorDetails.PossibleCauses
                .Select(cause => $"[dim]  - {cause}[/]")
                .Aggregate("", (acc, msg) => { AnsiConsole.MarkupLine(msg); return acc; });
        }

        // Display recommended actions
        if (errorDetails.RecommendedActions.Any())
        {
            AnsiConsole.MarkupLine("[yellow]Recommended actions:[/]");
            var actionMessages = errorDetails.RecommendedActions
                .Select(action => $"[dim]  - {action}[/]")
                .Aggregate("", (acc, msg) => { AnsiConsole.MarkupLine(msg); return acc; });
        }

        return 1;
    }

    /// <summary>
    /// Internal class for holding card display information.
    /// </summary>
    private class CardDisplayInfo
    {
        public string ReaderName { get; init; } = string.Empty;
        public bool IsVirtual { get; init; }
        public Maybe<SelectResponse> SelectResponse { get; init; }
        public bool CardConnected { get; init; }
    }

    /// <summary>
    /// Settings for the info command.
    /// </summary>
    public class Settings : CardCommandSettings
    {
        // Inherits ReaderName, SaveFile, and Verbose from CardCommandSettings
    }
}
