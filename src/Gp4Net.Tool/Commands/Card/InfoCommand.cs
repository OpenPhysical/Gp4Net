using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using Gp4Net.Services.GlobalPlatform;
using Gp4Net.Tool.Commands.Common;
using Gp4Net.Tool.Extensions;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
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
    private readonly ISmartCardServiceFactory _serviceFactory;
    private readonly IReaderResolutionService _resolutionService;
    private readonly IDisplayService _displayService;
    private readonly ILoggerFactory _loggerFactory;

    /// <summary>
    /// Initializes a new instance of the InfoCommand class.
    /// </summary>
    public InfoCommand(
        ISmartCardServiceFactory serviceFactory,
        IReaderResolutionService resolutionService,
        IDisplayService displayService,
        ILoggerFactory loggerFactory
    )
    {
        _serviceFactory = serviceFactory;
        _resolutionService = resolutionService;
        _displayService = displayService;
        _loggerFactory = loggerFactory;
    }

    /// <summary>
    /// Executes the info command using smart reader resolution.
    /// </summary>
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings)
    {
        // First resolve the reader
        var resolutionResult = await _resolutionService.ResolveReaderAsync(
            settings.GetReaderName(),
            CancellationToken.None
        );

        return await resolutionResult
            .Tap(resolution =>
                ReaderResolutionHelper.DisplayResolutionInfo(resolution, _displayService)
            )
            .Bind(async resolution =>
            {
                // Connect to the resolved reader
                var connectionResult = await _serviceFactory.CreateConnectedAsync(
                    resolution.ReaderName,
                    CancellationToken.None
                );

                return await connectionResult
                    .Tap(_ => _displayService.Success($"Connected to {resolution.ReaderName}"))
                    .Bind(async service =>
                    {
                        // Establish secure channel if requested
                        if (settings.UseSecureChannel)
                        {
                            var secureServiceResult = await EstablishSecureChannelAsync(
                                service,
                                settings
                            );
                            if (secureServiceResult.IsFailure)
                            {
                                return Result.Failure<CardDisplayInfo, SmartCardError>(
                                    secureServiceResult.Error
                                );
                            }
                            service = secureServiceResult.Value;
                        }

                        return await GetCardInformation(service, resolution.ReaderName, settings);
                    });
            })
            .Bind(info =>
                DisplayCardInformation(info, info.SecureChannelEstablished)
                    .Match(
                        () => Result.Success<CardDisplayInfo, SmartCardError>(info),
                        static error => Result.Failure<CardDisplayInfo, SmartCardError>(error)
                    )
            )
            .Match(
                async info =>
                {
                    // Save virtual card state if requested
                    await settings
                        .GetSaveFile()
                        .Match(
                            async saveFile =>
                            {
                                _displayService.Info($"Card state would be saved to: {saveFile}");
                                await Task.CompletedTask;
                            },
                            () => Task.CompletedTask
                        );

                    return 0;
                },
                error =>
                {
                    _displayService.Error(ReaderResolutionHelper.FormatResolutionError(error));
                    return Task.FromResult(1);
                }
            );
    }

    /// <summary>
    /// Establishes secure channel with the card.
    /// </summary>
    private async Task<Result<ISmartCardService, SmartCardError>> EstablishSecureChannelAsync(
        ISmartCardService service,
        Settings settings
    )
    {
        _displayService.Info("Establishing secure channel...");

        // Parse keyset from settings (defaults to GP test keys)
        var keysetSpec = settings.GetKeyset().GetValueOrDefault("gp_test");
        var rawKeysetResult = KeysetParser.ParseRawKeysetSpecification(keysetSpec);

        if (rawKeysetResult.IsFailure)
            return Result.Failure<ISmartCardService, SmartCardError>(rawKeysetResult.Error);

        var sessionResult = await ScpService.Establishment.EstablishAsync(
            service,
            rawKeysetResult.Value,
            SecurityLevel.CMac,
            CancellationToken.None
        );

        return sessionResult.Bind(session =>
        {
            _displayService.Success("✓ Secure channel established");
            return service.WithContextValue("SecureChannelSession", session.State);
        });
    }



    /// <summary>
    /// Gets comprehensive card information using the CardInformationGatherer service.
    /// </summary>
    private async Task<Result<CardDisplayInfo, SmartCardError>> GetCardInformation(
        ISmartCardService service,
        string readerName,
        Settings settings
    )
    {
        // Detect and select the ISD first
        var selectResult = await Discovery.DetectAndSelectIsdAsync(
            service.CreateExecutor(settings, settings.UseSecureChannel),
            CancellationToken.None
        );

        return await selectResult.Bind(async selectResponse =>
        {
            // Use CardInformationGatherer to get all card data
            var cardInfoResult = await CardInformationGatherer.GatherAsync(
                service.CreateExecutor(settings, settings.UseSecureChannel),
                Maybe<SelectResponse>.From(selectResponse),
                CancellationToken.None
            );

            return cardInfoResult.Map(cardInfo => new CardDisplayInfo
            {
                ReaderName = readerName,
                IsVirtual = readerName.StartsWith("virtual:", StringComparison.OrdinalIgnoreCase),
                SelectResponse = selectResponse,
                CardInformation = cardInfo,
                CardConnected = true,
                SecureChannelEstablished = settings.UseSecureChannel,
            });
        });
    }

    /// <summary>
    /// Displays card information in multiple formatted tables using CardInfoTableBuilder.
    /// </summary>
    private UnitResult<SmartCardError> DisplayCardInformation(
        CardDisplayInfo info,
        bool isSecureChannelEstablished
    )
    {
        // Use CardInfoTableBuilder to build semantic rows with all card data
        var cardInfoRows = CardInfoTableBuilder.BuildCardInfoRows(
            info.CardInformation,
            isSecureChannelEstablished: isSecureChannelEstablished
        );

        // Create sections using functional approach
        var sections = CreateSectionsFromRows(cardInfoRows);

        // Display each section as a separate table
        sections
            .Where(section => section.rows.Any())
            .Select(section => DisplaySectionTable(section, info))
            .ToList();

        if (info.IsVirtual)
        {
            AnsiConsole.MarkupLine(
                "[green]✓[/] Virtual card successfully connected and responding to commands"
            );
        }

        return UnitResult.Success<SmartCardError>();
    }

    private static IEnumerable<(
        string title,
        IEnumerable<(string name, string value, string type)> rows
    )> CreateSectionsFromRows(IEnumerable<CardInfoTableBuilder.CardInfoRow> rows)
    {
        return rows.Aggregate(
            new
            {
                Sections = new System.Collections.Generic.List<(
                    string,
                    System.Collections.Generic.List<(string, string, string)>
                )>(),
                CurrentTitle = "Basic Information",
                CurrentRows = new System.Collections.Generic.List<(string, string, string)>(),
            },
            (acc, row) =>
                row switch
                {
                    CardInfoTableBuilder.SectionHeader { Title: var title } => acc.CurrentRows.Any()
                        ? new
                        {
                            Sections = acc
                                .Sections.Concat(
                                    new[] { (acc.CurrentTitle, acc.CurrentRows.ToList()) }
                                )
                                .ToList(),
                            CurrentTitle = title,
                            CurrentRows = new System.Collections.Generic.List<(
                                string,
                                string,
                                string
                            )>(),
                        }
                        : new
                        {
                            acc.Sections,
                            CurrentTitle = title,
                            CurrentRows = new System.Collections.Generic.List<(
                                string,
                                string,
                                string
                            )>(),
                        },

                    CardInfoTableBuilder.PropertyRow { Name: var name, Value: var value } => new
                    {
                        acc.Sections,
                        acc.CurrentTitle,
                        CurrentRows = acc
                            .CurrentRows.Concat(new[] { (name, value, "property") })
                            .ToList(),
                    },

                    CardInfoTableBuilder.StatusRow
                    {
                        Name: var name,
                        IsAvailable: var available,
                        Details: var details
                    } => new
                    {
                        acc.Sections,
                        acc.CurrentTitle,
                        CurrentRows = acc
                            .CurrentRows.Concat(
                                new[]
                                {
                                    (
                                        name,
                                        $"[{(available ? "green" : "dim")}]{details}[/]",
                                        "status"
                                    ),
                                }
                            )
                            .ToList(),
                    },

                    CardInfoTableBuilder.ErrorRow { Name: var name, Message: var message } => new
                    {
                        acc.Sections,
                        acc.CurrentTitle,
                        CurrentRows = acc
                            .CurrentRows.Concat(new[] { (name, $"[red]{message}[/]", "error") })
                            .ToList(),
                    },

                    CardInfoTableBuilder.InfoRow { Message: var message } => new
                    {
                        acc.Sections,
                        acc.CurrentTitle,
                        CurrentRows = acc
                            .CurrentRows.Concat(new[] { ("", $"[dim]{message}[/]", "info") })
                            .ToList(),
                    },

                    CardInfoTableBuilder.FourColumnRow
                    {
                        Tag: var tag,
                        TagDescription: var desc,
                        Value: var val,
                        ValueDescription: var valDesc
                    } => new
                    {
                        acc.Sections,
                        acc.CurrentTitle,
                        CurrentRows = acc
                            .CurrentRows.Concat(
                                new[] { ($"{tag}|{desc}", $"{val}|{valDesc}", "fourcolumn") }
                            )
                            .ToList(),
                    },

                    _ => acc,
                },
            acc =>
            {
                var finalSections = acc.CurrentRows.Any()
                    ? acc
                        .Sections.Concat(new[] { (acc.CurrentTitle, acc.CurrentRows.ToList()) })
                        .ToList()
                    : acc.Sections;
                return finalSections.Select(s => (s.Item1, s.Item2.AsEnumerable()));
            }
        );
    }

    private static bool DisplaySectionTable(
        (string title, IEnumerable<(string name, string value, string type)> rows) section,
        CardDisplayInfo info
    )
    {
        var tableColor = GetTableColorForSection(section.title);
        var borderColor = tableColor switch
        {
            "yellow" => Color.Yellow,
            "cyan" => Color.Aqua, // Spectre uses Aqua instead of Cyan
            "red" => Color.Red,
            "magenta" => Color.Purple, // Spectre uses Purple instead of Magenta
            "green" => Color.Green,
            _ => Color.Grey,
        };

        // Check if this section contains four-column rows
        var hasFourColumnRows = section.rows.Any(r => r.type == "fourcolumn");

        if (hasFourColumnRows)
        {
            // Create 4-column table for Platform Identifiers
            var table = new Table()
                .Border(TableBorder.Rounded)
                .BorderColor(borderColor)
                .Title($"[bold {tableColor}]{section.title}[/]")
                .AddColumn(new TableColumn("Tag").NoWrap())
                .AddColumn(new TableColumn("Tag Description"))
                .AddColumn(new TableColumn("Value"))
                .AddColumn(new TableColumn("Meaning"));

            section
                .rows.Where(row => row.type == "fourcolumn")
                .Select(row =>
                {
                    var parts1 = row.name.Split('|');
                    var parts2 = row.value.Split('|');
                    table.AddRow(
                        parts1[0],
                        parts1.Length > 1 ? parts1[1] : "",
                        parts2[0],
                        parts2.Length > 1 ? parts2[1] : ""
                    );
                    return row;
                })
                .ToList();

            AnsiConsole.Write(table);
            AnsiConsole.WriteLine();
        }
        else
        {
            // Create standard 2-column table
            var table = new Table()
                .Border(TableBorder.Rounded)
                .BorderColor(borderColor)
                .Title($"[bold {tableColor}]{section.title}[/]")
                .AddColumn(new TableColumn("Property").NoWrap())
                .AddColumn(new TableColumn("Value"));

            // Add basic info to the first table
            if (section.title == "Basic Information" || section.title == "Connection")
            {
                table.AddRow("Type", info.IsVirtual ? "Virtual Card" : "Physical Card");

                _ = info.CardInformation.IsdInfo.Match(
                    isd =>
                    {
                        isd.Fci.Match(
                            fci =>
                            {
                                table.AddRow("ISD AID", Convert.ToHexString(fci.ApplicationAid));
                                return true;
                            },
                            () => false
                        );
                        return true;
                    },
                    () => false
                );
            }

            section
                .rows.Where(row => row.name.Length > 0 || row.value.Length > 0)
                .Select(row =>
                {
                    table.AddRow(row.name, row.value);
                    return row;
                })
                .ToList();

            AnsiConsole.Write(table);
            AnsiConsole.WriteLine();
        }

        return true;
    }

    private static string GetTableColorForSection(string sectionTitle)
    {
        return sectionTitle switch
        {
            var t when t.Contains("Manufacturing") || t.Contains("CPLC") => "yellow",
            var t when t.Contains("Chip") || t.Contains("Platform") => "cyan",
            var t when t.Contains("Security") || t.Contains("Keys") => "red",
            var t when t.Contains("Cryptographic") => "magenta",
            var t when t.Contains("Identifiers") => "green",
            _ => "grey",
        };
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
            var causeMessages = errorDetails
                .PossibleCauses.Select(cause => $"[dim]  - {cause}[/]")
                .Aggregate(
                    "",
                    (acc, msg) =>
                    {
                        AnsiConsole.MarkupLine(msg);
                        return acc;
                    }
                );
        }

        // Display recommended actions
        if (errorDetails.RecommendedActions.Any())
        {
            AnsiConsole.MarkupLine("[yellow]Recommended actions:[/]");
            var actionMessages = errorDetails
                .RecommendedActions.Select(action => $"[dim]  - {action}[/]")
                .Aggregate(
                    "",
                    (acc, msg) =>
                    {
                        AnsiConsole.MarkupLine(msg);
                        return acc;
                    }
                );
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
        public CardInformation CardInformation { get; init; } = CardInformation.Empty;
        public bool CardConnected { get; init; }
        public bool SecureChannelEstablished { get; init; }
    }

    /// <summary>
    /// Settings for the info command.
    /// </summary>
    public class Settings : CardCommandSettings
    {
        /// <summary>
        /// Gets or sets whether to establish a secure channel for more detailed information.
        /// </summary>
        [CommandOption("--secure-channel")]
        [Description("Establish secure channel for more detailed card information")]
        public bool UseSecureChannel { get; set; }

        /// <summary>
        /// Gets or sets the keyset specification for secure channel establishment.
        /// </summary>
        [CommandOption("-k|--keyset")]
        [Description("Keyset specification for secure channel (e.g., visa2:404142...)")]
        public string Keyset { get; set; } = string.Empty;

        /// <summary>
        /// Gets the keyset as Maybe type.
        /// </summary>
        public Maybe<string> GetKeyset() =>
            string.IsNullOrWhiteSpace(Keyset) ? Maybe<string>.None : Maybe<string>.From(Keyset);
    }
}
