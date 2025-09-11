using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Tool.Infrastructure;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Command to list applications on the card using library services.
/// Tool handles display, library provides data.
/// </summary>
[PublicAPI]
[CliCommand("list", "List applications on the card", "applet")]
[Description("List applications on the card")]
public class ListCliCommand : AsyncCommand<ListCliCommand.Settings>
{
    /// <summary>
    /// Initializes a new instance of the ListCliCommand class.
    /// Uses static GlobalPlatform services.
    /// </summary>
    public ListCliCommand() { }

    /// <summary>
    /// Executes the list command using library services for data and tool for display.
    /// </summary>
    /// <param name="context">The command context.</param>
    /// <param name="settings">The command settings.</param>
    /// <returns>0 if successful, 1 if failed.</returns>
    public override Task<int> ExecuteAsync(CommandContext context, Settings settings)
    {
        AnsiConsole.MarkupLine("[yellow]Listing applications on card...[/]");

        AnsiConsole.MarkupLine(
            "[red]Application listing not yet implemented with static services.[/]"
        );
        return Task.FromResult(1);
    }

    /// <summary>
    /// Executes with the service using proper library/tool separation.
    /// </summary>
    private async Task<int> ExecuteWithService(
        object service, // OBSOLETE: Need to refactor to static services
        Settings settings,
        CancellationToken cancellationToken
    )
    {
        // This obsolete service pattern will be removed - placeholder return
        return await Task.FromResult(
                Result.Failure<IReadOnlyList<ApplicationInfo>, SmartCardError>(
                    SmartCardError.Unsupported("Service integration pending")
                )
            )
            .Match(
                applications =>
                {
                    ProcessApplications(applications, settings);
                    return 0;
                },
                error =>
                {
                    HandleError(error, "Operation failed", settings);
                    return 1;
                }
            );
    }

    /// <summary>
    /// Establishes secure channel from settings with functional patterns.
    /// </summary>
    private Task<
        Result<SecureChannelState, SmartCardError>
    > EstablishSecureChannelFromSettings(
        object service, // OBSOLETE: Need to refactor to static services
        Settings settings,
        CancellationToken cancellationToken
    )
    {
        // Use pattern matching to check if all keys are provided
        return (
            settings.KeyEnc.HasValue && settings.KeyMac.HasValue && settings.KeyDek.HasValue
        ) switch
        {
            true =>
            // All keys provided - extract them using pattern matching
            Task.FromResult(
                settings.KeyEnc.Match(
                    encKey =>
                        settings.KeyMac.Match(
                            macKey =>
                                settings.KeyDek.Match(
                                    dekKey =>
                                        Result.Failure<SecureChannelState, SmartCardError>(
                                            SmartCardError.Unsupported("Service integration pending")
                                        ),
                                    () =>
                                        Result.Failure<SecureChannelState, SmartCardError>(
                                            SmartCardError.InvalidData(
                                                "DEK key is required when using explicit keys"
                                            )
                                        )
                                ),
                            () =>
                                Result.Failure<SecureChannelState, SmartCardError>(
                                    SmartCardError.InvalidData(
                                        "MAC key is required when using explicit keys"
                                    )
                                )
                        ),
                    () =>
                        Result.Failure<SecureChannelState, SmartCardError>(
                            SmartCardError.InvalidData("ENC key is required when using explicit keys")
                        )
                )
            ),
            false =>
            // Use keyset specification (placeholder implementation)
            Task.FromResult(
                Result.Failure<SecureChannelState, SmartCardError>(
                    SmartCardError.Unsupported("Service integration pending")
                )
            ),
        };
    }

    /// <summary>
    /// Handles errors with proper tool-layer error display.
    /// </summary>
    private static void HandleError(SmartCardError error, string operation, Settings settings)
    {
        AnsiConsole.MarkupLine($"[red]{operation}: {error.Message}[/]");

        if (settings.Verbose && error.InnerException.HasValue)
        {
            error.InnerException.Match(
                exception =>
                {
                    AnsiConsole.MarkupLine("[red]Detailed error information:[/]");
                    AnsiConsole.WriteException(exception);
                    return true;
                },
                () => false
            );
        }
    }

    /// <summary>
    /// Processes applications for display using functional composition.
    /// </summary>
    private void ProcessApplications(IReadOnlyList<ApplicationInfo> applications, Settings settings)
    {
        // Build semantic rows using pure functional composition
        var semanticRows = ApplicationTableBuilder
            .BuildApplicationRows(
                applications,
                showExtended: settings.ShowExtended,
                showSummary: settings.ShowSummary,
                filter: settings.Filter
            )
            .ToList();

        // Display based on format using pure functions
        switch (settings.Format.ToLowerInvariant())
        {
            case "json":
                string json = ApplicationTableBuilder.ToJson(applications);
                AnsiConsole.WriteLine(json);
                break;

            case "csv":
                string csv = ApplicationTableBuilder.ToCsv(applications);
                AnsiConsole.WriteLine(csv);
                break;

            case "table":
            default:
                ApplicationTableRenderer.RenderToTable(semanticRows, settings.ShowExtended);
                ApplicationTableRenderer.RenderPostTableRows(semanticRows);
                break;
        }
    }

    /// <summary>
    /// Settings for the list command.
    /// </summary>
    public class Settings : BaseCommandSettings
    {
        /// <summary>
        /// Gets or sets the filter type.
        /// </summary>
        [CommandOption("-f|--filter")]
        [Description("Filter applications (all, isd, apps, packages, ssd)")]
        [DefaultValue("all")]
        public string Filter { get; set; } = "all";

        /// <summary>
        /// Gets or sets the output format.
        /// </summary>
        [CommandOption("--format")]
        [Description("Output format (table, json, csv)")]
        [DefaultValue("table")]
        public string Format { get; set; } = "table";

        /// <summary>
        /// Gets or sets whether to show extended information.
        /// </summary>
        [CommandOption("-x|--extended")]
        [Description("Show extended information")]
        public bool ShowExtended { get; set; }

        /// <summary>
        /// Gets or sets whether to show summary.
        /// </summary>
        [CommandOption("--no-summary")]
        [Description("Don't show summary count")]
        public bool NoSummary { get; set; }

        /// <summary>
        /// Gets whether to show summary.
        /// </summary>
        public bool ShowSummary
        {
            get { return !NoSummary; }
        }

        /// <summary>
        /// Gets or sets whether to use secure channel.
        /// </summary>
        [CommandOption("--secure-channel")]
        [Description("Use secure channel for more detailed information")]
        public bool UseSecureChannel { get; set; }

        /// <summary>
        /// Gets or sets whether to skip card info display.
        /// </summary>
        [CommandOption("--no-card-info")]
        [Description("Skip card information display")]
        public bool NoCardInfo { get; set; }

        /// <inheritdoc />
        public override bool RequiresSecureChannel
        {
            get
            {
                return true; // Always require secure channel for listing applets
            }
        }

        /// <summary>
        /// Validates the command settings.
        /// </summary>
        /// <returns>Success if valid, or an error message if validation fails.</returns>
        public override ValidationResult Validate()
        {
            string[] validFilters = ["all", "isd", "apps", "applets", "packages", "ssd"];
            if (!validFilters.Contains(Filter.ToLowerInvariant()))
            {
                return ValidationResult.Error(
                    $"Invalid filter. Valid options: {string.Join(", ", validFilters)}"
                );
            }

            string[] validFormats = ["table", "json", "csv"];
            if (!validFormats.Contains(Format.ToLowerInvariant()))
            {
                return ValidationResult.Error(
                    $"Invalid format. Valid options: {string.Join(", ", validFormats)}"
                );
            }

            return ValidationResult.Success();
        }
    }
}
