using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Services;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;
using StatusSubset = Gp4Net.Domain.Commands.GetStatusCommand.StatusSubset;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Command to list applications on the card.
/// </summary>
[PublicAPI]
[CliCommand("list", "List applications on the card", "applet")]
/// <summary>
/// Command to list applications installed on a GlobalPlatform card.
/// </summary>
[Description("List applications on the card")]
public class ListCliCommand : BaseCommand<ListCliCommand.Settings>
{
    /// <summary>
    /// Initializes a new instance of the ListCliCommand class.
    /// </summary>
    public ListCliCommand(
        ICardService cardService,
        Gp4Net.Services.IGlobalPlatformService globalPlatformService,
        IKeysetResolver keysetResolver
    )
        : base(cardService, globalPlatformService, keysetResolver) { }

    /// <summary>
    /// Executes the list command to enumerate applications on the card.
    /// </summary>
    /// <param name="context">The command context.</param>
    /// <param name="settings">The command settings.</param>
    /// <returns>0 if successful, 1 if failed.</returns>
    protected override async Task<int> ExecuteCommandAsync(CommandContext context, Settings settings)
    {
        if (!EnsureCardConnection(settings))
        {
            return 1;
        }

        // Optionally establish secure channel for more detailed information
        if (settings.RequiresSecureChannel && !EnsureSecureChannel(settings))
        {
            return 1;
        }

        if (!settings.NoCardInfo)
        {
            DisplayCardInfo();
        }

        var statusResult = await GlobalPlatformService.GetStatusAsync(
            StatusSubset.ApplicationsAndSupplementaryDomains);

        if (statusResult.IsSuccess)
        {
            return await ProcessApplications(statusResult.Value, settings);
        }
        else
        {
            return HandleError(statusResult.Error, settings);
        }
    }

    private Task<int> ProcessApplications(IReadOnlyList<ApplicationInfo> applications, Settings settings)
    {
        // Apply filter
        var filteredApps = applications;
        if (!string.IsNullOrEmpty(settings.Filter) && settings.Filter != "all")
        {
            filteredApps = FilterApplications(filteredApps, settings.Filter);
        }

        if (filteredApps.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No applications found[/]");
            return Task.FromResult(0);
        }

        // Display based on format
        switch (settings.Format.ToLowerInvariant())
        {
            case "json":
                DisplayJson(filteredApps);
                break;

            case "csv":
                DisplayCsv(filteredApps);
                break;

            case "table":
            default:
                DisplayTable(filteredApps, settings.ShowExtended);
                break;
        }

        if (settings.ShowSummary)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"[dim]Total: {filteredApps.Count} application(s)[/]");
        }

        return Task.FromResult(0);
    }

    private static int HandleError(SmartCardError error, Settings settings)
    {
        AnsiConsole.MarkupLine($"[red]Error listing applications: {error.Message}[/]");
        if (settings.Verbose && error.InnerException.HasValue)
        {
            AnsiConsole.WriteException(error.InnerException.Value);
        }
        return 1;
    }

    private static IReadOnlyList<ApplicationInfo> FilterApplications(
        IReadOnlyList<ApplicationInfo> applications,
        string filter
    )
    {
        return ApplicationDisplayService.FilterApplications(applications, filter);
    }

    private static void DisplayTable(IReadOnlyList<ApplicationInfo> applications, bool extended)
    {
        ApplicationDisplayService.DisplayApplicationTable(applications, extended);
    }

    private static void DisplayJson(IReadOnlyList<ApplicationInfo> applications)
    {
        ApplicationDisplayService.DisplayApplicationsJson(applications);
    }

    private static void DisplayCsv(IReadOnlyList<ApplicationInfo> applications)
    {
        ApplicationDisplayService.DisplayApplicationsCsv(applications);
    }

    // Display methods now delegate to ApplicationDisplayService

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
        public bool ShowSummary => !NoSummary;

        /// <summary>
        /// Gets or sets whether to use secure channel.
        /// </summary>
        [CommandOption("--secure-channel")]
        [Description("Use secure channel for more detailed information")]
        public bool UseSecureChannel { get; set; }

        /// <inheritdoc />
        public override bool RequiresSecureChannel => UseSecureChannel;

        /// <summary>
        /// Validates the command settings.
        /// </summary>
        /// <returns>Success if valid, or an error message if validation fails.</returns>
        public override ValidationResult Validate()
        {
            var validFilters = new[] { "all", "isd", "apps", "applets", "packages", "ssd" };
            if (!validFilters.Contains(Filter.ToLowerInvariant()))
            {
                return ValidationResult.Error(
                    $"Invalid filter. Valid options: {string.Join(", ", validFilters)}"
                );
            }

            var validFormats = new[] { "table", "json", "csv" };
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