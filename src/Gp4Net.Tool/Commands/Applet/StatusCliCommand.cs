using System;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;
using StatusSubset = Gp4Net.Domain.Commands.GetStatusCommand.StatusSubset;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Command to get the status of applets on the card.
/// </summary>
[PublicAPI]
public class StatusCommand : BaseCommand<StatusCommand.Settings>
{
    /// <summary>
    /// Initializes a new instance of the StatusCommand class.
    /// </summary>
    public StatusCommand(
        ICardService cardService,
        Gp4Net.Services.IGlobalPlatformService globalPlatformService,
        IKeysetResolver keysetResolver
    )
        : base(cardService, globalPlatformService, keysetResolver) { }

    /// <summary>
    /// Executes the status command to display the status of applications on the card.
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

        // Optionally establish secure channel for better status information
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
            return await DisplayApplications(statusResult.Value, settings);
        }
        else
        {
            return HandleError(statusResult.Error);
        }
    }

    private static Task<int> DisplayApplications(ImmutableList<ApplicationInfo> applications, Settings settings)
    {
        if (applications.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No applets found on card[/]");
            return Task.FromResult(0);
        }

        AnsiConsole.MarkupLine($"[green]Found {applications.Count} applet(s) on card:[/]");

        var table = ApplicationDisplayService.CreateApplicationTable(false);
        table.Columns[2].Header("Lifecycle State");

        foreach (var app in applications
                     .OrderBy(a => a.Type)
                     .ThenBy(a => Convert.ToHexString(a.Aid)))
        {
            var typeColor = ApplicationDisplayService.GetTypeColor(app.Type);
            var stateColor = ApplicationDisplayService.GetStateColor(app.LifecycleState);
            var privilegesText = ApplicationDisplayService.GetPrivilegesDisplaySimple(app.Privileges);

            table.AddRow(
                $"[{typeColor}]{ApplicationDisplayService.GetTypeDisplayName(app.Type)}[/]",
                $"[dim]{app.AidHex}[/]",
                $"[{stateColor}]{app.LifecycleState}[/]",
                privilegesText
            );
        }

        AnsiConsole.Write(table);

        if (settings.Detailed)
        {
            AnsiConsole.WriteLine();
            ApplicationDisplayService.DisplayDetailedInformation(applications);
        }

        return Task.FromResult(0);
    }

    private static int HandleError(SmartCardError error)
    {
        AnsiConsole.MarkupLine($"[red]Error getting applet status: {error.Message}[/]");
        return 1;
    }

    // Display methods now delegate to ApplicationDisplayService

    /// <summary>
    /// Settings for the status command.
    /// </summary>
    public class Settings : BaseCommandSettings
    {
        /// <summary>
        /// Gets or sets a value indicating whether to show detailed information.
        /// </summary>
        [CommandOption("-d|--detailed")]
        [Description("Show detailed applet information")]
        public bool Detailed { get; set; }
    }
}