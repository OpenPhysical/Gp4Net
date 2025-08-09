using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Tool.Commands;
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
        IDomainServiceFactory domainServiceFactory,
        IKeysetResolver keysetResolver
    )
        : base(cardService, domainServiceFactory, keysetResolver) { }

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
        if (settings.RequiresSecureChannel && !await EnsureSecureChannel(settings))
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
        // Build semantic rows using pure functional composition
        var semanticRows = ApplicationTableBuilder.BuildApplicationRows(
            applications,
            showExtended: false,
            showSummary: true,
            filter: null
        ).ToList();

        // Check if we have any applications to display
        if (!semanticRows.OfType<ApplicationTableBuilder.ApplicationDataRow>().Any())
        {
            AnsiConsole.MarkupLine("[yellow]No applets found on card[/]");
            return Task.FromResult(0);
        }

        AnsiConsole.MarkupLine($"[green]Found {applications.Count} applet(s) on card:[/]");

        // Render using semantic table renderer
        ApplicationTableRenderer.RenderToTable(semanticRows, showExtended: false);
        ApplicationTableRenderer.RenderPostTableRows(semanticRows);

        if (settings.Detailed)
        {
            AnsiConsole.WriteLine();
            DisplayDetailedApplicationInfo(applications);
        }

        return Task.FromResult(0);
    }

    /// <summary>
    /// Displays detailed information for each application.
    /// </summary>
    private static void DisplayDetailedApplicationInfo(IReadOnlyList<ApplicationInfo> applications)
    {
        foreach (var app in applications)
        {
            AnsiConsole.MarkupLine($"[bold]{app.Type}:[/] [cyan]{Convert.ToHexString(app.Aid)}[/]");
            AnsiConsole.MarkupLine($"  State: {app.LifecycleState}");
            AnsiConsole.MarkupLine($"  Privileges: {string.Join(", ", app.Privileges.Select(p => p.ToString()))}");
            if (!string.IsNullOrEmpty(app.Version.GetValueOrDefault()))
            {
                AnsiConsole.MarkupLine($"  Version: {app.Version.Value}");
            }
            if (app.AssociatedSecurityDomain.HasValue)
            {
                AnsiConsole.MarkupLine($"  Associated SD: {Convert.ToHexString(app.AssociatedSecurityDomain.Value)}");
            }
            AnsiConsole.WriteLine();
        }
    }

    private static int HandleError(SmartCardError error)
    {
        AnsiConsole.MarkupLine($"[red]Error getting applet status: {error.Message}[/]");
        return 1;
    }

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