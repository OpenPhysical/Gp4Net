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
using Gp4Net.Services.GlobalPlatform;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Command to get the status of applets on the card.
/// </summary>
[PublicAPI]
[CommandHandler]
public class StatusCommand : IPipelineCommand<StatusCommand.Settings>
{
    /// <summary>
    /// Executes the status command to display the status of applications on the card.
    /// </summary>
    /// <param name="context">The CLI execution context.</param>
    /// <param name="settings">The command settings.</param>
    /// <returns>0 if successful, 1 if failed.</returns>
    public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
    {
        return await context.ExecuteAsync(async ctx =>
        {
            ctx.Display.Info("Starting applet status retrieval...");

            if (!settings.NoCardInfo)
            {
                await DisplayCardInfoAsync(ctx);
            }

            var statusResult = await RetrieveApplicationStatus(ctx);
            return await statusResult.Match(
                async applications => await ProcessApplications(ctx, applications, settings),
                error =>
                {
                    ctx.Display.Error($"Failed to get applet status: {error.Message}");
                    return Task.FromResult(1);
                }
            );
        });
    }

    private static Task DisplayCardInfoAsync(ICliExecutionContext context)
    {
        context.Display.Info("Card information display would go here");
        return Task.CompletedTask;
    }

    private static async Task<
        Result<ImmutableList<ApplicationInfo>, SmartCardError>
    > RetrieveApplicationStatus(ICliExecutionContext context)
    {
        return await Applications.GetApplicationsAndSecurityDomainsAsync(
            (command, ct) => context.CardService.ExecuteCommandAsync(command, ct),
            CancellationToken.None
        );
    }

    private static Task<int> ProcessApplications(
        ICliExecutionContext context,
        ImmutableList<ApplicationInfo> applications,
        Settings settings
    )
    {
        return Task.FromResult(DisplayApplications(context, applications, settings));
    }

    private static int DisplayApplications(
        ICliExecutionContext context,
        ImmutableList<ApplicationInfo> applications,
        Settings settings
    )
    {
        // Build semantic rows using pure functional composition
        List<ApplicationTableBuilder.ApplicationRow> semanticRows =
        [
            .. ApplicationTableBuilder.BuildApplicationRows(
                applications,
                showExtended: false,
                showSummary: true,
                filter: null
            ),
        ];

        // Check if we have any applications to display
        List<ApplicationTableBuilder.ApplicationDataRow> applicationRows =
        [
            .. semanticRows.OfType<ApplicationTableBuilder.ApplicationDataRow>(),
        ];
        if (!applicationRows.Any())
        {
            context.Display.Warning("No applets found on card");
            return 0;
        }

        context.Display.Success($"Found {applications.Count} applet(s) on card:");

        // Render using semantic table renderer
        ApplicationTableRenderer.RenderToTable(semanticRows, showExtended: false);
        ApplicationTableRenderer.RenderPostTableRows(semanticRows);

        if (settings.Detailed)
        {
            DisplayDetailedApplicationInfo(context, applications);
        }

        return 0;
    }

    /// <summary>
    /// Displays detailed information for each application using Spectre.Console formatting.
    /// </summary>
    private static void DisplayDetailedApplicationInfo(
        ICliExecutionContext context,
        IReadOnlyList<ApplicationInfo> applications
    )
    {
        List<Table> tables = [.. applications.Select(CreateApplicationDetailsTable)];

        // Display all tables functionally by writing them to console
        bool displayResult = tables
            .Select(table =>
            {
                AnsiConsole.Write(table);
                return true;
            })
            .All(success => success);
    }

    private static Table CreateApplicationDetailsTable(ApplicationInfo app)
    {
        var table = new Table()
            .AddColumn("Property")
            .AddColumn("Value")
            .Title($"[bold]{app.Type}: [cyan]{Convert.ToHexString(app.Aid)}[/][/]")
            .Border(TableBorder.Rounded);

        _ = table.AddRow("State", $"[yellow]{app.LifecycleState}[/]");
        _ = table.AddRow("Privileges", string.Join(", ", app.Privileges.Select(p => p.ToString())));

        app.Version.Match(version => table.AddRow("Version", $"[green]{version}[/]"), () => { });

        app.AssociatedSecurityDomain.Match(
            securityDomain =>
                table.AddRow("Associated SD", $"[dim]{Convert.ToHexString(securityDomain)}[/]"),
            () => { }
        );

        return table;
    }

    /// <summary>
    /// Settings for the status command.
    /// </summary>
    public class Settings : CommandSettings
    {
        /// <summary>
        /// Gets or sets a value indicating whether to show detailed information.
        /// </summary>
        [CommandOption("-d|--detailed")]
        [Description("Show detailed applet information")]
        public bool Detailed { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to skip card info display.
        /// </summary>
        [CommandOption("--no-card-info")]
        [Description("Skip card information display")]
        public bool NoCardInfo { get; set; }
    }
}
