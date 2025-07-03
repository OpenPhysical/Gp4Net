using System;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Services;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet
{
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
                StatusSubset.Applications);

            return await statusResult.MatchAsync(
                async applications => await DisplayApplications(applications, settings),
                failure => Task.FromResult(HandleError(failure)));
        }

        private Task<int> DisplayApplications(ImmutableList<ApplicationInfo> applications, Settings settings)
        {
            if (applications.Count == 0)
            {
                AnsiConsole.MarkupLine("[yellow]No applets found on card[/]");
                return Task.FromResult(0);
            }

            AnsiConsole.MarkupLine($"[green]Found {applications.Count} applet(s) on card:[/]");

            var table = new Table()
                .AddColumn("Type")
                .AddColumn("AID")
                .AddColumn("Lifecycle State")
                .AddColumn("Privileges");

            foreach (var app in applications
                .OrderBy(a => a.Type)
                .ThenBy(a => Convert.ToHexString(a.Aid)))
            {
                var typeColor = app.Type switch
                {
                    ApplicationType.IssuerSecurityDomain => "blue",
                    ApplicationType.SupplementarySecurityDomain => "purple",
                    ApplicationType.Application => "green",
                    ApplicationType.LoadFile => "yellow",
                    _ => "white",
                };

                var stateColor = app.LifecycleState switch
                {
                    LifecycleState.Selectable => "green",
                    LifecycleState.Personalized => "cyan",
                    LifecycleState.Blocked => "red",
                    LifecycleState.Locked => "red",
                    _ => "yellow",
                };

                var privilegesText = app.Privileges.Count > 0 
                    ? string.Join(", ", app.Privileges.Select(p => p.ToString()))
                    : "None";

                table.AddRow(
                    $"[{typeColor}]{GetTypeDisplayName(app.Type)}[/]",
                    $"[dim]{app.AidHex}[/]",
                    $"[{stateColor}]{app.LifecycleState}[/]",
                    privilegesText
                );
            }

            AnsiConsole.Write(table);

            if (settings.Detailed)
            {
                AnsiConsole.WriteLine();
                DisplayDetailedInformation(applications);
            }

            return Task.FromResult(0);
        }

        private int HandleError(SmartCardError error)
        {
            AnsiConsole.MarkupLine($"[red]Error getting applet status: {error.Message}[/]");
            return 1;
        }

        private static string GetTypeDisplayName(ApplicationType type)
        {
            return type switch
            {
                ApplicationType.IssuerSecurityDomain => "ISD",
                ApplicationType.SupplementarySecurityDomain => "SSD",
                ApplicationType.Application => "Applet",
                ApplicationType.LoadFile => "Load File",
                _ => "Unknown",
            };
        }

        private static void DisplayDetailedInformation(ImmutableList<ApplicationInfo> applications)
        {
            var groups = applications.GroupBy(a => a.Type);

            foreach (var group in groups)
            {
                AnsiConsole.MarkupLine($"[bold]{group.Key}s:[/]");

                foreach (var app in group)
                {
                    var panel = new Panel(
                        $"[dim]AID:[/] {System.Convert.ToHexString(app.Aid)}\n"
                            + $"[dim]State:[/] {app.LifecycleState}\n"
                            + $"[dim]Privileges:[/] {(app.Privileges.Count > 0 ? string.Join(", ", app.Privileges) : "None")}"
                    )
                    {
                        Header = new PanelHeader($"[bold]{GetTypeDisplayName(app.Type)}[/]"),
                    };

                    AnsiConsole.Write(panel);
                }

                AnsiConsole.WriteLine();
            }
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
}
