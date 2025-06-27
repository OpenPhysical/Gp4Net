using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
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
        public StatusCommand(ICardService cardService, IGlobalPlatformService globalPlatformService)
            : base(cardService, globalPlatformService)
        {
        }

        /// <inheritdoc />
        protected override Task<int> ExecuteCommandAsync(CommandContext context, Settings settings)
        {
            if (!EnsureCardConnection(settings))
            {
                return Task.FromResult(1);
            }

            if (!settings.NoCardInfo)
            {
                DisplayCardInfo();
            }

            try
            {
                var applications = GlobalPlatformService.GetApplications();

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

                foreach (var app in applications.OrderBy(a => a.Type).ThenBy(a => System.Convert.ToHexString(a.Aid)))
                {
                    var typeColor = app.Type switch
                    {
                        ApplicationType.IssuerSecurityDomain => "blue",
                        ApplicationType.SupplementarySecurityDomain => "purple",
                        ApplicationType.Applet => "green",
                        ApplicationType.LoadFile => "yellow",
                        _ => "white"
                    };

                    var stateColor = app.LifecycleState switch
                    {
                        LifecycleState.Selectable => "green",
                        LifecycleState.Personalized => "cyan",
                        LifecycleState.Blocked => "red",
                        LifecycleState.Locked => "red",
                        _ => "yellow"
                    };

                    table.AddRow(
                        $"[{typeColor}]{GetTypeDisplayName(app.Type)}[/]",
                        $"[dim]{System.Convert.ToHexString(app.Aid)}[/]",
                        $"[{stateColor}]{app.LifecycleState}[/]",
                        $"0x{app.Privileges:X2}"
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
            catch (System.Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error getting applet status: {ex.Message}[/]");
                return Task.FromResult(1);
            }
        }

        private static string GetTypeDisplayName(ApplicationType type)
        {
            return type switch
            {
                ApplicationType.IssuerSecurityDomain => "ISD",
                ApplicationType.SupplementarySecurityDomain => "SSD",
                ApplicationType.Applet => "Applet",
                ApplicationType.LoadFile => "Load File",
                _ => "Unknown"
            };
        }

        private static void DisplayDetailedInformation(System.Collections.Generic.IList<ApplicationInfo> applications)
        {
            var groups = applications.GroupBy(a => a.Type);

            foreach (var group in groups)
            {
                AnsiConsole.MarkupLine($"[bold]{group.Key}s:[/]");
                
                foreach (var app in group)
                {
                    var panel = new Panel($"[dim]AID:[/] {System.Convert.ToHexString(app.Aid)}\n" +
                                         $"[dim]State:[/] {app.LifecycleState}\n" +
                                         $"[dim]Privileges:[/] 0x{app.Privileges:X2}")
                    {
                        Header = new PanelHeader($"[bold]{GetTypeDisplayName(app.Type)}[/]")
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