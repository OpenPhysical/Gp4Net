using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet
{
    /// <summary>
    /// Command to list applications on the card.
    /// </summary>
    [PublicAPI]
    /// <summary>
    /// Command to list applications installed on a GlobalPlatform card.
    /// </summary>
    [Description("List applications on the card")]
    public class ListCommand : BaseCommand<ListCommand.Settings>
    {
        /// <summary>
        /// Initializes a new instance of the ListCommand class.
        /// </summary>
        public ListCommand(
            ICardService cardService,
            IGlobalPlatformService globalPlatformService,
            IKeysetResolver keysetResolver
        )
            : base(cardService, globalPlatformService, keysetResolver) { }

        /// <summary>
        /// Executes the list command to enumerate applications on the card.
        /// </summary>
        /// <param name="context">The command context.</param>
        /// <param name="settings">The command settings.</param>
        /// <returns>0 if successful, 1 if failed.</returns>
        protected override Task<int> ExecuteCommandAsync(CommandContext context, Settings settings)
        {
            if (!EnsureCardConnection(settings))
            {
                return Task.FromResult(1);
            }

            // Optionally establish secure channel for more detailed information
            if (settings.RequiresSecureChannel && !EnsureSecureChannel(settings))
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

                // Apply filter
                if (!string.IsNullOrEmpty(settings.Filter) && settings.Filter != "all")
                {
                    applications = FilterApplications(applications, settings.Filter);
                }

                if (applications.Count == 0)
                {
                    AnsiConsole.MarkupLine("[yellow]No applications found[/]");
                    return Task.FromResult(0);
                }

                // Display based on format
                switch (settings.Format.ToLowerInvariant())
                {
                    case "json":
                        DisplayJson(applications);
                        break;

                    case "csv":
                        DisplayCsv(applications);
                        break;

                    case "table":
                    default:
                        DisplayTable(applications, settings.ShowExtended);
                        break;
                }

                if (settings.ShowSummary)
                {
                    AnsiConsole.WriteLine();
                    AnsiConsole.MarkupLine($"[dim]Total: {applications.Count} application(s)[/]");
                }

                return Task.FromResult(0);
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error listing applications: {ex.Message}[/]");
                if (settings.Verbose)
                {
                    AnsiConsole.WriteException(ex);
                }
                return Task.FromResult(1);
            }
        }

        private IList<ApplicationInfo> FilterApplications(
            IList<ApplicationInfo> applications,
            string filter
        )
        {
            return filter.ToLowerInvariant() switch
            {
                "isd" => [.. applications.Where(a => a.Type == "ISD")],
                "apps" or "applets" => [.. applications.Where(a => a.Type == "Application")],
                "packages" => [.. applications.Where(a => a.Type == "Package")],
                "ssd" => [.. applications.Where(a => a.Type == "SSD")],
                _ => applications,
            };
        }

        private void DisplayTable(IList<ApplicationInfo> applications, bool extended)
        {
            var table = new Table();

            // Basic columns
            _ = table.AddColumn("Type");
            _ = table.AddColumn("AID");
            _ = table.AddColumn("State");
            _ = table.AddColumn("Privileges");

            // Extended columns
            if (extended)
            {
                _ = table.AddColumn("Version");
                _ = table.AddColumn("Assoc. SD");
            }

            foreach (var app in applications)
            {
                var row = new List<string>
                {
                    GetTypeDisplay(app.Type),
                    $"[cyan]{Convert.ToHexString(app.Aid)}[/]",
                    GetStateDisplay(app.LifecycleState),
                    GetPrivilegesDisplay(app.Privileges),
                };

                if (extended)
                {
                    row.Add(app.Version ?? "-");
                    row.Add(
                        app.AssociatedSecurityDomain != null
                            ? Convert.ToHexString(app.AssociatedSecurityDomain)
                            : "-"
                    );
                }

                _ = table.AddRow(row.ToArray());
            }

            AnsiConsole.Write(table);
        }

        private void DisplayJson(IList<ApplicationInfo> applications)
        {
            var json = JsonSerializer.Serialize(
                applications.Select(a => new
                {
                    type = a.Type,
                    aid = Convert.ToHexString(a.Aid),
                    state = a.LifecycleState,
                    privileges = a.Privileges,
                    version = a.Version,
                    associatedSD = a.AssociatedSecurityDomain != null
                        ? Convert.ToHexString(a.AssociatedSecurityDomain)
                        : null,
                }),
                new JsonSerializerOptions { WriteIndented = true }
            );

            Console.WriteLine(json);
        }

        private void DisplayCsv(IList<ApplicationInfo> applications)
        {
            Console.WriteLine("Type,AID,State,Privileges,Version,AssociatedSD");

            foreach (var app in applications)
            {
                Console.WriteLine(
                    $"{app.Type},"
                        + $"{Convert.ToHexString(app.Aid)},"
                        + $"{app.LifecycleState},"
                        + $"\"{string.Join(";", app.Privileges)}\","
                        + $"{app.Version ?? ""},"
                        + $"{(app.AssociatedSecurityDomain != null ? Convert.ToHexString(app.AssociatedSecurityDomain) : "")}"
                );
            }
        }

        private string GetTypeDisplay(string type)
        {
            return type switch
            {
                "ISD" => "[red]ISD[/]",
                "SSD" => "[yellow]SSD[/]",
                "Application" => "[green]App[/]",
                "Package" => "[blue]Pkg[/]",
                _ => type,
            };
        }

        private string GetStateDisplay(string state)
        {
            return state.ToLowerInvariant() switch
            {
                "selectable" => "[green]Selectable[/]",
                "personalized" => "[blue]Personalized[/]",
                "blocked" => "[red]Blocked[/]",
                "locked" => "[red]Locked[/]",
                _ => state,
            };
        }

        private string GetPrivilegesDisplay(IEnumerable<string> privileges)
        {
            var privList = privileges.ToList();
            if (!privList.Any())
            {
                return "[dim]-[/]";
            }

            if (privList.Count <= 3)
            {
                return string.Join(", ", privList);
            }

            return $"{string.Join(", ", privList.Take(2))}, [dim]+{privList.Count - 2} more[/]";
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
}
