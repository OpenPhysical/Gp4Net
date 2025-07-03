using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Services;
using Gp4Net.Tool.Infrastructure;
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
                StatusSubset.Applications);

            return await statusResult.MatchAsync(
                async applications => await ProcessApplications(applications, settings),
                error => Task.FromResult(HandleError(error, settings)));
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

        private int HandleError(SmartCardError error, Settings settings)
        {
            AnsiConsole.MarkupLine($"[red]Error listing applications: {error.Message}[/]");
            if (settings.Verbose && error.InnerException != null)
            {
                AnsiConsole.WriteException(error.InnerException);
            }
            return 1;
        }

        private IReadOnlyList<ApplicationInfo> FilterApplications(
            IReadOnlyList<ApplicationInfo> applications,
            string filter
        )
        {
            return filter.ToLowerInvariant() switch
            {
                "isd" => applications.Where(a => a.Type == ApplicationType.IssuerSecurityDomain).ToList(),
                "apps" or "applets" => applications.Where(a => a.Type == ApplicationType.Application).ToList(),
                "packages" => applications.Where(a => a.Type == ApplicationType.LoadFile).ToList(),
                "ssd" => applications.Where(a => a.Type == ApplicationType.SupplementarySecurityDomain).ToList(),
                _ => applications,
            };
        }

        private void DisplayTable(IReadOnlyList<ApplicationInfo> applications, bool extended)
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

        private void DisplayJson(IReadOnlyList<ApplicationInfo> applications)
        {
            var json = JsonSerializer.Serialize(
                applications.Select(a => new
                {
                    type = a.Type.ToString(),
                    aid = Convert.ToHexString(a.Aid),
                    state = a.LifecycleState.ToString(),
                    privileges = a.Privileges.Select(p => p.ToString()).ToArray(),
                    version = a.Version,
                    associatedSD = a.AssociatedSecurityDomain != null
                        ? Convert.ToHexString(a.AssociatedSecurityDomain)
                        : null,
                }),
                new JsonSerializerOptions { WriteIndented = true }
            );

            Console.WriteLine(json);
        }

        private void DisplayCsv(IReadOnlyList<ApplicationInfo> applications)
        {
            Console.WriteLine("Type,AID,State,Privileges,Version,AssociatedSD");

            foreach (var app in applications)
            {
                Console.WriteLine(
                    $"{app.Type},"
                        + $"{Convert.ToHexString(app.Aid)},"
                        + $"{app.LifecycleState},"
                        + $"\"{string.Join(";", app.Privileges.Select(p => p.ToString()))}\","
                        + $"{app.Version ?? ""},"
                        + $"{(app.AssociatedSecurityDomain != null ? Convert.ToHexString(app.AssociatedSecurityDomain) : "")}"
                );
            }
        }

        private string GetTypeDisplay(ApplicationType type)
        {
            return type switch
            {
                ApplicationType.IssuerSecurityDomain => "[red]ISD[/]",
                ApplicationType.SupplementarySecurityDomain => "[yellow]SSD[/]",
                ApplicationType.Application => "[green]App[/]",
                ApplicationType.LoadFile => "[blue]Pkg[/]",
                _ => type.ToString(),
            };
        }

        private string GetStateDisplay(LifecycleState state)
        {
            return state switch
            {
                LifecycleState.Selectable => "[green]Selectable[/]",
                LifecycleState.Personalized => "[blue]Personalized[/]",
                LifecycleState.Blocked => "[red]Blocked[/]",
                LifecycleState.Locked => "[red]Locked[/]",
                _ => state.ToString(),
            };
        }

        private string GetPrivilegesDisplay(ImmutableList<Privilege> privileges)
        {
            if (privileges.Count == 0)
            {
                return "[dim]-[/]";
            }

            if (privileges.Count <= 3)
            {
                return string.Join(", ", privileges.Select(p => p.ToString()));
            }

            return $"{string.Join(", ", privileges.Take(2).Select(p => p.ToString()))}, [dim]+{privileges.Count - 2} more[/]";
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
