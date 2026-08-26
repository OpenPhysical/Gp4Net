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
using Gp4Net.Tool.Extensions;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Command to list applications on the card using library services.
/// Tool handles display, library provides data.
/// </summary>
[PublicAPI]
[CliCommand("list", "List applications on the card", "applet")]
[CommandHandler]
[Description("List applications on the card")]
public class ListCliCommand : IPipelineCommand<ListCliCommand.Settings>
{
    /// <summary>
    /// Executes the list command using library services for data and tool for display.
    /// </summary>
    /// <param name="context">The command context.</param>
    /// <param name="settings">The command settings.</param>
    /// <returns>0 if successful, 1 if failed.</returns>
    public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
    {
        var connected = await context.RequireCardConnection(settings.GetReaderName());
        if (connected.IsFailure)
        {
            context.Display.Error($"Card connection failed: {connected.Error.Message}");
            return 1;
        }

        var secured = await connected.Value.RequireSecureChannel(settings.ToSecureChannelRequest());
        if (secured.IsFailure)
        {
            context.Display.Error($"Secure channel establishment failed: {secured.Error.Message}");
            return 1;
        }

        var result = await Applications.RetrieveCompleteCardContentAsync(
            (command, ct) => secured.Value.CardService.ExecuteCommandAsync(command, ct),
            CancellationToken.None
        );
        if (result.IsFailure)
        {
            context.Display.Error($"Application listing failed: {result.Error.Message}");
            return 1;
        }

        ProcessApplications(ToApplicationInfos(result.Value), settings);
        return 0;
    }

    private static IReadOnlyList<ApplicationInfo> ToApplicationInfos(CardContent content)
    {
        var applications = new List<ApplicationInfo>();
        content.IssuerSecurityDomain.Execute(applications.Add);
        applications.AddRange(content.SecurityDomains);
        applications.AddRange(content.Applications);
        applications.AddRange(
            content.ExecutableLoadFiles.Select(loadFile =>
                new ApplicationInfo(
                    loadFile.Aid,
                    (byte)loadFile.LifecycleState,
                    ImmutableList<Privilege>.Empty,
                    ApplicationType.ExecutableLoadFile,
                    loadFile.Version,
                    loadFile.AssociatedSecurityDomainAid
                )
            )
        );
        return applications;
    }

    /// <summary>
    /// Processes applications for display using functional composition.
    /// </summary>
    private static void ProcessApplications(
        IReadOnlyList<ApplicationInfo> applications,
        Settings settings
    )
    {
        IReadOnlyList<ApplicationInfo> filtered = ApplicationTableBuilder.ApplyFilter(
            applications,
            settings.Filter
        );
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
                string json = ApplicationTableBuilder.ToJson(filtered);
                AnsiConsole.WriteLine(json);
                break;

            case "csv":
                string csv = ApplicationTableBuilder.ToCsv(filtered);
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
