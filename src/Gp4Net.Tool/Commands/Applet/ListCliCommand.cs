using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using Gp4Net.Tool.Commands;
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
[Description("List applications on the card")]
public class ListCliCommand : BaseCommand<ListCliCommand.Settings>
{
    /// <summary>
    /// Initializes a new instance of the ListCliCommand class.
    /// </summary>
    public ListCliCommand(
        ICardService cardService,
        IDomainServiceFactory domainServiceFactory,
        IKeysetResolver keysetResolver
    )
        : base(cardService, domainServiceFactory, keysetResolver) { }

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

        if (!settings.NoCardInfo)
        {
            DisplayCardInfo();
        }

        // Use functional card content retriever for complete listing
        var contentRetriever = DomainServiceFactory.CreateCardContentRetriever(CardService);
        
        // Determine key set to use (default to GP test keys)
        var keySet = ResolveKeySetForRetrieval(settings);
        
        AnsiConsole.MarkupLine("[yellow]Retrieving complete card content...[/]");
        var contentResult = await contentRetriever.RetrieveCardContentAsync(keySet);

        if (contentResult.IsSuccess)
        {
            return await ProcessCardContent(contentResult.Value, settings);
        }
        else
        {
            return HandleError(contentResult.Error, settings);
        }
    }

    /// <summary>
    /// Resolves the key set to use for card content retrieval.
    /// </summary>
    private IKeySet ResolveKeySetForRetrieval(Settings settings)
    {
        // If specific keys are provided, use them
        if (settings.KeyEnc != null || settings.KeyMac != null || settings.KeyDek != null)
        {
            return KeysetResolver.ResolveKeyset(
                settings.Keyset,
                settings.KeysetParams,
                settings.KeyEnc,
                settings.KeyMac,
                settings.KeyDek,
                settings.KeyVersion,
                null);
        }

        // Use GP test keys by default
        return null; // CardContentRetriever will default to GP test keys
    }

    /// <summary>
    /// Processes the complete card content for display.
    /// </summary>
    private Task<int> ProcessCardContent(CardContent cardContent, Settings settings)
    {
        // Convert CardContent to legacy ApplicationInfo list for compatibility
        var allApplications = cardContent.AllApplications;
        
        // Add ISD to the list if present
        var applicationsWithIsd = cardContent.IssuerSecurityDomain.HasValue
            ? allApplications.Add(cardContent.IssuerSecurityDomain.Value)
            : allApplications;

        return ProcessApplications(applicationsWithIsd, settings);
    }

    private Task<int> ProcessApplications(IReadOnlyList<ApplicationInfo> applications, Settings settings)
    {
        // Build semantic rows using pure functional composition
        var semanticRows = ApplicationTableBuilder.BuildApplicationRows(
            applications,
            showExtended: settings.ShowExtended,
            showSummary: settings.ShowSummary,
            filter: settings.Filter
        ).ToList();

        // Display based on format using pure functions
        switch (settings.Format.ToLowerInvariant())
        {
            case "json":
                var json = ApplicationTableBuilder.ToJson(applications);
                AnsiConsole.WriteLine(json);
                break;

            case "csv":
                var csv = ApplicationTableBuilder.ToCsv(applications);
                AnsiConsole.WriteLine(csv);
                break;

            case "table":
            default:
                ApplicationTableRenderer.RenderToTable(semanticRows, settings.ShowExtended);
                ApplicationTableRenderer.RenderPostTableRows(semanticRows);
                break;
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
            get
            {
                return !NoSummary;
            }
        }

        /// <summary>
        /// Gets or sets whether to use secure channel.
        /// </summary>
        [CommandOption("--secure-channel")]
        [Description("Use secure channel for more detailed information")]
        public bool UseSecureChannel { get; set; }

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