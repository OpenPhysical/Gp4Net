using System.ComponentModel;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Services;
using Gp4Net.Tool.Infrastructure;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;
using StatusSubset = Gp4Net.Domain.Commands.GetStatusCommand.StatusSubset;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Command to list applications on the card using library services.
/// Tool handles display, library provides data.
/// </summary>
[PublicAPI]
[CliCommand("list", "List applications on the card", "applet")]
[Description("List applications on the card")]
public class ListCliCommand : AsyncCommand<ListCliCommand.Settings>
{
    private readonly IGlobalPlatformService _globalPlatformService;

    /// <summary>
    /// Initializes a new instance of the ListCliCommand class with direct service injection.
    /// </summary>
    public ListCliCommand(IGlobalPlatformService globalPlatformService)
    {
        _globalPlatformService = globalPlatformService;
    }

    /// <summary>
    /// Executes the list command using library services for data and tool for display.
    /// </summary>
    /// <param name="context">The command context.</param>
    /// <param name="settings">The command settings.</param>
    /// <returns>0 if successful, 1 if failed.</returns>
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings)
    {
        AnsiConsole.MarkupLine("[yellow]Listing applications on card...[/]");

        // Use injected service directly - no factory needed
        return await ExecuteWithService(_globalPlatformService, settings, context.CancellationToken);
    }

    /// <summary>
    /// Executes with the service using proper library/tool separation.
    /// </summary>
    private async Task<int> ExecuteWithService(
        IGlobalPlatformService service, 
        Settings settings, 
        CancellationToken cancellationToken)
    {
        // List command focuses only on applications - no card info display
        // Select ISD, establish secure channel, get applications
        return await service.SelectIsdAsync(cancellationToken)
            .Bind(async _ => await EstablishSecureChannelFromSettings(service, settings, cancellationToken))
            .Bind(async _ => await service.GetStatusAsync(StatusSubset.Applications, cancellationToken))
            .Match(
                applications => 
                {
                    ProcessApplications(applications, settings);
                    return 0;
                },
                error => HandleError(error, "Operation failed", settings));
    }

    /// <summary>
    /// Establishes secure channel from settings with functional patterns.
    /// </summary>
    private async Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelFromSettings(
        IGlobalPlatformService service, Settings settings, CancellationToken cancellationToken)
    {
        // Use pattern matching to check if all keys are provided
        return (settings.KeyEnc.HasValue && settings.KeyMac.HasValue && settings.KeyDek.HasValue) switch
        {
            true => 
                // All keys provided - extract them using pattern matching
                await settings.KeyEnc.Match(
                    async encKey => await settings.KeyMac.Match(
                        async macKey => await settings.KeyDek.Match(
                            async dekKey => await service.EstablishSecureChannelAsync(
                                encKey, macKey, dekKey,
                                settings.KeyVersion.Match(v => v, () => (byte)0x01),
                                cancellationToken: cancellationToken),
                            async () => Result.Failure<SecureChannelState, SmartCardError>(
                                SmartCardError.InvalidData("DEK key is required when using explicit keys"))),
                        async () => Result.Failure<SecureChannelState, SmartCardError>(
                            SmartCardError.InvalidData("MAC key is required when using explicit keys"))),
                    async () => Result.Failure<SecureChannelState, SmartCardError>(
                        SmartCardError.InvalidData("ENC key is required when using explicit keys"))),
            false => 
                // Use keyset specification
                await service.EstablishSecureChannelAsync(
                    settings.Keyset.Match(k => k, () => "gp_test_keys"),
                    keyVersion: settings.KeyVersion.Match(v => v, () => (byte)0x01),
                    cancellationToken: cancellationToken)
        };
    }


    /// <summary>
    /// Handles errors with proper tool-layer error display.
    /// </summary>
    private static int HandleError(SmartCardError error, string operation, Settings settings)
    {
        AnsiConsole.MarkupLine($"[red]{operation}: {error.Message}[/]");
        
        if (settings.Verbose && error.InnerException.HasValue)
        {
            error.InnerException.Match(
                exception => 
                {
                    AnsiConsole.MarkupLine("[red]Detailed error information:[/]");
                    AnsiConsole.WriteException(exception);
                    return true;
                },
                () => false);
        }
        
        return 1;
    }


    /// <summary>
    /// Processes applications for display using functional composition.
    /// </summary>
    private void ProcessApplications(IReadOnlyList<ApplicationInfo> applications, Settings settings)
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
                string json = ApplicationTableBuilder.ToJson(applications);
                AnsiConsole.WriteLine(json);
                break;

            case "csv":
                string csv = ApplicationTableBuilder.ToCsv(applications);
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

        /// <summary>
        /// Gets or sets the keyset specification.
        /// </summary>
        [CommandOption("--keyset")]
        [Description("Keyset specification")]
        public Maybe<string> Keyset { get; set; } = Maybe<string>.From("gp_test_keys");

        /// <summary>
        /// Gets or sets the encryption key.
        /// </summary>
        [CommandOption("--key-enc")]
        [Description("Encryption key (hex)")]
        public Maybe<string> KeyEnc { get; set; } = Maybe<string>.None;

        /// <summary>
        /// Gets or sets the MAC key.
        /// </summary>
        [CommandOption("--key-mac")]
        [Description("MAC key (hex)")]
        public Maybe<string> KeyMac { get; set; } = Maybe<string>.None;

        /// <summary>
        /// Gets or sets the DEK key.
        /// </summary>
        [CommandOption("--key-dek")]
        [Description("DEK key (hex)")]
        public Maybe<string> KeyDek { get; set; } = Maybe<string>.None;

        /// <summary>
        /// Gets or sets the key version.
        /// </summary>
        [CommandOption("--key-version")]
        [Description("Key version")]
        public Maybe<byte> KeyVersion { get; set; } = Maybe<byte>.From((byte)0x01);

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