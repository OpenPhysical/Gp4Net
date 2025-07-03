using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.CapFile;
using Gp4Net.Services;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using log4net;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet
{
    /// <summary>
    /// Command to delete an applet from the card.
    /// </summary>
    [PublicAPI]
    [CliCommand("delete", "Delete an applet from the card", "applet")]
    [CliCommand("uninstall", "Uninstall an applet from the card (alias for delete)", "applet", isAlias: true)]
    public class DeleteCliCommand : BaseCommand<DeleteCliCommand.Settings>
    {
        private static new readonly ILog Logger = LogManager.GetLogger(typeof(DeleteCliCommand));

        /// <summary>
        /// Initializes a new instance of the DeleteCliCommand class.
        /// </summary>
        public DeleteCliCommand(
            ICardService cardService,
            Gp4Net.Services.IGlobalPlatformService globalPlatformService,
            IKeysetResolver keysetResolver
        )
            : base(cardService, globalPlatformService, keysetResolver) { }

        /// <summary>
        /// Executes the delete command to remove an application from the card.
        /// </summary>
        /// <param name="context">The command context.</param>
        /// <param name="settings">The command settings.</param>
        /// <returns>0 if successful, 1 if failed.</returns>
        protected override async Task<int> ExecuteCommandAsync(CommandContext context, Settings settings)
        {
            try
            {
                // Determine AIDs to delete
                var aidsToDelete = await DetermineAidsToDelete(settings);
                if (aidsToDelete.Count == 0)
                {
                    AnsiConsole.MarkupLine("[yellow]No AIDs to delete[/]");
                    return await Task.FromResult(0);
                }

                // Display what will be deleted
                DisplayDeletionPlan(aidsToDelete, settings);

                // Dry-run mode - exit after showing plan
                if (settings.DryRun)
                {
                    AnsiConsole.MarkupLine("[yellow]Dry-run mode - no changes made[/]");
                    return await Task.FromResult(0);
                }

                // Confirm deletion
                if (!settings.Force && !ConfirmDeletion(aidsToDelete))
                {
                    AnsiConsole.MarkupLine("[yellow]Operation cancelled[/]");
                    return await Task.FromResult(0);
                }

                // Connect to card
                if (!EnsureCardConnection(settings))
                {
                    return await Task.FromResult(1);
                }

                // Establish secure channel for deletion
                if (!EnsureSecureChannel(settings))
                {
                    return await Task.FromResult(1);
                }

                // Display card info if requested
                if (!settings.NoCardInfo)
                {
                    DisplayCardInfo();
                }

                // Perform deletions
                return await PerformDeletions(aidsToDelete, settings);
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error: {ex.Message}[/]");
                if (settings.Verbose || settings.Debug)
                {
                    AnsiConsole.WriteException(ex);
                }
                return 1;
            }
        }

        private Task<List<(byte[] Aid, string Description, string Source)>> DetermineAidsToDelete(
            Settings settings
        )
        {
            var aidsToDelete = new List<(byte[] Aid, string Description, string Source)>();

            // Option 1: AIDs specified directly
            if (settings.Aids != null && settings.Aids.Any())
            {
                foreach (var aidString in settings.Aids)
                {
                    try
                    {
                        var aid = Convert.FromHexString(aidString);
                        aidsToDelete.Add((aid, $"Applet/Package {aidString}", "Command line"));
                    }
                    catch
                    {
                        throw new ArgumentException($"Invalid AID format: {aidString}");
                    }
                }
            }

            // Option 2: CAP file specified
            if (!string.IsNullOrEmpty(settings.CapFile))
            {
                var capAids = ExtractAidsFromCapFile(settings.CapFile, settings.DeleteRelated).Result;
                aidsToDelete.AddRange(capAids);
            }

            // Option 3: Interactive mode
            if (settings.Interactive)
            {
                var interactiveAids = GetInteractiveAids().Result;
                aidsToDelete.AddRange(interactiveAids);
            }

            return Task.FromResult(aidsToDelete);
        }

        private Task<List<(byte[] Aid, string Description, string Source)>> ExtractAidsFromCapFile(
            string capFilePath,
            bool deleteRelated
        )
        {
            if (!File.Exists(capFilePath))
            {
                throw new FileNotFoundException($"CAP file not found: {capFilePath}");
            }

            AnsiConsole.MarkupLine($"[cyan]Reading CAP file: {capFilePath}[/]");

            var capData = File.ReadAllBytes(capFilePath);
            var capFile = CapFileStructure.Parse(capData);

            var aids = new List<(byte[] Aid, string Description, string Source)>();

            // Add package AID
            aids.Add((
                capFile.PackageAid,
                $"Package {Convert.ToHexString(capFile.PackageAid)}",
                Path.GetFileName(capFilePath)
            ));

            // Add applet AIDs only if we're not deleting related objects
            // (because deleting package with related will delete applets too)
            if (!deleteRelated)
            {
                foreach (var applet in capFile.Applets)
                {
                    aids.Add((
                        applet.Aid,
                        $"Applet {Convert.ToHexString(applet.Aid)}",
                        Path.GetFileName(capFilePath)
                    ));
                }
            }

            if (Logger.IsDebugEnabled)
            {
                Logger.Debug($"Found {aids.Count} AIDs in CAP file:");
                foreach (var (aid, desc, _) in aids)
                {
                    Logger.Debug($"  - {Convert.ToHexString(aid)}: {desc}");
                }
                if (deleteRelated && capFile.Applets.Count > 0)
                {
                    Logger.Debug($"  (Skipped {capFile.Applets.Count} applet AIDs - will be deleted with package)");
                }
            }

            return Task.FromResult(aids);
        }

        private async Task<List<(byte[] Aid, string Description, string Source)>> GetInteractiveAids()
        {
            if (!EnsureCardConnection(new Settings { Verbose = false }))
            {
                throw new InvalidOperationException("Failed to connect to card for interactive mode");
            }

            if (!EnsureSecureChannel(new Settings { Verbose = false }))
            {
                throw new InvalidOperationException("Failed to establish secure channel for interactive mode");
            }

            var statusResult = await GlobalPlatformService.GetStatusAsync(StatusSubset.Applications);
            
            var applications = await statusResult.MatchAsync<IReadOnlyList<ApplicationInfo>>(
                apps => Task.FromResult<IReadOnlyList<ApplicationInfo>>(apps),
                error => 
                {
                    AnsiConsole.MarkupLine($"[red]Error getting applications: {error.Message}[/]");
                    return Task.FromResult<IReadOnlyList<ApplicationInfo>>(new List<ApplicationInfo>());
                });

            if (applications.Count == 0)
            {
                AnsiConsole.MarkupLine("[yellow]No applications found on card[/]");
                return new List<(byte[] Aid, string Description, string Source)>();
            }

            // Create multi-selection prompt
            var prompt = new MultiSelectionPrompt<ApplicationInfo>()
                .Title("Select applications to delete:")
                .PageSize(10)
                .MoreChoicesText("[grey](Move up and down to reveal more applications)[/]")
                .InstructionsText(
                    "[grey](Press [blue]<space>[/] to toggle, " +
                    "[green]<enter>[/] to accept)[/]"
                )
                .AddChoices(applications)
                .UseConverter(app =>
                    $"{Convert.ToHexString(app.Aid)} ({app.Type}) - {app.LifecycleState}"
                );

            var selected = AnsiConsole.Prompt(prompt);

            return selected
                .Select(app => (
                    app.Aid,
                    $"{app.Type} {Convert.ToHexString(app.Aid)}",
                    "Interactive selection"
                ))
                .ToList();
        }

        private void DisplayDeletionPlan(
            List<(byte[] Aid, string Description, string Source)> aidsToDelete,
            Settings settings
        )
        {
            var table = new Table()
                .Title("Deletion Plan")
                .AddColumn("AID")
                .AddColumn("Description")
                .AddColumn("Source")
                .AddColumn("Options");

            foreach (var (aid, description, source) in aidsToDelete)
            {
                var options = new List<string>();
                if (settings.DeleteRelated)
                {
                    options.Add("Delete related");
                }
                if (settings.DryRun)
                {
                    options.Add("DRY RUN");
                }

                table.AddRow(
                    $"[yellow]{Convert.ToHexString(aid)}[/]",
                    description,
                    $"[dim]{source}[/]",
                    string.Join(", ", options)
                );
            }

            AnsiConsole.Write(table);
            
            // Show note about delete related behavior with CAP files
            if (!string.IsNullOrEmpty(settings.CapFile) && settings.DeleteRelated && aidsToDelete.Count == 1)
            {
                AnsiConsole.MarkupLine("\n[dim]Note: Only deleting the package AID. Applets will be deleted automatically with 'Delete related' option.[/]");
            }

            if (settings.Debug)
            {
                AnsiConsole.MarkupLine("\n[dim]Debug information:[/]");
                AnsiConsole.MarkupLine($"[dim]  Delete related objects: {settings.DeleteRelated}[/]");
                AnsiConsole.MarkupLine($"[dim]  Force mode: {settings.Force}[/]");
                AnsiConsole.MarkupLine($"[dim]  Dry-run mode: {settings.DryRun}[/]");
                AnsiConsole.MarkupLine($"[dim]  Total objects to delete: {aidsToDelete.Count}[/]");
            }
        }

        private bool ConfirmDeletion(List<(byte[] Aid, string Description, string Source)> aidsToDelete)
        {
            var message = aidsToDelete.Count == 1
                ? $"Are you sure you want to delete {aidsToDelete[0].Description}?"
                : $"Are you sure you want to delete {aidsToDelete.Count} objects?";

            return AnsiConsole.Confirm(message);
        }

        private async Task<int> PerformDeletions(
            List<(byte[] Aid, string Description, string Source)> aidsToDelete,
            Settings settings
        )
        {
            var successCount = 0;
            var failureCount = 0;

            await AnsiConsole.Progress()
                .StartAsync(async ctx =>
                {
                    var task = ctx.AddTask("[green]Deleting objects[/]", maxValue: aidsToDelete.Count);

                    foreach (var (aid, description, _) in aidsToDelete)
                    {
                        task.Description = $"Deleting {description}";

                        if (settings.Debug)
                        {
                            Logger.Debug($"Deleting AID: {Convert.ToHexString(aid)}");
                            Logger.Debug($"  Delete related: {settings.DeleteRelated}");
                        }

                        try
                        {
                            var result = await GlobalPlatformService.DeleteApplicationAsync(aid, settings.DeleteRelated);

                            await result.MatchAsync<object>(
                                async unit =>
                                {
                                    successCount++;
                                    AnsiConsole.MarkupLine($"[green]✓ Deleted {description}[/]");
                                    return Task.CompletedTask;
                                },
                                async error =>
                                {
                                    AnsiConsole.MarkupLine($"[red]✗ Failed to delete {description}: {error.Message}[/]");
                                    if (settings.Debug && error.InnerException != null)
                                    {
                                        AnsiConsole.WriteException(error.InnerException);
                                    }
                                    return Task.CompletedTask;
                                });

                        }
                        catch (Exception ex)
                        {
                            failureCount++;
                            AnsiConsole.MarkupLine($"[red]✗ Error deleting {description}: {ex.Message}[/]");
                            
                            if (settings.Debug)
                            {
                                Logger.Error($"Exception deleting {Convert.ToHexString(aid)}", ex);
                            }
                        }

                        task.Increment(1);
                    }
                });

            // Summary
            AnsiConsole.WriteLine();
            if (failureCount == 0)
            {
                AnsiConsole.MarkupLine($"[green]Successfully deleted {successCount} object(s)[/]");
                return 0;
            }
            else if (successCount > 0)
            {
                AnsiConsole.MarkupLine(
                    $"[yellow]Partially successful: {successCount} deleted, {failureCount} failed[/]"
                );
                return 1;
            }
            else
            {
                AnsiConsole.MarkupLine($"[red]Failed to delete all {failureCount} object(s)[/]");
                return 1;
            }
        }

        /// <summary>
        /// Settings for the delete command.
        /// </summary>
        public class Settings : BaseCommandSettings
        {
            /// <summary>
            /// Gets or sets the AIDs to delete.
            /// </summary>
            [CommandOption("--aid")]
            [Description("AID to delete (hex string). Can be specified multiple times.")]
            public string[]? Aids { get; set; }

            /// <summary>
            /// Gets or sets the CAP file to extract AIDs from.
            /// </summary>
            [CommandOption("--cap")]
            [Description("CAP file to extract AIDs from for deletion")]
            public string? CapFile { get; set; }

            /// <summary>
            /// Gets or sets a value indicating whether to use interactive mode.
            /// </summary>
            [CommandOption("-i|--interactive")]
            [Description("Interactive mode - select from installed applets")]
            public bool Interactive { get; set; }

            /// <summary>
            /// Gets or sets a value indicating whether to delete related objects.
            /// </summary>
            [CommandOption("--no-delete-related")]
            [Description("Don't delete related objects")]
            public bool NoDeleteRelated { get; set; }

            /// <summary>
            /// Gets a value indicating whether to delete related objects.
            /// </summary>
            public bool DeleteRelated => !NoDeleteRelated;

            /// <summary>
            /// Gets or sets a value indicating whether to force deletion without confirmation.
            /// </summary>
            [CommandOption("-f|--force")]
            [Description("Force deletion without confirmation")]
            public bool Force { get; set; }

            /// <summary>
            /// Gets or sets a value indicating whether to run in dry-run mode.
            /// </summary>
            [CommandOption("--dry-run")]
            [Description("Show what would be deleted without actually deleting")]
            public bool DryRun { get; set; }

            /// <summary>
            /// Gets or sets a value indicating whether to enable debug output.
            /// </summary>
            [CommandOption("--debug")]
            [Description("Enable debug output for troubleshooting")]
            public bool Debug { get; set; }

            /// <summary>
            /// Validates the command settings.
            /// </summary>
            /// <returns>Success if valid, or an error message if validation fails.</returns>
            public override ValidationResult Validate()
            {
                // At least one source of AIDs must be specified
                var hasAids = Aids != null && Aids.Length > 0;
                var hasCapFile = !string.IsNullOrWhiteSpace(CapFile);
                var hasInteractive = Interactive;

                if (!hasAids && !hasCapFile && !hasInteractive)
                {
                    return ValidationResult.Error(
                        "Specify at least one AID, use --cap with a CAP file, or use --interactive mode"
                    );
                }

                // Validate direct AIDs
                if (hasAids)
                {
                    foreach (var aid in Aids!)
                    {
                        try
                        {
                            _ = Convert.FromHexString(aid);
                        }
                        catch
                        {
                            return ValidationResult.Error($"Invalid AID format: {aid}");
                        }
                    }
                }

                // Validate CAP file exists
                if (hasCapFile && !File.Exists(CapFile))
                {
                    return ValidationResult.Error($"CAP file not found: {CapFile}");
                }

                // Dry-run doesn't require secure channel
                if (DryRun && hasCapFile)
                {
                    // CAP file parsing doesn't need card connection in dry-run
                    return ValidationResult.Success();
                }

                return ValidationResult.Success();
            }

            /// <inheritdoc />
            public override bool RequiresSecureChannel => !DryRun; // Deletion requires secure channel unless dry-run
        }
    }
}