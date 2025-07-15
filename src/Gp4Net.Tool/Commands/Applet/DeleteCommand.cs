using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.CapFile;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using log4net;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet
{
    /// <summary>
    /// Command to delete applications or packages from a GlobalPlatform smart card using the functional pipeline pattern.
    /// Supports deletion by AID, CAP file extraction, and interactive selection with comprehensive error handling.
    /// 
    /// This command implements the GlobalPlatform DELETE instruction per Card Specification v2.3.1 with proper
    /// cryptographic verification through secure channels. All operations follow the functional architecture
    /// pattern using Result&lt;T,E&gt; monads for explicit error handling.
    /// </summary>
    /// <remarks>
    /// <para><strong>Supported Operations:</strong></para>
    /// <list type="bullet">
    /// <item><description>Delete by specific AID with hex string input</description></item>
    /// <item><description>Delete package AID extracted from CAP file</description></item>
    /// <item><description>Interactive selection from applications on card</description></item>
    /// <item><description>Dry-run mode for safe operation preview</description></item>
    /// <item><description>Related object deletion (cascade delete for packages)</description></item>
    /// </list>
    /// 
    /// <para><strong>Security Requirements:</strong></para>
    /// <list type="bullet">
    /// <item><description>Requires established secure channel (SCP02/SCP03)</description></item>
    /// <item><description>DELETE command uses authenticated encryption</description></item>
    /// <item><description>Proper authentication with card management keys</description></item>
    /// </list>
    /// 
    /// <para><strong>Error Handling:</strong></para>
    /// <para>All GlobalPlatform status words are mapped to human-readable error messages based on 
    /// the official specification. Common errors include application not found (0x6A82), 
    /// dependencies exist (0x6985), and security conditions not satisfied (0x6982).</para>
    /// </remarks>
    [PublicAPI]
    [CliCommand("delete", "Delete an applet from the card", "applet")]
    [CliCommand("uninstall", "Uninstall an applet from the card (alias for delete)", "applet", isAlias: true)]
    public class DeleteCommand : IPipelineCommand<DeleteCommand.Settings>
    {
        private static readonly ILog Logger = LogManager.GetLogger(typeof(DeleteCommand));

        /// <summary>
        /// Executes the delete command to remove applications or packages from the GlobalPlatform smart card.
        /// </summary>
        /// <param name="context">The command execution context providing access to card services and configuration.</param>
        /// <param name="settings">The command settings specifying what to delete and how to delete it.</param>
        /// <returns>
        /// A task representing the asynchronous operation. The result is:
        /// <list type="bullet">
        /// <item><description>0 if all deletions succeeded</description></item>
        /// <item><description>1 if any deletion failed or validation error occurred</description></item>
        /// </list>
        /// </returns>
        /// <remarks>
        /// <para>This method implements the complete deletion workflow:</para>
        /// <list type="number">
        /// <item><description>Validates input parameters and determines target AIDs</description></item>
        /// <item><description>Displays deletion plan with confirmation (unless forced)</description></item>
        /// <item><description>Establishes card connection and secure channel</description></item>
        /// <item><description>Executes DELETE commands with progress tracking</description></item>
        /// <item><description>Provides detailed success/failure reporting</description></item>
        /// </list>
        /// 
        /// <para>In dry-run mode, the method stops after displaying the deletion plan without 
        /// connecting to the card or executing any DELETE commands.</para>
        /// 
        /// <para>All errors are logged and human-readable error messages are displayed to the user
        /// based on GlobalPlatform specification status words.</para>
        /// </remarks>
        /// <exception cref="InvalidOperationException">Thrown when no deletion target is specified.</exception>
        /// <exception cref="FileNotFoundException">Thrown when a specified CAP file does not exist.</exception>
        public async Task<int> ExecuteAsync(ICommandContext context, Settings settings)
        {
            try
            {
                // Configure context
                var ctx = context.WithVerbose(settings.Verbose);
                
                // Determine AIDs to delete
                var aidsToDelete = await DetermineAidsToDelete(ctx, settings);
                if (aidsToDelete.Count == 0)
                {
                    AnsiConsole.MarkupLine("[yellow]No AIDs to delete[/]");
                    return 0;
                }

                // Display what will be deleted
                DisplayDeletionPlan(aidsToDelete, settings);

                // Dry-run mode - exit after showing plan
                if (settings.DryRun)
                {
                    AnsiConsole.MarkupLine("[yellow]Dry-run mode - no changes made[/]");
                    return 0;
                }

                // Confirm deletion
                if (!settings.Force && !ConfirmDeletion(aidsToDelete))
                {
                    AnsiConsole.MarkupLine("[yellow]Operation cancelled[/]");
                    return 0;
                }

                // Connect to card and establish secure channel
                ctx = await ctx.RequireCardConnection(settings);
                ctx = await ctx.RequireSecureChannel(settings);

                // Display card info if requested
                if (!settings.NoCardInfo)
                {
                    await DisplayCardInfo(ctx);
                }

                // Perform deletions
                return await PerformDeletions(ctx, aidsToDelete, settings);
            }
            catch (Exception ex)
            {
                Logger.Error("Error executing delete command", ex);
                AnsiConsole.MarkupLine($"[red]Error: {ex.Message}[/]");
                if (settings.Verbose || settings.Debug)
                {
                    AnsiConsole.WriteException(ex);
                }
                return 1;
            }
        }

        /// <summary>
        /// Determines the list of AIDs to delete based on the command settings.
        /// </summary>
        /// <param name="context">The command execution context for card operations.</param>
        /// <param name="settings">The command settings specifying the deletion source.</param>
        /// <returns>
        /// A task that returns a list of tuples containing:
        /// <list type="bullet">
        /// <item><description>Aid: The application identifier bytes</description></item>
        /// <item><description>Description: Human-readable description for display</description></item>
        /// <item><description>Source: The source of the AID (command line, CAP file, etc.)</description></item>
        /// </list>
        /// </returns>
        /// <remarks>
        /// <para>This method supports three modes of AID determination:</para>
        /// <list type="bullet">
        /// <item><description><strong>Direct AID:</strong> Uses the AID specified in settings.Aid</description></item>
        /// <item><description><strong>CAP File:</strong> Extracts package AID from the specified CAP file</description></item>
        /// <item><description><strong>Interactive:</strong> Prompts user to select from applications on card</description></item>
        /// </list>
        /// 
        /// <para>For CAP files, only the package AID is returned as deleting the package
        /// will cascade to delete all related applets when deleteRelated is true.</para>
        /// </remarks>
        /// <exception cref="InvalidOperationException">Thrown when no deletion target is specified.</exception>
        /// <exception cref="FileNotFoundException">Thrown when a CAP file is specified but does not exist.</exception>
        private async Task<List<(byte[] Aid, string Description, string Source)>> DetermineAidsToDelete(
            ICommandContext context,
            Settings settings)
        {
            var aidsToDelete = new List<(byte[] Aid, string Description, string Source)>();

            if (!string.IsNullOrEmpty(settings.Aid))
            {
                // Delete by specific AID
                var aid = Convert.FromHexString(settings.Aid);
                aidsToDelete.Add((aid, $"Application {settings.Aid}", "Command line"));
            }
            else if (!string.IsNullOrEmpty(settings.CapFile))
            {
                // Delete from CAP file
                aidsToDelete.AddRange(await GetAidsFromCapFile(settings.CapFile));
            }
            else if (settings.Interactive)
            {
                // Interactive selection
                aidsToDelete.AddRange(await GetInteractiveAids(context, settings));
            }
            else
            {
                throw new InvalidOperationException(
                    "No deletion target specified. Use --aid, --cap, or --interactive");
            }

            return aidsToDelete;
        }

        private async Task<List<(byte[] Aid, string Description, string Source)>> GetAidsFromCapFile(
            string capFilePath)
        {
            if (!File.Exists(capFilePath))
            {
                throw new FileNotFoundException($"CAP file not found: {capFilePath}");
            }

            var capData = await File.ReadAllBytesAsync(capFilePath);
            var validationResult = CapFileLoadingWorkflow.ValidateCapFile(capData);
            if (!validationResult.IsValid)
            {
                throw new InvalidOperationException($"Invalid CAP file: {validationResult.ErrorMessage}");
            }
            var capFile = validationResult.CapFile!;

            // For CAP files, we typically delete the package, not individual applets
            // The package deletion will cascade to delete all applets
            return new List<(byte[], string, string)>
            {
                (capFile.PackageAid, $"Package {Convert.ToHexString(capFile.PackageAid)}", capFilePath)
            };
        }

        private async Task<List<(byte[] Aid, string Description, string Source)>> GetInteractiveAids(
            ICommandContext context,
            Settings settings)
        {
            // Need to establish secure channel first for GET STATUS
            var ctx = await context.RequireCardConnection(settings);
            ctx = await ctx.RequireSecureChannel(settings);

            var statusResult = await ctx.GetGlobalPlatformService().GetStatusAsync(Gp4Net.Services.StatusSubset.Applications);
            
            var applications = await statusResult.MatchAsync(
                apps => Task.FromResult(apps),
                error => 
                {
                    AnsiConsole.MarkupLine($"[red]Error getting applications: {error.Message}[/]");
                    return Task.FromResult(ImmutableList<ApplicationInfo>.Empty);
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

            return ((IEnumerable<ApplicationInfo>)selected)
                .Select(app => (
                    app.Aid,
                    $"{app.Type} {Convert.ToHexString(app.Aid)}",
                    "Interactive selection"
                ))
                .ToList();
        }

        private void DisplayDeletionPlan(
            List<(byte[] Aid, string Description, string Source)> aidsToDelete,
            Settings settings)
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
            }
        }

        private bool ConfirmDeletion(List<(byte[] Aid, string Description, string Source)> aidsToDelete)
        {
            var message = aidsToDelete.Count == 1
                ? "Delete this application?"
                : $"Delete {aidsToDelete.Count} applications?";

            return AnsiConsole.Confirm(message);
        }

        private async Task<int> PerformDeletions(
            ICommandContext context,
            List<(byte[] Aid, string Description, string Source)> aidsToDelete,
            Settings settings)
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

                        var result = await context.GetGlobalPlatformService()
                            .DeleteApplicationAsync(aid, settings.DeleteRelated);

                        await result.MatchAsync<object>(
                            async unit =>
                            {
                                successCount++;
                                AnsiConsole.MarkupLine($"[green]✓ Deleted {description}[/]");
                                return new object();
                            },
                            async error =>
                            {
                                failureCount++;
                                var errorMessage = GetHumanReadableError(error);
                                AnsiConsole.MarkupLine($"[red]✗ Failed to delete {description}: {errorMessage}[/]");
                                
                                if (settings.Debug && error.InnerException != null)
                                {
                                    AnsiConsole.WriteException(error.InnerException);
                                }
                                return new object();
                            });

                        task.Increment(1);
                    }
                });

            // Summary
            AnsiConsole.WriteLine();
            if (successCount > 0)
            {
                AnsiConsole.MarkupLine($"[green]Successfully deleted {successCount} object(s)[/]");
            }
            if (failureCount > 0)
            {
                AnsiConsole.MarkupLine($"[red]Failed to delete {failureCount} object(s)[/]");
            }

            return failureCount > 0 ? 1 : 0;
        }

        /// <summary>
        /// Converts a SmartCardError to a human-readable error message based on GlobalPlatform specification status words.
        /// </summary>
        /// <param name="error">The smart card error containing the status word and message.</param>
        /// <returns>
        /// A descriptive error message suitable for display to users. If the status word is not recognized,
        /// returns the original error message.
        /// </returns>
        /// <remarks>
        /// <para>This method maps GlobalPlatform Card Specification v2.3.1 status words to user-friendly descriptions:</para>
        /// <list type="table">
        /// <listheader>
        /// <term>Status Word</term>
        /// <description>Meaning</description>
        /// </listheader>
        /// <item><term>0x6283</term><description>Application is locked (personalized state)</description></item>
        /// <item><term>0x6581</term><description>Memory allocation problem</description></item>
        /// <item><term>0x6982</term><description>Security status not satisfied</description></item>
        /// <item><term>0x6985</term><description>Cannot delete - application has dependencies</description></item>
        /// <item><term>0x6A80</term><description>Incorrect parameters in command data</description></item>
        /// <item><term>0x6A82</term><description>Application or package not found</description></item>
        /// <item><term>0x6A86</term><description>Incorrect P1/P2 parameters</description></item>
        /// <item><term>0x6A88</term><description>Referenced data not found</description></item>
        /// <item><term>0x6D00</term><description>Invalid instruction (DELETE not supported)</description></item>
        /// <item><term>0x6E00</term><description>Invalid class</description></item>
        /// <item><term>0x6F00</term><description>No precise diagnosis available</description></item>
        /// </list>
        /// </remarks>
        private string GetHumanReadableError(SmartCardError error)
        {
            // Map status words to human-readable messages based on GP spec
            return error.StatusWord switch
            {
                0x6283 => "Application is locked (personalized state)",
                0x6581 => "Memory allocation problem",
                0x6982 => "Security status not satisfied",
                0x6985 => "Cannot delete - application has dependencies",
                0x6A80 => "Incorrect parameters in command data",
                0x6A82 => "Application or package not found",
                0x6A86 => "Incorrect P1/P2 parameters", 
                0x6A88 => "Referenced data not found",
                0x6D00 => "Invalid instruction (DELETE not supported)",
                0x6E00 => "Invalid class",
                0x6F00 => "No precise diagnosis available",
                _ => error.Message
            };
        }

        private async Task DisplayCardInfo(ICommandContext context)
        {
            try
            {
                var selectResult = await context.GetGlobalPlatformService().SelectIsdAsync();
                await selectResult.MatchAsync<object>(
                    async response =>
                    {
                        AnsiConsole.MarkupLine($"[dim]ISD AID: {Convert.ToHexString(response.Fci?.ApplicationAid ?? [])}[/]");
                        return new object();
                    },
                    async _ => new object());
            }
            catch
            {
                // Ignore errors in card info display
            }
        }

        /// <summary>
        /// Configuration settings for the DELETE command, supporting multiple deletion modes and security options.
        /// Inherits card connection and authentication settings from CardCommandSettings.
        /// </summary>
        /// <remarks>
        /// <para>The Settings class provides three mutually exclusive modes for specifying what to delete:</para>
        /// <list type="bullet">
        /// <item><description><strong>Direct AID Mode:</strong> Delete a specific application by providing its AID as a hex string</description></item>
        /// <item><description><strong>CAP File Mode:</strong> Extract and delete the package AID from a CAP file</description></item>
        /// <item><description><strong>Interactive Mode:</strong> Select applications to delete from a list retrieved from the card</description></item>
        /// </list>
        /// 
        /// <para><strong>Security Considerations:</strong></para>
        /// <list type="bullet">
        /// <item><description>All deletion operations require an established secure channel</description></item>
        /// <item><description>Use Force mode carefully as it bypasses confirmation prompts</description></item>
        /// <item><description>DryRun mode is recommended for testing deletion plans safely</description></item>
        /// <item><description>DeleteRelated should be used with caution for package deletions</description></item>
        /// </list>
        /// 
        /// <para><strong>Best Practices:</strong></para>
        /// <list type="bullet">
        /// <item><description>Always use --dry-run first to preview deletion operations</description></item>
        /// <item><description>Enable --debug for detailed operation logging</description></item>
        /// <item><description>Use DeleteRelated=true for complete package removal</description></item>
        /// <item><description>Verify card state after deletion operations</description></item>
        /// </list>
        /// </remarks>
        public class Settings : SecureCommandSettings
        {
            /// <summary>
            /// Gets or sets the Application Identifier (AID) of the application to delete.
            /// Must be provided as a hexadecimal string without spaces or separators.
            /// </summary>
            /// <value>
            /// A hex string representing the AID (e.g., "A000000003000000"). 
            /// Null if not specified (other deletion modes will be used).
            /// </value>
            /// <example>
            /// <code>
            /// // Delete specific application
            /// settings.Aid = "A000000003000000";
            /// 
            /// // Delete applet instance  
            /// settings.Aid = "A000000003000001";
            /// </code>
            /// </example>
            [CommandOption("-a|--aid <AID>")]
            [Description("The AID of the application to delete (hex string)")]
            public string? Aid { get; set; }

            /// <summary>
            /// Gets or sets the path to a CAP file from which to extract the package AID for deletion.
            /// When specified, the command will parse the CAP file to determine the package AID and delete it.
            /// </summary>
            /// <value>
            /// A file path to a valid CAP file. The file must exist and be a valid Java Card CAP archive.
            /// Null if not specified (other deletion modes will be used).
            /// </value>
            /// <remarks>
            /// <para>When using CAP file deletion:</para>
            /// <list type="bullet">
            /// <item><description>Only the package AID is extracted and deleted</description></item>
            /// <item><description>Applets are deleted automatically if DeleteRelated is true</description></item>
            /// <item><description>The CAP file is only read, not modified</description></item>
            /// <item><description>File must be accessible and properly formatted</description></item>
            /// </list>
            /// </remarks>
            /// <example>
            /// <code>
            /// // Delete package from CAP file
            /// settings.CapFile = "/path/to/myapp.cap";
            /// settings.DeleteRelated = true;  // Also delete related applets
            /// </code>
            /// </example>
            [CommandOption("-c|--cap <FILE>")]
            [Description("Delete the package from the specified CAP file")]
            public string? CapFile { get; set; }

            /// <summary>
            /// Gets or sets whether to use interactive mode.
            /// </summary>
            [CommandOption("-i|--interactive")]
            [Description("Select applications to delete interactively")]
            public bool Interactive { get; set; }

            /// <summary>
            /// Gets or sets whether to delete related objects when deleting a package.
            /// When true, deleting a package will also delete all related applet instances.
            /// </summary>
            /// <value>
            /// <c>true</c> to delete related objects (default); <c>false</c> to delete only the specific object.
            /// </value>
            /// <remarks>
            /// <para>This setting corresponds to the P1 parameter of the GlobalPlatform DELETE command:</para>
            /// <list type="bullet">
            /// <item><description><c>true</c>: P1=0x00 (Delete object and related objects)</description></item>
            /// <item><description><c>false</c>: P1=0x80 (Delete object only)</description></item>
            /// </list>
            /// 
            /// <para><strong>Warning:</strong> When deleting packages with DeleteRelated=false, 
            /// related applets may become orphaned and unusable. This is typically not recommended
            /// for package deletions unless you have specific requirements.</para>
            /// </remarks>
            /// <example>
            /// <code>
            /// // Complete package removal (recommended)
            /// settings.DeleteRelated = true;   // Delete package and all applets
            /// 
            /// // Package-only deletion (advanced use case)
            /// settings.DeleteRelated = false;  // Leave applets orphaned
            /// </code>
            /// </example>
            [CommandOption("--delete-related")]
            [Description("Delete related objects (applets when deleting package)")]
            [DefaultValue(true)]
            public bool DeleteRelated { get; set; } = true;

            /// <summary>
            /// Gets or sets whether to force deletion without confirmation.
            /// </summary>
            [CommandOption("-f|--force")]
            [Description("Force deletion without confirmation")]
            public bool Force { get; set; }

            /// <summary>
            /// Gets or sets whether to perform a dry run.
            /// </summary>
            [CommandOption("--dry-run")]
            [Description("Show what would be deleted without actually deleting")]
            public bool DryRun { get; set; }

            /// <summary>
            /// Gets or sets whether to skip card info display.
            /// </summary>
            [Description("Don't display card information")]
            public new bool NoCardInfo { get; set; }

            /// <summary>
            /// Gets or sets debug mode.
            /// </summary>
            [CommandOption("-d|--debug")]
            [Description("Enable debug output")]
            public bool Debug { get; set; }
        }
    }
}