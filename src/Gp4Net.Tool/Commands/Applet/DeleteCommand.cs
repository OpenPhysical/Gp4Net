using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Gp4Net.Tool.Services;
using Gp4Net.Utils;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet
{
    /// <summary>
    /// Command to delete an applet from the card.
    /// </summary>
    [PublicAPI]
    public class DeleteCommand : BaseCommand<DeleteCommand.Settings>
    {
        /// <summary>
        /// Initializes a new instance of the DeleteCommand class.
        /// </summary>
        public DeleteCommand(ICardService cardService, IGlobalPlatformService globalPlatformService)
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

            try
            {
                var aid = ConvertCompat.FromHexString(settings.Aid);
                
                AnsiConsole.MarkupLine($"[cyan]Deleting applet: {settings.Aid}[/]");

                if (!settings.NoCardInfo)
                {
                    DisplayCardInfo();
                }

                if (!settings.Force)
                {
                    if (!AnsiConsole.Confirm($"Are you sure you want to delete applet {settings.Aid}?"))
                    {
                        AnsiConsole.MarkupLine("[yellow]Operation cancelled[/]");
                        return Task.FromResult(0);
                    }
                }

                var result = GlobalPlatformService.DeleteApplication(aid, settings.DeleteRelated);

                if (result.IsSuccessful)
                {
                    AnsiConsole.MarkupLine("[green]✓ Applet deleted successfully[/]");
                    
                    if (result.DeletedAids.Count > 0)
                    {
                        AnsiConsole.MarkupLine($"[green]Deleted {result.DeletedAids.Count} object(s):[/]");
                        foreach (var deletedAid in result.DeletedAids)
                        {
                            AnsiConsole.MarkupLine($"  [dim]• {Convert.ToHexString(deletedAid)}[/]");
                        }
                    }
                }
                else
                {
                    AnsiConsole.MarkupLine($"[red]✗ Deletion failed: {result.ErrorMessage}[/]");
                    return Task.FromResult(1);
                }

                return Task.FromResult(0);
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error deleting applet: {ex.Message}[/]");
                if (settings.Verbose)
                {
                    AnsiConsole.WriteException(ex);
                }
                return Task.FromResult(1);
            }
        }

        /// <summary>
        /// Settings for the delete command.
        /// </summary>
        public class Settings : BaseCommandSettings
        {
            /// <summary>
            /// Gets or sets the AID to delete.
            /// </summary>
            [CommandArgument(0, "<AID>")]
            [Description("The AID of the applet to delete (hex string)")]
            public string Aid { get; set; } = string.Empty;

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

            /// <inheritdoc />
            public override ValidationResult Validate()
            {
                if (string.IsNullOrWhiteSpace(Aid))
                {
                    return ValidationResult.Error("AID is required");
                }

                try
                {
                    ConvertCompat.FromHexString(Aid);
                }
                catch
                {
                    return ValidationResult.Error("AID must be a valid hex string");
                }

                return ValidationResult.Success();
            }
        }
    }
}