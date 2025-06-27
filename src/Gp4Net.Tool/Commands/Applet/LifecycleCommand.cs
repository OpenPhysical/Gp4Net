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
    /// Command to manage application lifecycle states.
    /// </summary>
    [PublicAPI]
    public class LifecycleCommand : BaseCommand<LifecycleCommand.Settings>
    {
        /// <summary>
        /// Initializes a new instance of the LifecycleCommand class.
        /// </summary>
        public LifecycleCommand(ICardService cardService, IGlobalPlatformService globalPlatformService)
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
                
                AnsiConsole.MarkupLine($"[cyan]Setting lifecycle state for: {settings.Aid}[/]");
                AnsiConsole.MarkupLine($"[cyan]New state: {settings.State}[/]");

                if (!settings.NoCardInfo)
                {
                    DisplayCardInfo();
                }

                if (!settings.Force)
                {
                    if (!AnsiConsole.Confirm($"Set lifecycle state of {settings.Aid} to {settings.State}?"))
                    {
                        AnsiConsole.MarkupLine("[yellow]Operation cancelled[/]");
                        return Task.FromResult(0);
                    }
                }

                var success = GlobalPlatformService.SetLifecycleState(aid, settings.State);

                if (success)
                {
                    AnsiConsole.MarkupLine("[green]✓ Lifecycle state updated successfully[/]");
                }
                else
                {
                    AnsiConsole.MarkupLine("[red]✗ Failed to update lifecycle state[/]");
                    return Task.FromResult(1);
                }

                return Task.FromResult(0);
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error setting lifecycle state: {ex.Message}[/]");
                if (settings.Verbose)
                {
                    AnsiConsole.WriteException(ex);
                }
                return Task.FromResult(1);
            }
        }

        /// <summary>
        /// Settings for the lifecycle command.
        /// </summary>
        public class Settings : BaseCommandSettings
        {
            /// <summary>
            /// Gets or sets the AID of the application.
            /// </summary>
            [CommandArgument(0, "<AID>")]
            [Description("The AID of the application (hex string)")]
            public string Aid { get; set; } = string.Empty;

            /// <summary>
            /// Gets or sets the new lifecycle state.
            /// </summary>
            [CommandArgument(1, "<STATE>")]
            [Description("The new lifecycle state (Selectable, Personalized, Blocked, Locked)")]
            public LifecycleState State { get; set; }

            /// <summary>
            /// Gets or sets a value indicating whether to force the operation without confirmation.
            /// </summary>
            [CommandOption("-f|--force")]
            [Description("Force operation without confirmation")]
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

                if (!Enum.IsDefined(typeof(LifecycleState), State))
                {
                    return ValidationResult.Error("Invalid lifecycle state");
                }

                return ValidationResult.Success();
            }
        }
    }
}