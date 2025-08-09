using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Gp4Net.Domain;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Command to manage application lifecycle states.
/// </summary>
[PublicAPI]
public class LifecycleCommand : BaseCommand<LifecycleCommand.Settings>
{
    /// <summary>
    /// Initializes a new instance of the LifecycleCommand class.
    /// </summary>
    public LifecycleCommand(
        ICardService cardService,
        IDomainServiceFactory domainServiceFactory,
        IKeysetResolver keysetResolver
    )
        : base(cardService, domainServiceFactory, keysetResolver) { }

    /// <summary>
    /// Executes the lifecycle command to change an application's lifecycle state.
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

        try
        {
            var aid = Convert.FromHexString(settings.Aid);

            AnsiConsole.MarkupLine($"[cyan]Setting lifecycle state for: {settings.Aid}[/]");
            AnsiConsole.MarkupLine($"[cyan]New state: {settings.State}[/]");

            if (!settings.NoCardInfo)
            {
                DisplayCardInfo();
            }

            if (!settings.Force)
            {
                if (
                    !AnsiConsole.Confirm(
                        $"Set lifecycle state of {settings.Aid} to {settings.State}?"
                    )
                )
                {
                    AnsiConsole.MarkupLine("[yellow]Operation cancelled[/]");
                    return Task.FromResult(0);
                }
            }

            // TODO: Implement SetLifecycleState in functional IGlobalPlatformService
            AnsiConsole.MarkupLine("[yellow]Lifecycle state changes not yet implemented in functional architecture[/]");
            return Task.FromResult(1);
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

        /// <summary>
        /// Validates the command settings.
        /// </summary>
        /// <returns>Success if valid, or an error message if validation fails.</returns>
        public override ValidationResult Validate()
        {
            if (string.IsNullOrWhiteSpace(Aid))
            {
                return ValidationResult.Error("AID is required");
            }

            try
            {
                _ = Convert.FromHexString(Aid);
            }
            catch
            {
                return ValidationResult.Error("AID must be a valid hex string");
            }

            if (!Enum.IsDefined(typeof(Gp4Net.Domain.LifecycleState), State))
            {
                return ValidationResult.Error("Invalid lifecycle state");
            }

            return ValidationResult.Success();
        }
    }
}