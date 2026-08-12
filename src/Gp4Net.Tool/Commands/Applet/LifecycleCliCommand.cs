using System;
using System.ComponentModel;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Command to manage application lifecycle states.
/// </summary>
[PublicAPI]
public class LifecycleCommand : IPipelineCommand<LifecycleCommand.Settings>
{
    /// <summary>GP Card Specification v2.3.1, §11.10.2.2.</summary>
    public enum ApplicationLockState : byte
    {
        Previous = 0x00,
        Locked = 0x80,
    }

    /// <summary>
    /// Executes the lifecycle command to change an application's lifecycle state.
    /// </summary>
    /// <param name="context">The CLI execution context.</param>
    /// <param name="settings">The command settings.</param>
    /// <returns>0 if successful, 1 if failed.</returns>
    public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
    {
        return await context.ExecuteAsync(async ctx =>
        {
            var result = await ValidateSettings(settings)
                .Bind(_ =>
                {
                    ctx.Display.Info($"Setting lifecycle state for: {settings.Aid}");
                    ctx.Display.Info($"New state: {settings.State}");
                    return Result.Success<bool, SmartCardError>(true);
                })
                .Bind(_ => ConfirmOperation(ctx, settings))
                .Bind(_ => PerformLifecycleChange(ctx, settings));

            return result.Match(
                success => 0,
                error =>
                {
                    ctx.Display.Error($"Lifecycle change failed: {error.Message}");
                    return 1;
                }
            );
        });
    }

    private static Result<bool, SmartCardError> ValidateSettings(Settings settings)
    {
        return Result
            .Try(
                () => Convert.FromHexString(settings.Aid),
                ex => $"Invalid AID format: {ex.Message}"
            )
            .MapError(SmartCardError.InvalidArgument)
            .Map(_ => true);
    }

    private static Result<bool, SmartCardError> ConfirmOperation(
        ICliExecutionContext context,
        Settings settings
    )
    {
        if (settings.Force)
        {
            return Result.Success<bool, SmartCardError>(true);
        }

        bool confirmed = AnsiConsole.Confirm(
            $"Set lifecycle state of {settings.Aid} to {settings.State}?"
        );
        return confirmed
            ? Result.Success<bool, SmartCardError>(true)
            : Result.Failure<bool, SmartCardError>(
                SmartCardError.OperationCancelled("User cancelled operation")
            );
    }

    private static Task<Result<bool, SmartCardError>> PerformLifecycleChange(
        ICliExecutionContext context,
        Settings settings
    )
    {
        byte[] aid = Convert.FromHexString(settings.Aid);
        context.Display.Info("Executing lifecycle state change...");

        context.Display.Error(
            "Lifecycle management functionality not yet implemented with static services."
        );
        return Task.FromResult(
            Result.Failure<bool, SmartCardError>(
                SmartCardError.Unsupported(
                    "Lifecycle management functionality needs to be implemented using static GlobalPlatformService methods"
                )
            )
        );
    }

    /// <summary>
    /// Settings for the lifecycle command.
    /// </summary>
    public class Settings : CommandSettings
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
        [Description("The application lock state (Previous or Locked)")]
        public ApplicationLockState State { get; set; }

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

            if (!Enum.IsDefined(typeof(ApplicationLockState), State))
            {
                return ValidationResult.Error("Invalid lifecycle state");
            }

            return ValidationResult.Success();
        }
    }
}
