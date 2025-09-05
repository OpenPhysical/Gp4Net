using System.ComponentModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Services;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Command to load a CAP file package onto a GlobalPlatform card without installing applets.
/// </summary>
[PublicAPI]
[Description("Load a CAP file package onto the card (without installing applets)")]
public class LoadCommand : IPipelineCommand<LoadCommand.Settings>
{
    /// <summary>
    /// Executes the load command to upload a CAP file package to the card.
    /// </summary>
    /// <param name="context">The CLI execution context.</param>
    /// <param name="settings">The command settings.</param>
    /// <returns>0 if successful, 1 if failed.</returns>
    public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
    {
        return await context.ExecuteAsync(async ctx =>
        {
            return await ValidateCapFile(settings.CapFile)
                .Bind(_ =>
                {
                    ctx.Display.Info("Starting CAP file load operation...");
                    return Result.Success<bool, SmartCardError>(true);
                })
                .Bind(_ => PerformLoad(ctx, settings))
                .Match(
                    success => 0,
                    error =>
                    {
                        ctx.Display.Error($"Load failed: {error.Message}");
                        return 1;
                    }
                );
        });
    }

    private static Result<bool, SmartCardError> ValidateCapFile(string capFilePath)
    {
        return File.Exists(capFilePath)
            ? Result.Success<bool, SmartCardError>(true)
            : Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument($"CAP file not found: {capFilePath}")
            );
    }

    private static async Task<Result<bool, SmartCardError>> PerformLoad(
        ICliExecutionContext context,
        Settings settings
    )
    {
        context.Display.Info($"Reading CAP file: {settings.CapFile}");
        byte[] capData = await File.ReadAllBytesAsync(settings.CapFile);
        context.Display.Info($"CAP file size: {capData.Length} bytes");

        if (!settings.NoCardInfo)
        {
            await DisplayCardInfoAsync(context);
        }

        context.Display.Info("Loading CAP file package...");
        context.Display.Error("CAP file loading not yet implemented with static services.");
        Result<bool, SmartCardError> loadResult = Result.Failure<bool, SmartCardError>(
            SmartCardError.Unsupported("CAP file loading functionality needs to be implemented using static GlobalPlatformService methods")
        );

        return loadResult.Match(
            success =>
            {
                context.Display.Success($"CAP file {settings.CapFile} loaded successfully");
                return Result.Success<bool, SmartCardError>(true);
            },
            error =>
            {
                context.Display.Error($"Load failed: {error.Message}");
                return Result.Failure<bool, SmartCardError>(error);
            }
        );
    }

    private static Task DisplayCardInfoAsync(ICliExecutionContext context)
    {
        context.Display.Info("Card information display would go here");
        return Task.CompletedTask;
    }

    /// <summary>
    /// Settings for the load command.
    /// </summary>
    public class Settings : CommandSettings
    {
        /// <summary>
        /// Gets or sets the CAP file path.
        /// </summary>
        [CommandArgument(0, "<CAP_FILE>")]
        [Description("Path to the CAP file to load")]
        public string CapFile { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package AID override.
        /// </summary>
        [CommandOption("--package-aid")]
        [Description("Override the package AID (hex string)")]
        [TypeConverter(typeof(HexStringTypeConverter))]
        public byte[] PackageAid { get; set; }

        /// <summary>
        /// Gets or sets the security domain AID.
        /// </summary>
        [CommandOption("--security-domain")]
        [Description("Security domain AID for delegated management (hex string)")]
        [TypeConverter(typeof(HexStringTypeConverter))]
        public byte[] SecurityDomain { get; set; }

        /// <summary>
        /// Gets or sets the maximum block size.
        /// </summary>
        [CommandOption("--max-block-size")]
        [Description("Maximum APDU data block size (default: 255)")]
        [DefaultValue(255)]
        public int MaxBlockSize { get; set; } = 255;

        /// <summary>
        /// Gets or sets whether to show package details.
        /// </summary>
        [CommandOption("-d|--details")]
        [Description("Show package details after loading")]
        public bool ShowDetails { get; set; }

        /// <summary>
        /// Gets or sets whether to skip card info display.
        /// </summary>
        [CommandOption("--no-card-info")]
        [Description("Skip card information display")]
        public bool NoCardInfo { get; set; }

        /// <summary>
        /// Validates the command settings.
        /// </summary>
        /// <returns>Success if valid, or an error message if validation fails.</returns>
        public override ValidationResult Validate()
        {
            if (string.IsNullOrWhiteSpace(CapFile))
            {
                return ValidationResult.Error("CAP file path is required");
            }

            if (MaxBlockSize is < 1 or > 255)
            {
                return ValidationResult.Error("Max block size must be between 1 and 255");
            }

            return ValidationResult.Success();
        }
    }
}
