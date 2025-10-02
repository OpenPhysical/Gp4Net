using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// CLI command to install a CAP file on the card.
/// </summary>
[PublicAPI]
[CliCommand("install", "Install a CAP file on the card", "applet")]
public class InstallCliCommand : IPipelineCommand<InstallCliCommand.Settings>
{
    /// <summary>
    /// Executes the install command to load and install a CAP file on the card.
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
                    ctx.Display.Info("Starting CAP file installation...");
                    return Result.Success<bool, SmartCardError>(true);
                })
                .Bind(_ => PerformInstall(ctx, settings))
                .Match(
                    success => 0,
                    error =>
                    {
                        ctx.Display.Error($"Installation failed: {error.Message}");
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

    private static async Task<Result<bool, SmartCardError>> PerformInstall(
        ICliExecutionContext context,
        Settings settings
    )
    {
        byte[] capFileData = await File.ReadAllBytesAsync(settings.CapFile);

        var connectionResult = await context.RequireCardConnection(settings.GetReaderName());
        return await connectionResult.Match(
            async connectedCtx =>
            {
                var secureChannelResult = await connectedCtx.RequireSecureChannel();
                return await secureChannelResult.Match(
                    async secureCtx =>
                    {
                        context.Display.Info($"Installing CAP file: {settings.CapFile}");
                        context.Display.Info("Step 1: INSTALL [for load]");
                        context.Display.Info("Step 2: LOAD");
                        context.Display.Info(
                            $"Step 3: INSTALL [for install] {(settings.InstallApplets ? "(enabled)" : "(skipped)")}"
                        );

                        var installResult =
                            await Gp4Net.Services.GlobalPlatform.CardManagement.InstallCapFileAsync(
                                capFileData,
                                securityDomainAid: CSharpFunctionalExtensions.Maybe<byte[]>.None,
                                settings.InstallApplets,
                                settings.MakeSelectable,
                                (command, ct) =>
                                    secureCtx.CardService.ExecuteCommandAsync(command, ct),
                                CancellationToken.None
                            );

                        return installResult.Match(
                            result =>
                            {
                                context.Display.Success("Installation completed successfully");
                                context.Display.Info(
                                    $"Package AID: {Convert.ToHexString(result.PackageAid)}"
                                );
                                if (result.AppletsInstalled && result.InstalledAppletAids.Count > 0)
                                {
                                    DisplayInstalledApplets(context, result.InstalledAppletAids);
                                }
                                return Result.Success<bool, SmartCardError>(true);
                            },
                            error =>
                            {
                                context.Display.Error($"Installation failed: {error.Message}");
                                return Result.Failure<bool, SmartCardError>(error);
                            }
                        );
                    },
                    async secureChannelError =>
                    {
                        context.Display.Error(
                            $"Secure channel error: {secureChannelError.Message}"
                        );
                        return await Task.FromResult(
                            Result.Failure<bool, SmartCardError>(secureChannelError)
                        );
                    }
                );
            },
            async connectionError =>
            {
                context.Display.Error($"Connection error: {connectionError.Message}");
                return await Task.FromResult(Result.Failure<bool, SmartCardError>(connectionError));
            }
        );
    }

    private static bool DisplayInstalledApplets(
        ICliExecutionContext context,
        System.Collections.Generic.IReadOnlyList<byte[]> appletAids
    )
    {
        context.Display.Info("Installed applets:");
        appletAids
            .Select(aid => $"  - {Convert.ToHexString(aid)}")
            .Select(line =>
            {
                context.Display.Info(line);
                return true;
            })
            .ToList();

        return true;
    }

    /// <summary>
    /// Settings for the install command.
    /// </summary>
    public class Settings : SecureCommandSettings
    {
        /// <summary>
        /// Gets or sets the CAP file path.
        /// </summary>
        [CommandOption("--cap")]
        [Description("Path to the CAP file to install")]
        public string CapFile { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether to install applets.
        /// </summary>
        [CommandOption("--no-install-applets")]
        [Description("Don't install applets after loading the package")]
        public bool NoInstallApplets { get; set; }

        /// <summary>
        /// Gets a value indicating whether to install applets.
        /// </summary>
        public bool InstallApplets
        {
            get { return !NoInstallApplets; }
        }

        /// <summary>
        /// Gets or sets a value indicating whether to make applets selectable.
        /// </summary>
        [CommandOption("--no-make-selectable")]
        [Description("Don't make applets selectable after installation")]
        public bool NoMakeSelectable { get; set; }

        /// <summary>
        /// Gets a value indicating whether to make applets selectable.
        /// </summary>
        public bool MakeSelectable
        {
            get { return !NoMakeSelectable; }
        }

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

            return ValidationResult.Success();
        }
    }
}
