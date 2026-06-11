using System;
using System.ComponentModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;
using Gp4Net.Tool.Extensions;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// CLI command to uninstall a CAP file package and instances from the card.
/// Simplified workflow that removes both applet instances and load file package.
/// </summary>
[PublicAPI]
public class UninstallCommand : IPipelineCommand<UninstallCommand.Settings>
{
    public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
    {
        return await context.ExecuteAsync(async ctx =>
        {
            var capFileResult = await ValidateCapFile(settings.CapFile);

            return await capFileResult.Match(
                async capStructure =>
                {
                    var uninstallResult = await PerformUninstall(
                        ctx,
                        settings,
                        capStructure.PackageAid,
                        capStructure.Applets
                    );

                    return uninstallResult.Match(
                        result =>
                        {
                            if (result.AlreadyRemoved)
                            {
                                ctx.Display.Info("Package already removed (idempotent success)");
                            }
                            else
                            {
                                ctx.Display.Success("Uninstallation completed successfully");
                            }
                            return 0;
                        },
                        error =>
                        {
                            ctx.Display.Error($"Uninstallation failed: {error.Message}");
                            return 1;
                        }
                    );
                },
                error =>
                {
                    ctx.Display.Error($"Validation failed: {error.Message}");
                    return Task.FromResult(1);
                }
            );
        });
    }

    private static async Task<Result<CapFileStructure, SmartCardError>> ValidateCapFile(
        string capFilePath
    )
    {
        if (!File.Exists(capFilePath))
        {
            return Result.Failure<CapFileStructure, SmartCardError>(
                SmartCardError.InvalidArgument(
                    $"CAP file not found: {capFilePath}. Please verify the file path and try again."
                )
            );
        }

        var capFileData = await File.ReadAllBytesAsync(capFilePath);
        return CapFileStructure.Parse(capFileData);
    }

    private static async Task<Result<UninstallResult, SmartCardError>> PerformUninstall(
        ICliExecutionContext context,
        Settings settings,
        byte[] packageAid,
        System.Collections.Generic.IReadOnlyList<AppletInfo> applets
    )
    {
        var connectionResult = await context.RequireCardConnection(settings.GetReaderName());

        return await connectionResult.Match(
            async connectedCtx =>
            {
                var secureChannelResult = await connectedCtx.RequireSecureChannel(
                    settings.ToSecureChannelRequest()
                );

                return await secureChannelResult.Match(
                    async secureCtx =>
                    {
                        context.Display.Info(
                            $"Uninstalling package: {Convert.ToHexString(packageAid)}"
                        );
                        var alreadyRemoved = true;

                        foreach (var applet in applets)
                        {
                            context.Display.Info(
                                $"Removing applet instance: {Convert.ToHexString(applet.Aid)}"
                            );

                            var deleteCmd =
                                Gp4Net.Services.GlobalPlatform.Commands.CreateDeleteCommand(
                                    applet.Aid,
                                    deleteRelated: false
                                );

                            var deleteResult = await ExecuteDeleteAsync(
                                secureCtx,
                                deleteCmd,
                                $"Applet {Convert.ToHexString(applet.Aid)}"
                            );

                            if (deleteResult.IsFailure)
                            {
                                return Result.Failure<UninstallResult, SmartCardError>(
                                    deleteResult.Error
                                );
                            }

                            if (deleteResult.Value == DeleteOutcome.Deleted)
                            {
                                alreadyRemoved = false;
                            }
                        }

                        if (!settings.InstancesOnly)
                        {
                            context.Display.Info(
                                $"Removing load file: {Convert.ToHexString(packageAid)}"
                            );

                            var deleteCmd =
                                Gp4Net.Services.GlobalPlatform.Commands.CreateDeleteCommand(
                                    packageAid,
                                    deleteRelated: true
                                );

                            var deleteResult = await ExecuteDeleteAsync(
                                secureCtx,
                                deleteCmd,
                                $"Package {Convert.ToHexString(packageAid)}"
                            );

                            if (deleteResult.IsFailure)
                            {
                                return Result.Failure<UninstallResult, SmartCardError>(
                                    deleteResult.Error
                                );
                            }

                            if (deleteResult.Value == DeleteOutcome.Deleted)
                            {
                                alreadyRemoved = false;
                            }
                        }
                        else
                        {
                            context.Display.Info("Package (load file) retained (--instances-only)");
                        }

                        return Result.Success<UninstallResult, SmartCardError>(
                            new UninstallResult(alreadyRemoved)
                        );
                    },
                    async error =>
                    {
                        context.Display.Error($"Secure channel error: {error.Message}");
                        return await Task.FromResult(
                            Result.Failure<UninstallResult, SmartCardError>(error)
                        );
                    }
                );
            },
            async error =>
            {
                context.Display.Error($"Connection error: {error.Message}");
                return await Task.FromResult(
                    Result.Failure<UninstallResult, SmartCardError>(error)
                );
            }
        );
    }

    private static async Task<Result<DeleteOutcome, SmartCardError>> ExecuteDeleteAsync(
        ICliExecutionContext context,
        Result<Gp4Net.Domain.Commands.DeleteCommand, SmartCardError> deleteCommand,
        string targetDescription
    )
    {
        if (deleteCommand.IsFailure)
        {
            return Result.Failure<DeleteOutcome, SmartCardError>(deleteCommand.Error);
        }

        var result = await context.CardService.ExecuteCommandAsync(
            deleteCommand.Value.ToApdu(),
            true,
            CancellationToken.None
        );

        if (result.IsFailure)
        {
            return Result.Failure<DeleteOutcome, SmartCardError>(result.Error);
        }

        var response = result.Value;
        if (response.IsSuccess)
        {
            return Result.Success<DeleteOutcome, SmartCardError>(DeleteOutcome.Deleted);
        }

        if (IsAlreadyRemovedStatus(response.StatusWord))
        {
            context.Display.Info($"{targetDescription} already absent ({response.StatusWord})");
            return Result.Success<DeleteOutcome, SmartCardError>(DeleteOutcome.AlreadyRemoved);
        }

        return Result.Failure<DeleteOutcome, SmartCardError>(
            SmartCardError.FromStatusWord(response.StatusWord)
        );
    }

    private static bool IsAlreadyRemovedStatus(StatusWord statusWord) =>
        statusWord == Gp4Net.Constants.Constants.StatusWords.Legacy.ReferencedDataNotFound
        || statusWord == Gp4Net.Constants.Constants.StatusWords.Legacy.FileNotFound;

    private enum DeleteOutcome
    {
        Deleted,
        AlreadyRemoved,
    }

    public sealed record UninstallResult(bool AlreadyRemoved);

    [PublicAPI]
    public class Settings : SecureCommandSettings
    {
        [Description("Path to the CAP file to uninstall")]
        [CommandArgument(0, "<cap-file>")]
        public string CapFile { get; init; } = string.Empty;

        [Description("Remove only applet instances, leave package (load file) on card")]
        [CommandOption("--instances-only")]
        public bool InstancesOnly { get; init; }
    }
}
