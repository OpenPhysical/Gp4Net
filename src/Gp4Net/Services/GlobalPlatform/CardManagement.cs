using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;
using Gp4Net.Domain.Commands;
using Gp4Net.Pipeline;
using JetBrains.Annotations;
using WSCT.ISO7816;

namespace Gp4Net.Services.GlobalPlatform;

/// <summary>
/// Card lifecycle and management operations.
/// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.4, 11.8
/// </summary>
[PublicAPI]
public static class CardManagement
{
    /// <summary>
    /// Installs a CAP file on the card with complete workflow.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.5
    /// </summary>
    /// <param name="capFileData">The CAP file binary data.</param>
    /// <param name="securityDomainAid">Optional security domain AID (None for default ISD).</param>
    /// <param name="installApplets">Whether to install applets after loading.</param>
    /// <param name="makeSelectable">Whether to make applets selectable after installation.</param>
    /// <param name="executeCommand">Function to execute commands on the card.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Result containing installation details or error.</returns>
    public static async Task<Result<InstallationResult, SmartCardError>> InstallCapFileAsync(
        byte[] capFileData,
        Maybe<byte[]> securityDomainAid,
        bool installApplets,
        bool makeSelectable,
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken = default
    )
    {
        return await ValidateCapFile(capFileData)
            .Bind(capFile =>
                SendInstallForLoad(
                        capFile.PackageAid,
                        securityDomainAid,
                        executeCommand,
                        cancellationToken
                    )
                    .Bind(_ =>
                        LoadCapFileDataSequential(capFileData, executeCommand, cancellationToken)
                    )
                    .Bind(_ =>
                        installApplets && capFile.Applets.Count > 0
                            ? InstallAppletsSequential(
                                capFile.PackageAid,
                                capFile.Applets.ToList(),
                                makeSelectable
                                    ? InstallType.ForInstallAndMakeSelectable
                                    : InstallType.ForInstall,
                                executeCommand,
                                cancellationToken
                            )
                            : Task.FromResult(
                                Result.Success<InstallationResult, SmartCardError>(
                                    new InstallationResult(
                                        capFile.PackageAid,
                                        ImmutableList<byte[]>.Empty,
                                        false
                                    )
                                )
                            )
                    )
            );
    }

    private static Result<CapFileStructure, SmartCardError> ValidateCapFile(byte[] capFileData)
    {
        var validationResult = CapFileLoadingWorkflow.ValidateCapFile(capFileData);
        return validationResult.CapFile.ToResult(
            SmartCardError.InvalidData(
                validationResult.ErrorMessage.GetValueOrDefault("Invalid CAP file")
            )
        );
    }

    private static async Task<Result<bool, SmartCardError>> SendInstallForLoad(
        byte[] packageAid,
        Maybe<byte[]> securityDomainAid,
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken
    )
    {
        return await InstallCommand
            .InstallForLoadCommand.Create(
                packageAid,
                securityDomainAid: securityDomainAid
            )
            .Bind(cmd => cmd.ToCommandApdu())
            .Bind(commandApdu => executeCommand(commandApdu, cancellationToken))
            .Bind(response =>
                response.IsSuccess
                    ? Result.Success<bool, SmartCardError>(true)
                    : Result.Failure<bool, SmartCardError>(
                        SmartCardError.CardError(
                            $"INSTALL [for load] failed with SW: {response.StatusWord:X4}"
                        )
                    )
            );
    }

    private static async Task<Result<bool, SmartCardError>> LoadCapFileDataSequential(
        byte[] capFileData,
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken
    )
    {
        return await LoadCommand
            .CreateFromCapFile(capFileData)
            .Bind(loadCommands =>
                loadCommands
                    .Select(loadCmd =>
                        (Func<Task<Result<bool, SmartCardError>>>)(
                            async () =>
                                await loadCmd
                                    .ToCommandApdu()
                                    .Bind(commandApdu =>
                                        executeCommand(commandApdu, cancellationToken)
                                    )
                                    .Bind(response =>
                                        response.IsSuccess
                                            ? Result.Success<bool, SmartCardError>(true)
                                            : Result.Failure<bool, SmartCardError>(
                                                SmartCardError.CardError(
                                                    $"LOAD failed with SW: {response.StatusWord:X4}"
                                                )
                                            )
                                    )
                        )
                    )
                    .Aggregate(
                        Task.FromResult(Result.Success<bool, SmartCardError>(true)),
                        async (accTask, loadFunc) => await accTask.Bind(async _ => await loadFunc())
                    )
            );
    }

    private static async Task<Result<InstallationResult, SmartCardError>> InstallAppletsSequential(
        byte[] packageAid,
        IList<AppletInfo> applets,
        InstallType installType,
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken
    )
    {
        var aggregateResult = await applets
            .Select(applet =>
                (Func<Task<Result<byte[], SmartCardError>>>)(
                    async () =>
                        await SendInstallForInstall(
                                packageAid,
                                applet.Aid,
                                applet.Aid,
                                installType,
                                executeCommand,
                                cancellationToken
                            )
                            .Map(_ => applet.Aid)
                )
            )
            .Aggregate(
                Task.FromResult(
                    Result.Success<ImmutableList<byte[]>, SmartCardError>(
                        ImmutableList<byte[]>.Empty
                    )
                ),
                async (accTask, installFunc) =>
                    await accTask.Bind(async existingList =>
                        await installFunc().Map(aid => existingList.Add(aid))
                    )
            );

        return aggregateResult.Map(aids => new InstallationResult(packageAid, aids, true));
    }

    private static async Task<Result<bool, SmartCardError>> SendInstallForInstall(
        byte[] packageAid,
        byte[] moduleAid,
        byte[] applicationAid,
        InstallType installType,
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken
    )
    {
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> cmdResult =
            installType == InstallType.ForInstallAndMakeSelectable
                ? InstallCommand.InstallForInstallCommand.CreateAndMakeSelectable(
                    packageAid,
                    moduleAid,
                    applicationAid,
                    [0x00]
                )
                : InstallCommand.InstallForInstallCommand.Create(
                    packageAid,
                    moduleAid,
                    applicationAid,
                    [0x00]
                );

        return await cmdResult
            .Bind(cmd => cmd.ToCommandApdu())
            .Bind(commandApdu => executeCommand(commandApdu, cancellationToken))
            .Bind(response =>
                response.IsSuccess
                    ? Result.Success<bool, SmartCardError>(true)
                    : Result.Failure<bool, SmartCardError>(
                        SmartCardError.CardError(
                            $"INSTALL [for install] failed with SW: {response.StatusWord:X4}"
                        )
                    )
            );
    }

    /// <summary>
    /// Deletes an application from the card.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.8
    /// </summary>
    public static async Task<Result<bool, SmartCardError>> DeleteApplicationAsync(
        byte[] aid,
        bool deleteRelated,
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken = default
    )
    {
        return await Commands
            .CreateDeleteCommand(aid, deleteRelated)
            .Bind(cmd => cmd.ToCommandApdu())
            .Bind(commandApdu => executeCommand(commandApdu, cancellationToken))
            .Bind(response => Responses.ParseDeleteResponse(response));
    }

    /// <summary>
    /// Sets the lifecycle state of a card or application.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.4
    /// </summary>
    public static async Task<Result<bool, SmartCardError>> SetLifecycleStateAsync(
        byte[] aid,
        byte p1,
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken = default
    )
    {
        return await Commands
            .CreateSetStatusCommand(aid, p1)
            .Bind(cmd => cmd.ToCommandApdu())
            .Bind(commandApdu => executeCommand(commandApdu, cancellationToken))
            .Bind(response =>
                response.IsSuccess
                    ? Result.Success<bool, SmartCardError>(true)
                    : Result.Failure<bool, SmartCardError>(
                        SmartCardError.CardError(
                            $"SET STATUS failed with SW: {response.StatusWord:X4}"
                        )
                    )
            );
    }
}

/// <summary>
/// Result of a CAP file installation operation.
/// </summary>
[PublicAPI]
public class InstallationResult
{
    /// <summary>
    /// Gets the package AID that was installed.
    /// </summary>
    public byte[] PackageAid { get; }

    /// <summary>
    /// Gets the list of applet AIDs that were installed.
    /// </summary>
    public IReadOnlyList<byte[]> InstalledAppletAids { get; }

    /// <summary>
    /// Gets a value indicating whether applets were installed.
    /// </summary>
    public bool AppletsInstalled { get; }

    /// <summary>
    /// Initializes a new instance of the InstallationResult class.
    /// </summary>
    public InstallationResult(
        byte[] packageAid,
        IReadOnlyList<byte[]> installedAppletAids,
        bool appletsInstalled
    )
    {
        PackageAid = (byte[])packageAid.Clone();
        InstalledAppletAids = installedAppletAids
            .Select(aid => (byte[])aid.Clone())
            .ToList()
            .AsReadOnly();
        AppletsInstalled = appletsInstalled;
    }
}
