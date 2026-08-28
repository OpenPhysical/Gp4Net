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
    /// Identifies a successfully loaded package and the verified LFDBH.
    /// See GlobalPlatform Card Specification v2.3.1, sections 11.6 and C.2.
    /// </summary>
    public sealed record DapLoadResult(byte[] PackageAid, byte[] LoadFileDataBlockHash);

    /// <summary>
    /// Creates a supplementary Security Domain with INSTALL [for install and make selectable].
    /// The privilege field must include Security Domain privilege. See GlobalPlatform
    /// Card Specification v2.3.1, sections 6.6.3 and 11.5.2.3.2 and Table 11-43.
    /// </summary>
    public static async Task<Result<bool, SmartCardError>> CreateSupplementarySecurityDomainAsync(
        byte[] packageAid,
        byte[] moduleAid,
        byte[] securityDomainAid,
        byte[] privileges,
        Maybe<byte[]> installParameters,
        Func<CommandAPDU, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        if (privileges is null || privileges.Length == 0 || (privileges[0] & 0x80) == 0)
            return SmartCardError.InvalidArgument(
                "Supplementary Security Domain privileges must include Security Domain.");

        return await InstallCommand.InstallForInstallCommand
            .CreateAndMakeSelectable(packageAid, moduleAid, securityDomainAid, privileges, installParameters)
            .Bind(command => command.ToCommandApdu())
            .Bind(apdu => executeCommand(apdu, cancellationToken))
            .Bind(response => response.IsSuccess
                ? Result.Success<bool, SmartCardError>(true)
                : Result.Failure<bool, SmartCardError>(SmartCardError.CardError(
                    $"Security Domain creation failed with SW: {response.StatusWord:X4}")));
    }

    /// <summary>
    /// Changes an application's associated Security Domain with INSTALL [for extradition].
    /// See GlobalPlatform Card Specification v2.3.1, section 11.5.2.3.4 and Table 11-45.
    /// </summary>
    public static async Task<Result<bool, SmartCardError>> ExtraditeApplicationAsync(
        byte[] applicationAid,
        byte[] targetSecurityDomainAid,
        Maybe<byte[]> extraditionParameters,
        Maybe<byte[]> extraditionToken,
        Func<CommandAPDU, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        return await InstallCommand.InstallForManagementCommand
            .CreateForExtradition(targetSecurityDomainAid, applicationAid, extraditionParameters, extraditionToken)
            .Bind(command => command.ToCommandApdu())
            .Bind(apdu => executeCommand(apdu, cancellationToken))
            .Bind(response => response.IsSuccess
                ? Result.Success<bool, SmartCardError>(true)
                : Result.Failure<bool, SmartCardError>(SmartCardError.CardError(
                    $"INSTALL [for extradition] failed with SW: {response.StatusWord:X4}")));
    }

    /// <summary>
    /// Loads a CAP package with an AES-CMAC DAP block before the <c>C4</c> Load
    /// File Data Block. See GlobalPlatform Card Specification v2.3.1,
    /// section 11.6.2.3, Table 11-58, and sections B.2.2 and C.3.
    /// </summary>
    public static async Task<Result<DapLoadResult, SmartCardError>> LoadCapFileWithDapAsync(
        byte[] capFileData,
        byte[] dapSecurityDomainAid,
        byte[] dapKey,
        Maybe<byte[]> targetSecurityDomainAid,
        Maybe<byte[]> loadParameters,
        int maxBlockSize,
        Func<CommandAPDU, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        var cap = ValidateCapFile(capFileData);
        if (cap.IsFailure) return cap.Error;
        var artifacts = DapLoadArtifacts.Create(cap.Value, dapSecurityDomainAid, dapKey,
            targetSecurityDomainAid, loadParameters, maxBlockSize);
        if (artifacts.IsFailure) return artifacts.Error;
        var install = artifacts.Value.InstallForLoad.ToCommandApdu();
        if (install.IsFailure) return install.Error;
        var installResponse = await executeCommand(install.Value, cancellationToken);
        if (installResponse.IsFailure) return installResponse.Error;
        if (!installResponse.Value.IsSuccess)
            return SmartCardError.CardError($"INSTALL [for load] failed with SW: {installResponse.Value.StatusWord:X4}");
        foreach (LoadCommand command in artifacts.Value.LoadCommands)
        {
            var apdu = command.ToCommandApdu();
            if (apdu.IsFailure) return apdu.Error;
            var response = await executeCommand(apdu.Value, cancellationToken);
            if (response.IsFailure) return response.Error;
            if (!response.Value.IsSuccess)
                return SmartCardError.CardError($"LOAD failed with SW: {response.Value.StatusWord:X4}");
            var parsed = LoadResponse.Parse(response.Value.Data, response.Value.StatusWord);
            if (parsed.IsFailure) return parsed.Error;
        }
        return new DapLoadResult(cap.Value.PackageAid, artifacts.Value.LoadFileDataBlockHash);
    }

    /// <summary>
    /// Loads a CAP package using AES-CMAC delegated management and strictly parses
    /// the optional Load Receipt. See GlobalPlatform Card Specification v2.3.1,
    /// sections 11.1.6 and 11.6 and Appendices C.4.1 and C.5.1.
    /// </summary>
    public static async Task<Result<DelegatedLoadResult, SmartCardError>> LoadCapFileAsync(
        byte[] capFileData,
        DelegatedLoadOptions options,
        int maxBlockSize,
        Func<CommandAPDU, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        var capResult = ValidateCapFile(capFileData);
        if (capResult.IsFailure)
            return capResult.Error;
        var artifactsResult = DelegatedLoadArtifacts.Create(capResult.Value, options, maxBlockSize);
        if (artifactsResult.IsFailure)
            return artifactsResult.Error;
        DelegatedLoadArtifacts artifacts = artifactsResult.Value;

        var installApdu = artifacts.InstallForLoad.ToCommandApdu();
        if (installApdu.IsFailure)
            return installApdu.Error;
        var installResponse = await executeCommand(installApdu.Value, cancellationToken);
        if (installResponse.IsFailure)
            return installResponse.Error;
        if (!installResponse.Value.IsSuccess)
            return SmartCardError.CardError($"INSTALL [for load] failed with SW: {installResponse.Value.StatusWord:X4}");

        Maybe<LoadConfirmation> confirmation = Maybe<LoadConfirmation>.None;
        foreach (LoadCommand loadCommand in artifacts.LoadCommands)
        {
            var apdu = loadCommand.ToCommandApdu();
            if (apdu.IsFailure)
                return apdu.Error;
            var response = await executeCommand(apdu.Value, cancellationToken);
            if (response.IsFailure)
                return response.Error;
            if (!response.Value.IsSuccess)
                return SmartCardError.CardError($"LOAD failed with SW: {response.Value.StatusWord:X4}");
            var parsed = LoadResponse.Parse(response.Value.Data, response.Value.StatusWord);
            if (parsed.IsFailure)
                return parsed.Error;
            if (loadCommand.IsFinalBlock)
                confirmation = parsed.Value.Confirmation;
        }

        return new DelegatedLoadResult(
            capResult.Value.PackageAid,
            artifacts.LoadFileDataBlockHash,
            artifacts.LoadToken,
            confirmation);
    }

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
                        LoadCapFileDataSequential(capFile, executeCommand, cancellationToken)
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
            .InstallForLoadCommand.Create(packageAid, securityDomainAid: securityDomainAid)
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
        CapFileStructure capFile,
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken
    )
    {
        return await LoadCommand
            .CreateFromCapFile(capFile)
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

/// <summary>Result of an AES delegated LOAD operation.</summary>
public sealed class DelegatedLoadResult
{
    private readonly byte[] _packageAid;
    private readonly byte[] _hash;
    private readonly byte[] _token;
    public byte[] PackageAid => (byte[])_packageAid.Clone();
    public byte[] LoadFileDataBlockHash => (byte[])_hash.Clone();
    public byte[] LoadToken => (byte[])_token.Clone();
    public Maybe<LoadConfirmation> Confirmation { get; }

    public DelegatedLoadResult(byte[] packageAid, byte[] hash, byte[] token, Maybe<LoadConfirmation> confirmation)
    {
        _packageAid = (byte[])packageAid.Clone();
        _hash = (byte[])hash.Clone();
        _token = (byte[])token.Clone();
        Confirmation = confirmation;
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
