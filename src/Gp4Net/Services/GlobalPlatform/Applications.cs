// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Pipeline;
using JetBrains.Annotations;
using WSCT.ISO7816;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.Services.GlobalPlatform;

/// <summary>
/// Application and status operations.
/// Handles GET STATUS, application queries, and lifecycle management.
/// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.5
/// </summary>
[PublicAPI]
public static class Applications
{
    /// <summary>
    /// Retrieves complete card content including ISD, applications, and load files.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.5
    /// </summary>
    /// <param name="executeCommand">Function to execute APDU commands.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The complete card content or an error.</returns>
    public static async Task<Result<CardContent, SmartCardError>> RetrieveCompleteCardContentAsync(
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken = default
    )
    {
        // Retrieve ISD and applications
        Task<Result<ImmutableList<ApplicationInfo>, SmartCardError>> isdTask =
            GetIssuerSecurityDomainAsync(executeCommand, cancellationToken);
        Task<Result<ImmutableList<ApplicationInfo>, SmartCardError>> appsTask =
            GetApplicationsAndSecurityDomainsAsync(executeCommand, cancellationToken);

        // Retrieve load files
        Task<Result<ImmutableList<ExecutableLoadFile>, SmartCardError>> loadFilesTask =
            GetExecutableLoadFilesAsync(executeCommand, cancellationToken);
        Task<Result<ImmutableList<ExecutableLoadFile>, SmartCardError>> loadFilesWithModulesTask =
            GetExecutableLoadFilesWithModulesAsync(executeCommand, cancellationToken);

        // Wait for all tasks
        await Task.WhenAll(isdTask, appsTask, loadFilesTask, loadFilesWithModulesTask);

        // Check for failures and get values
        var isdResult = await isdTask;
        var appsResult = await appsTask;
        var loadFilesResult = await loadFilesTask;
        var loadFilesWithModulesResult = await loadFilesWithModulesTask;

        if (isdResult.IsFailure)
            return Result.Failure<CardContent, SmartCardError>(isdResult.Error);
        if (appsResult.IsFailure)
            return Result.Failure<CardContent, SmartCardError>(appsResult.Error);
        if (loadFilesResult.IsFailure)
            return Result.Failure<CardContent, SmartCardError>(loadFilesResult.Error);
        if (loadFilesWithModulesResult.IsFailure)
            return Result.Failure<CardContent, SmartCardError>(loadFilesWithModulesResult.Error);

        // Combine results into CardContent
        return CombineIntoCardContent(
            isdResult.Value,
            appsResult.Value,
            loadFilesResult.Value,
            loadFilesWithModulesResult.Value
        );
    }

    /// <summary>
    /// Retrieves the Issuer Security Domain information.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.5.1
    /// </summary>
    public static async Task<
        Result<ImmutableList<ApplicationInfo>, SmartCardError>
    > GetIssuerSecurityDomainAsync(
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken = default
    )
    {
        Result<GetStatusCommand, SmartCardError> cmdResult = Commands.CreateGetStatusCommand(
            GetStatusCommand.StatusSubset.IssuerSecurityDomain,
            new byte[] { 0x4F, 0x00 }
        ); // Tag 4F, length 0

        return await cmdResult
            .Bind(command => command.ToCommandApdu())
            .Bind(async commandApdu => await executeCommand(commandApdu, cancellationToken))
            .Bind(response => Responses.ParseGetStatusResponse(response));
    }

    /// <summary>
    /// Retrieves applications and supplementary security domains.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.5.2
    /// </summary>
    public static async Task<
        Result<ImmutableList<ApplicationInfo>, SmartCardError>
    > GetApplicationsAndSecurityDomainsAsync(
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken = default
    )
    {
        Result<GetStatusCommand, SmartCardError> cmdResult = Commands.CreateGetStatusCommand(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            new byte[] { 0x4F, 0x00 }
        );

        return await cmdResult
            .Bind(command => command.ToCommandApdu())
            .Bind(async commandApdu => await executeCommand(commandApdu, cancellationToken))
            .Bind(response => Responses.ParseGetStatusResponse(response));
    }

    /// <summary>
    /// Retrieves executable load files.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.5.3
    /// </summary>
    public static async Task<
        Result<ImmutableList<ExecutableLoadFile>, SmartCardError>
    > GetExecutableLoadFilesAsync(
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken = default
    )
    {
        Result<GetStatusCommand, SmartCardError> cmdResult = Commands.CreateGetStatusCommand(
            GetStatusCommand.StatusSubset.ExecutableLoadFiles,
            new byte[] { 0x4F, 0x00 }
        );

        Result<ImmutableList<ApplicationInfo>, SmartCardError> parseResult = await cmdResult
            .Bind(command => command.ToCommandApdu())
            .Bind(async commandApdu => await executeCommand(commandApdu, cancellationToken))
            .Bind(response => Responses.ParseGetStatusResponse(response));

        return parseResult.Map(apps =>
            apps.Select(app => new ExecutableLoadFile(
                Aid: app.Aid,
                LifecycleState: app.LifecycleState,
                Version: Maybe<string>.None,
                ExecutableModules: ImmutableList<ExecutableModule>.Empty,
                AssociatedSecurityDomainAid: app.AssociatedSecurityDomain
            )).ToImmutableList()
        );
    }

    /// <summary>
    /// Retrieves executable load files and their executable modules.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.5.4
    /// </summary>
    public static async Task<
        Result<ImmutableList<ExecutableLoadFile>, SmartCardError>
    > GetExecutableLoadFilesWithModulesAsync(
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken = default
    )
    {
        Result<GetStatusCommand, SmartCardError> cmdResult = Commands.CreateGetStatusCommand(
            GetStatusCommand.StatusSubset.ExecutableLoadFilesAndModules,
            new byte[] { 0x4F, 0x00 }
        );

        // Parse response and convert to ExecutableLoadFile objects with modules
        Result<ImmutableList<ApplicationInfo>, SmartCardError> parseResult = await cmdResult
            .Bind(command => command.ToCommandApdu())
            .Bind(async commandApdu => await executeCommand(commandApdu, cancellationToken))
            .Bind(response => Responses.ParseGetStatusResponse(response));

        return parseResult.Map(apps =>
            apps.Select(app => new ExecutableLoadFile(
                Aid: app.Aid,
                LifecycleState: app.LifecycleState,
                Version: Maybe<string>.None,
                ExecutableModules: ImmutableList<ExecutableModule>.Empty,
                AssociatedSecurityDomainAid: app.AssociatedSecurityDomain
            )).ToImmutableList()
        );
    }

    #region Private Helper Methods

    /// <summary>
    /// Combines the retrieved information into a CardContent structure.
    /// </summary>
    private static Result<CardContent, SmartCardError> CombineIntoCardContent(
        ImmutableList<ApplicationInfo> isd,
        ImmutableList<ApplicationInfo> applications,
        ImmutableList<ExecutableLoadFile> loadFiles,
        ImmutableList<ExecutableLoadFile> loadFilesWithModules
    )
    {
        // Find the ISD from the list
        Maybe<ApplicationInfo> issuerSecurityDomain = isd.Count > 0
            ? Maybe<ApplicationInfo>.From(isd.First())
            : Maybe<ApplicationInfo>.None;

        // Combine all load files (prefer ones with modules if available)
        ImmutableDictionary<string, ExecutableLoadFile> loadFileDict = loadFilesWithModules
            .Concat(loadFiles)
            .GroupBy(lf => Convert.ToHexString(lf.Aid))
            .Select(g => g.First())
            .ToImmutableDictionary(lf => Convert.ToHexString(lf.Aid), lf => lf);

        // Separate security domains from regular applications
        var securityDomains = applications
            .Where(app => app.Privileges.Contains(Privilege.SecurityDomain))
            .ToImmutableList();

        var regularApplications = applications
            .Where(app => !app.Privileges.Contains(Privilege.SecurityDomain))
            .ToImmutableList();

        return Result.Success<CardContent, SmartCardError>(
            new CardContent(
                IssuerSecurityDomain: issuerSecurityDomain,
                Applications: regularApplications,
                SecurityDomains: securityDomains,
                ExecutableLoadFiles: loadFileDict.Values.ToImmutableList()
            )
        );
    }

    #endregion
}
