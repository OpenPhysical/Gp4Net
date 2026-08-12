// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
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
/// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.4
/// </summary>
[PublicAPI]
public static class Applications
{
    private const ushort GET_STATUS_MORE_DATA = 0x6310;

    /// <summary>
    /// Retrieves complete card content including ISD, applications, and load files.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.4
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
        var isdTask = GetIssuerSecurityDomainAsync(executeCommand, cancellationToken);
        var appsTask = GetApplicationsAndSecurityDomainsAsync(executeCommand, cancellationToken);

        // Retrieve load files
        var loadFilesTask = GetExecutableLoadFilesAsync(executeCommand, cancellationToken);
        var loadFilesWithModulesTask = GetExecutableLoadFilesWithModulesAsync(
            executeCommand,
            cancellationToken
        );

        // Wait for all tasks to complete
        var isdResult = await isdTask;
        var appsResult = await appsTask;
        var loadFilesResult = await loadFilesTask;
        var loadFilesWithModulesResult = await loadFilesWithModulesTask;

        // Combine results functionally using railway-oriented programming
        return isdResult.Bind(isd =>
            appsResult.Bind(apps =>
                loadFilesResult.Bind(loadFiles =>
                    loadFilesWithModulesResult.Bind(loadFilesWithModules =>
                        CombineIntoCardContent(isd, apps, loadFiles, loadFilesWithModules)
                    )
                )
            )
        );
    }

    /// <summary>
    /// Retrieves the Issuer Security Domain information.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.4
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
        var dataResult = await GetAllStatusDataAsync(
            GetStatusCommand.StatusSubset.IssuerSecurityDomain,
            executeCommand,
            cancellationToken
        );

        return dataResult.Bind(TlvCodec.GlobalPlatformParsers.ParseApplicationsResponse);
    }

    /// <summary>
    /// Retrieves applications and supplementary security domains.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.4
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
        var dataResult = await GetAllStatusDataAsync(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            executeCommand,
            cancellationToken
        );

        return dataResult.Bind(TlvCodec.GlobalPlatformParsers.ParseApplicationsResponse);
    }

    /// <summary>
    /// Retrieves executable load files.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.4
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
        var dataResult = await GetAllStatusDataAsync(
            GetStatusCommand.StatusSubset.ExecutableLoadFiles,
            executeCommand,
            cancellationToken
        );

        return dataResult.Bind(TlvCodec.GlobalPlatformParsers.ParseLoadFilesResponse);
    }

    /// <summary>
    /// Retrieves executable load files and their executable modules.
    /// Reference: GlobalPlatform Card Specification v2.3.1 Section 11.4
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
        var dataResult = await GetAllStatusDataAsync(
            GetStatusCommand.StatusSubset.ExecutableLoadFilesAndModules,
            executeCommand,
            cancellationToken
        );

        return dataResult.Bind(TlvCodec.GlobalPlatformParsers.ParseLoadFilesResponse);
    }

    #region Private Helper Methods

    private static async Task<Result<byte[], SmartCardError>> GetAllStatusDataAsync(
        GetStatusCommand.StatusSubset subset,
        Func<
            CommandAPDU,
            CancellationToken,
            Task<Result<CommandResponse, SmartCardError>>
        > executeCommand,
        CancellationToken cancellationToken
    )
    {
        var data = new List<byte>();
        var occurrence = GetStatusCommand.OccurrenceMode.FirstOrAll;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var commandResult = Commands
                .CreateGetStatusCommand(subset, occurrence: occurrence)
                .Bind(command => command.ToCommandApdu());
            if (commandResult.IsFailure)
            {
                return commandResult.Error;
            }

            var responseResult = await executeCommand(commandResult.Value, cancellationToken);
            if (responseResult.IsFailure)
            {
                return responseResult.Error;
            }

            var response = responseResult.Value;
            if (response.StatusWord != GET_STATUS_MORE_DATA && !response.IsSuccess)
            {
                return SmartCardError.FromStatusWord(response.StatusWord);
            }

            data.AddRange(response.Data);
            if (response.IsSuccess)
            {
                return data.ToArray();
            }

            // GP Card Specification v2.3.1, Table 11-38.
            occurrence = GetStatusCommand.OccurrenceMode.Next;
        }
    }

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
        var issuerSecurityDomain =
            isd.Count > 0 ? Maybe<ApplicationInfo>.From(isd.First()) : Maybe<ApplicationInfo>.None;

        // Combine all load files (prefer ones with modules if available)
        var loadFileDict = loadFilesWithModules
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
