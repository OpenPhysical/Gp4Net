using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.Tlv;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using Gp4Net.Pipeline;

namespace Gp4Net.Domain.Modules;

/// <summary>
/// Pure functional module for retrieving card status information.
/// Handles GET STATUS operations for different entity types.
/// </summary>
public static class CardStatusRetriever
{
    /// <summary>
    /// Retrieves complete card content including ISD, applications, and load files.
    /// </summary>
    /// <param name="executeCommand">Function to execute APDU commands.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The complete card content or an error.</returns>
    public static async Task<Result<CardContent, SmartCardError>> RetrieveCompleteCardContentAsync(
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
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

        // Check for failures
        if (isdTask.Result.IsFailure)
            return Result.Failure<CardContent, SmartCardError>(isdTask.Result.Error);
        if (appsTask.Result.IsFailure)
            return Result.Failure<CardContent, SmartCardError>(appsTask.Result.Error);
        if (loadFilesTask.Result.IsFailure)
            return Result.Failure<CardContent, SmartCardError>(loadFilesTask.Result.Error);
        if (loadFilesWithModulesTask.Result.IsFailure)
            return Result.Failure<CardContent, SmartCardError>(loadFilesWithModulesTask.Result.Error);

        // Combine results into CardContent
        return CombineIntoCardContent(
            isdTask.Result.Value,
            appsTask.Result.Value,
            loadFilesTask.Result.Value,
            loadFilesWithModulesTask.Result.Value);
    }

    /// <summary>
    /// Retrieves the Issuer Security Domain information.
    /// </summary>
    public static async Task<Result<ImmutableList<ApplicationInfo>, SmartCardError>> GetIssuerSecurityDomainAsync(
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        Result<GetStatusCommand, SmartCardError> cmdResult = CommandFactory.CreateGetStatusCommand(
            GetStatusCommand.StatusSubset.IssuerSecurityDomain,
            [0x4F, 0x00]); // Tag 4F, length 0

        if (cmdResult.IsFailure)
        {
            return Result.Failure<ImmutableList<ApplicationInfo>, SmartCardError>(cmdResult.Error);
        }

        Result<CommandResponse, SmartCardError> response =
            await executeCommand(cmdResult.Value, cancellationToken);

        return response.IsSuccess
            ? ResponseParser.ParseGetStatusResponse(response.Value)
            : Result.Failure<ImmutableList<ApplicationInfo>, SmartCardError>(response.Error);
    }

    /// <summary>
    /// Retrieves applications and supplementary security domains.
    /// </summary>
    public static async Task<Result<ImmutableList<ApplicationInfo>, SmartCardError>> GetApplicationsAndSecurityDomainsAsync(
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        Result<GetStatusCommand, SmartCardError> cmdResult = CommandFactory.CreateGetStatusCommand(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            [0x4F, 0x00]); // Tag 4F, length 0

        if (cmdResult.IsFailure)
        {
            return Result.Failure<ImmutableList<ApplicationInfo>, SmartCardError>(cmdResult.Error);
        }

        Result<CommandResponse, SmartCardError> response =
            await executeCommand(cmdResult.Value, cancellationToken);

        return response.IsSuccess
            ? ResponseParser.ParseGetStatusResponse(response.Value)
            : Result.Failure<ImmutableList<ApplicationInfo>, SmartCardError>(response.Error);
    }

    /// <summary>
    /// Retrieves executable load files.
    /// </summary>
    public static async Task<Result<ImmutableList<ExecutableLoadFile>, SmartCardError>> GetExecutableLoadFilesAsync(
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        Result<GetStatusCommand, SmartCardError> cmdResult = CommandFactory.CreateGetStatusCommand(
            GetStatusCommand.StatusSubset.ExecutableLoadFiles,
            [0x4F, 0x00]); // Tag 4F, length 0

        if (cmdResult.IsFailure)
        {
            return Result.Failure<ImmutableList<ExecutableLoadFile>, SmartCardError>(cmdResult.Error);
        }

        Result<CommandResponse, SmartCardError> response =
            await executeCommand(cmdResult.Value, cancellationToken);

        return response.IsSuccess
            ? ParseLoadFileResponse(response.Value)
            : Result.Failure<ImmutableList<ExecutableLoadFile>, SmartCardError>(response.Error);
    }

    /// <summary>
    /// Retrieves executable load files and their modules.
    /// </summary>
    public static async Task<Result<ImmutableList<ExecutableLoadFile>, SmartCardError>> GetExecutableLoadFilesWithModulesAsync(
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        Result<GetStatusCommand, SmartCardError> cmdResult = CommandFactory.CreateGetStatusCommand(
            GetStatusCommand.StatusSubset.ExecutableLoadFilesAndModules,
            [0x4F, 0x00]); // Tag 4F, length 0

        if (cmdResult.IsFailure)
        {
            return Result.Failure<ImmutableList<ExecutableLoadFile>, SmartCardError>(cmdResult.Error);
        }

        Result<CommandResponse, SmartCardError> response =
            await executeCommand(cmdResult.Value, cancellationToken);

        return response.IsSuccess
            ? ParseLoadFileResponse(response.Value)
            : Result.Failure<ImmutableList<ExecutableLoadFile>, SmartCardError>(response.Error);
    }

    /// <summary>
    /// Retrieves status for a specific subset.
    /// </summary>
    public static async Task<Result<ImmutableList<ApplicationInfo>, SmartCardError>> GetStatusAsync(
        GetStatusCommand.StatusSubset subset,
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        Result<GetStatusCommand, SmartCardError> cmdResult =
            CommandFactory.CreateGetStatusCommand(subset);

        if (cmdResult.IsFailure)
        {
            return Result.Failure<ImmutableList<ApplicationInfo>, SmartCardError>(cmdResult.Error);
        }

        Result<CommandResponse, SmartCardError> response =
            await executeCommand(cmdResult.Value, cancellationToken);

        return response.IsSuccess
            ? ResponseParser.ParseGetStatusResponse(response.Value)
            : Result.Failure<ImmutableList<ApplicationInfo>, SmartCardError>(response.Error);
    }

    /// <summary>
    /// Combines entity lists into a CardContent structure.
    /// </summary>
    private static Result<CardContent, SmartCardError> CombineIntoCardContent(
        ImmutableList<ApplicationInfo> isdList,
        ImmutableList<ApplicationInfo> appsAndSds,
        ImmutableList<ExecutableLoadFile> loadFiles,
        ImmutableList<ExecutableLoadFile> loadFilesWithModules)
    {
        // Extract ISD (should be only one)
        Maybe<ApplicationInfo> isd = isdList.Count > 0
            ? Maybe<ApplicationInfo>.From(isdList[0])
            : Maybe<ApplicationInfo>.None;

        // Separate applications and security domains
        ImmutableList<ApplicationInfo> applications = appsAndSds
            .Where(app => app.Type == ApplicationType.Application)
            .ToImmutableList();

        ImmutableList<ApplicationInfo> securityDomains = appsAndSds
            .Where(app => app.Type == ApplicationType.SupplementarySecurityDomain)
            .ToImmutableList();

        // Use load files with modules if available, otherwise basic load files
        ImmutableList<ExecutableLoadFile> effectiveLoadFiles = loadFilesWithModules.Count > 0
            ? loadFilesWithModules
            : loadFiles;

        return Result.Success<CardContent, SmartCardError>(
            new CardContent(
                IssuerSecurityDomain: isd,
                Applications: applications,
                SecurityDomains: securityDomains,
                ExecutableLoadFiles: effectiveLoadFiles));
    }

    /// <summary>
    /// Parses a GET STATUS response for executable load files.
    /// </summary>
    private static Result<ImmutableList<ExecutableLoadFile>, SmartCardError> ParseLoadFileResponse(
        CommandResponse response)
    {
        if (!response.IsSuccess)
        {
            return Result.Failure<ImmutableList<ExecutableLoadFile>, SmartCardError>(
                SmartCardError.InvalidResponse($"GET STATUS failed with SW: {response.StatusWord:X4}"));
        }

        byte[] data = response.Data ?? [];

        // Parse TLV entries per GP Table 11-37; cards return multiple E3 entries (per-entry templates)
        ImmutableList<TlvObject> tlvs = Core.Tlv.TlvParser.ParseAll(data).ToImmutableList();

        // Per GP Table 11-37, all load file responses MUST use E3 containers. All traced cards comply.
        ImmutableList<TlvObject> entryTlvs = tlvs.Where(t =>
        {
            Result<uint, SmartCardError> tagNumber = t.GetTagNumber();
            return tagNumber.IsSuccess && tagNumber.Value == 0xE3;
        }).ToImmutableList();

        ImmutableList<ExecutableLoadFile>.Builder builder = ImmutableList.CreateBuilder<ExecutableLoadFile>();

        foreach (TlvObject entry in entryTlvs)
        {
            // For E3 templates, parse children; otherwise, treat the TLV itself as a container
            Result<uint, SmartCardError> tagNumber = entry.GetTagNumber();
            ImmutableList<TlvObject> children = tagNumber.IsSuccess && tagNumber.Value == 0xE3
                ? entry.ParseNestedTlv().ToImmutableList()
                : new[] { entry }.ToImmutableList();

            // Aid (4F)
            TlvObject aidTlv = children.FirstOrDefault(c =>
            {
                Result<uint, SmartCardError> tagNumber = c.GetTagNumber();
                return tagNumber.IsSuccess && tagNumber.Value == 0x4F;
            });
            if (aidTlv == null || aidTlv.Value == null || aidTlv.Value.Length == 0)
            {
                // Skip malformed entry without AID
                continue;
            }
            byte[] aid = aidTlv.Value;

            // Lifecycle (prefer 9F70, else Unknown)
            TlvObject lifeTlv = children.FirstOrDefault(c =>
            {
                Result<uint, SmartCardError> tagNumber = c.GetTagNumber();
                return tagNumber.IsSuccess && tagNumber.Value == 0x9F70;
            });
            LifecycleState lifecycle = lifeTlv != null && lifeTlv.Value != null && lifeTlv.Value.Length > 0
                ? MapLifecycle(lifeTlv.Value[0])
                : LifecycleState.Unknown;

            // Modules (84 can appear multiple times)
            IEnumerable<TlvObject> moduleTlvs = children.Where(c =>
            {
                Result<uint, SmartCardError> tagNumber = c.GetTagNumber();
                return tagNumber.IsSuccess && tagNumber.Value == 0x84 && c.Value != null && c.Value.Length > 0;
            });
            ImmutableList<ExecutableModule> modules = moduleTlvs
                .Select(m => new ExecutableModule(m.Value))
                .ToImmutableList();

            // Associated Security Domain AID (observed tag CC in traces)
            TlvObject sdTlv = children.FirstOrDefault(c =>
            {
                Result<uint, SmartCardError> tagNumber = c.GetTagNumber();
                return tagNumber.IsSuccess && tagNumber.Value == 0xCC;
            });
            Maybe<byte[]> sdAidMaybe = sdTlv != null && sdTlv.Value != null && sdTlv.Value.Length >= 5 && sdTlv.Value.Length <= 16
                ? Maybe<byte[]>.From(sdTlv.Value)
                : Maybe<byte[]>.None;

            // Version (observed tag CE 02 [major][minor])
            TlvObject verTlv = children.FirstOrDefault(c =>
            {
                Result<uint, SmartCardError> tagNumber = c.GetTagNumber();
                return tagNumber.IsSuccess && tagNumber.Value == 0xCE;
            });
            Maybe<string> versionMaybe = Maybe<string>.None;
            if (verTlv != null && verTlv.Value != null && verTlv.Value.Length >= 2)
            {
                byte major = verTlv.Value[0];
                byte minor = verTlv.Value[1];
                versionMaybe = Maybe<string>.From($"{major}.{minor}");
            }

            builder.Add(new ExecutableLoadFile(
                Aid: aid,
                LifecycleState: lifecycle,
                Version: versionMaybe,
                ExecutableModules: modules,
                AssociatedSecurityDomainAid: sdAidMaybe));
        }

        return Result.Success<ImmutableList<ExecutableLoadFile>, SmartCardError>(builder.ToImmutable());

        static LifecycleState MapLifecycle(byte b) => b switch
        {
            0x01 => LifecycleState.Loaded,
            0x03 => LifecycleState.Installed,
            0x07 => LifecycleState.Selectable,
            0x0F => LifecycleState.Personalized,
            0x7F => LifecycleState.Locked,
            0xFF => LifecycleState.Terminated,
            _ => LifecycleState.Unknown
        };
    }
}
