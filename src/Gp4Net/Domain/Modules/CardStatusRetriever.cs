using System;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
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
            new byte[] { 0x4F, 0x00 }); // Tag 4F, length 0
        
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
            new byte[] { 0x4F, 0x00 }); // Tag 4F, length 0
        
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
            new byte[] { 0x4F, 0x00 }); // Tag 4F, length 0
        
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
            new byte[] { 0x4F, 0x00 }); // Tag 4F, length 0
        
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

        // For now, return empty list as we need to implement proper parsing
        // This would require parsing the TLV structure for load file information
        return Result.Success<ImmutableList<ExecutableLoadFile>, SmartCardError>(
            ImmutableList<ExecutableLoadFile>.Empty);
    }
}