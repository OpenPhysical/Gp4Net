using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Core.Tlv;
using Gp4Net.Domain;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Pipeline;
using Gp4Net.Domain.Modules;
using Microsoft.Extensions.Logging;
using StatusSubset = Gp4Net.Domain.Commands.GetStatusCommand.StatusSubset;

namespace Gp4Net.Services;

/// <summary>
/// Functional implementation of IGlobalPlatformService using pure functions.
/// Built alongside the existing service for gradual migration.
/// </summary>
public class GlobalPlatformService : IGlobalPlatformService
{
    private readonly ISmartCardService _cardService;
    private readonly ISecureChannelManager _secureChannelManager;
    private readonly ILogger<GlobalPlatformService> _logger;

    /// <inheritdoc/>
    public ISmartCardService CardService => _cardService;

    /// <summary>
    /// Initializes a new instance of the GlobalPlatformService class.
    /// </summary>
    public GlobalPlatformService(
        ISmartCardService cardService,
        ISecureChannelManager secureChannelManager,
        ILogger<GlobalPlatformService> logger)
    {
        _cardService = cardService;
        _secureChannelManager = secureChannelManager;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<Result<SelectResponse, SmartCardError>> SelectIsdAsync(
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Selecting Issuer Security Domain with auto-detection");

        // Use the CardDiscovery module
        var result = await CardDiscovery.DetectAndSelectIsdAsync(
            async (cmd, ct) => await _cardService.ExecuteCommandAsync(cmd, ct),
            cancellationToken);

        // Normalize errors to a consistent message expected by tests/consumers
        if (result.IsFailure)
        {
            return Result.Failure<SelectResponse, SmartCardError>(
                SmartCardError.CardError("No ISD found on card"));
        }

        return result;
    }

    /// <inheritdoc/>
    public async Task<Result<Domain.Security.SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        KeySet keySet,
        SecurityLevel securityLevel = SecurityLevel.CMac,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Establishing secure channel with security level: {SecurityLevel}", securityLevel);

        // Use the SecureChannelEstablishment module
        var result = await SecureChannelEstablishment.EstablishAsync(
            keySet,
            securityLevel,
            async (cmd, ct) => await _cardService.ExecuteCommandAsync(cmd, ct),
            selectedAid: null,
            cancellationToken);

        // The secure channel state will be managed by the SecureChannelManager
        return result;
    }

    /// <inheritdoc/>
    public async Task<Result<ImmutableList<ApplicationInfo>, SmartCardError>> GetStatusAsync(
        StatusSubset subset = StatusSubset.IssuerSecurityDomain,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Getting status for subset: {Subset}", subset);

        // Convert between enums and use CardStatusRetriever module
        var domainSubset = (GetStatusCommand.StatusSubset)(byte)subset;
        return await CardStatusRetriever.GetStatusAsync(
            domainSubset,
            async (cmd, ct) => await _cardService.ExecuteCommandAsync(cmd, ct),
            cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<Result<InstallationResult, SmartCardError>> InstallCapFileAsync(
        byte[] capFileData,
        InstallOptions options,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Installing CAP file ({Length} bytes)", capFileData.Length);
            
        // Validate secure channel is established
        var session = _cardService.Context.Get<Domain.Security.SecureChannelState>(ContextKeys.SecureChannelSession);
        if (!session.HasValue)
        {
            return Result.Failure<InstallationResult, SmartCardError>(
                SmartCardError.SecurityError("Security status not satisfied"));
        }

        // Basic CAP file validation
        if (capFileData == null || capFileData.Length == 0)
        {
            return Result.Failure<InstallationResult, SmartCardError>(
                SmartCardError.InvalidData("CAP file data is empty"));
        }

        // Create loading commands using the CAP file loading workflow
        var createCommandsResult = Domain.CapFile.CapFileLoadingWorkflow.CreateLoadingCommands(capFileData);
        
        if (createCommandsResult.IsFailure)
        {
            return Result.Failure<InstallationResult, SmartCardError>(createCommandsResult.Error);
        }

        var commands = createCommandsResult.Value;
        _logger.LogInformation("Created {Count} installation commands from CAP file", commands.Count);

        // Execute all commands through the card service using functional composition
        var tasks = commands
            .Select(async command => 
                (await _cardService.ExecuteCommandAsync(command, cancellationToken))
                    .Map(response => (command, response)))
            .ToArray();
            
        var results = await Task.WhenAll(tasks);
        
        // Check for any failures - fail fast on first error
        foreach (var result in results)
        {
            if (result.IsFailure)
            {
                return Result.Failure<InstallationResult, SmartCardError>(result.Error);
            }
        }
        
        // All successful - extract values
        var successfulResults = results.Select(r => r.Value).ToArray();
        
        _logger.LogInformation("Successfully installed CAP file with {Count} commands", successfulResults.Length);
        
        return Result.Success<InstallationResult, SmartCardError>(
            new InstallationResult(
                PackageAid: ExtractPackageAidFromResults(successfulResults),
                InstalledApplets: ExtractInstalledAppletsFromResults(successfulResults),
                ExecutedCommands: successfulResults.Length));
    }

    /// <summary>
    /// Extracts the package AID from installation results by analyzing INSTALL [for load] commands.
    /// </summary>
    /// <param name="results">The command execution results.</param>
    /// <returns>The package AID bytes extracted from successful installation commands.</returns>
    private static byte[] ExtractPackageAidFromResults((IApduCommand command, Pipeline.CommandResponse response)[] results)
    {
        var packageAids = results
            .Where(r => r.response.IsSuccess)
            .Select(r => r.command)
            .OfType<Domain.Commands.InstallCommand>()
            .Select(cmd => cmd.PackageAid.ToArray())
            .Where(aid => aid.Length > 0)
            .ToArray();

        return packageAids.Length > 0 ? packageAids[0] : [];
    }

    /// <summary>
    /// Extracts installed applet AIDs from installation results by analyzing command data.
    /// </summary>
    /// <param name="results">The command execution results.</param>
    /// <returns>List of installed applet AIDs extracted from successful installation commands.</returns>
    private static ImmutableList<byte[]> ExtractInstalledAppletsFromResults((IApduCommand command, Pipeline.CommandResponse response)[] results)
    {
        return results
            .Where(r => r.response.IsSuccess)
            .Select(r => r.command)
            .OfType<Domain.Commands.InstallCommand>()
            .Select(cmd => cmd.PackageAid.ToArray())
            .Where(aid => aid.Length > 0)
            .ToImmutableList();
    }

    /// <inheritdoc/>
    public async Task<Result<bool, SmartCardError>> DeleteApplicationAsync(
        byte[] aid,
        bool deleteRelated = false,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Deleting application with AID: {AID}", Convert.ToHexString(aid));

        // Use CardLifecycleManager module
        return await CardLifecycleManager.DeleteApplicationAsync(
            aid,
            deleteRelated,
            async (cmd, ct) => await _cardService.ExecuteCommandAsync(cmd, ct),
            cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<Result<bool, SmartCardError>> PutKeysAsync(
        KeySet keySet,
        byte keyVersion,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Putting keys with version: {KeyVersion}", keyVersion);
            
        // Validate secure channel is established
        var session = _cardService.Context.Get<Domain.Security.SecureChannelState>(ContextKeys.SecureChannelSession);
        if (!session.HasValue)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.SecurityError("Security status not satisfied"));
        }

        // Validate key set
        if (keySet == null)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("Key set cannot be null"));
        }

        // Create PUT KEY command
        var commandResult = PutKeyCommand.Create(
                keyVersion: keyVersion,
                keyDataBlocks: new List<KeyDataBlock>()) // Empty for now
            .MapError(e => SmartCardError.InvalidData($"Failed to create PUT KEY command: {e.Message}"));

        if (commandResult.IsFailure)
        {
            return commandResult.Error;
        }

        // Execute command
        var response = await _cardService.ExecuteCommandAsync(commandResult.Value, cancellationToken);
        return response.Map(r => r.IsSuccess);
    }

    /// <inheritdoc/>
    public async Task<Result<CplcData, SmartCardError>> GetCplcAsync(
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Getting CPLC data");

        var commandResult = CommandFactory.CreateGetDataCommand(GetDataCommand.DataObjects.CardProductionLifeCycle);
        if (commandResult.IsFailure)
        {
            return Result.Failure<CplcData, SmartCardError>(commandResult.Error);
        }

        var response = await _cardService.ExecuteCommandAsync(commandResult.Value, cancellationToken);
            
        return response.Bind(r => ResponseParser.ParseCplcResponse(r));
    }

    /// <inheritdoc/>
    public async Task<Result<byte[], SmartCardError>> GetDataAsync(
        ushort tag,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Getting data for tag: {Tag:X4}", tag);

        var commandResult = CommandFactory.CreateGetDataCommand(tag);
        if (commandResult.IsFailure)
        {
            return Result.Failure<byte[], SmartCardError>(commandResult.Error);
        }

        var response = await _cardService.ExecuteCommandAsync(commandResult.Value, cancellationToken);
            
        return response.Bind(r => ResponseParser.ParseGetDataResponse(r));
    }

    /// <inheritdoc/>
    public async Task<Result<bool, SmartCardError>> SetLifecycleStateAsync(
        byte[] aid,
        LifecycleState state,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Setting lifecycle state for AID: {AID} to {State}", 
            Convert.ToHexString(aid), state);
            
        // Validate secure channel is established
        var session = _cardService.Context.Get<Domain.Security.SecureChannelState>(ContextKeys.SecureChannelSession);
        if (!session.HasValue)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.SecurityError("Security status not satisfied"));
        }

        // Use CardLifecycleManager module
        return await CardLifecycleManager.SetLifecycleStateAsync(
            aid,
            state,
            async (cmd, ct) => await _cardService.ExecuteCommandAsync(cmd, ct),
            cancellationToken);
    }

}
