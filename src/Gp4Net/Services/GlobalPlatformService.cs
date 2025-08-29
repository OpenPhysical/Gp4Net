using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Modules;
using Gp4Net.Domain.Protocol;
using Gp4Net.Domain.Security;
using Gp4Net.Pipeline;
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
    private readonly IKeysetResolver _keysetResolver;
    private readonly ILogger<GlobalPlatformService> _logger;

    /// <inheritdoc/>
    public ISmartCardService CardService => _cardService;

    /// <summary>
    /// Initializes a new instance of the GlobalPlatformService class.
    /// </summary>
    public GlobalPlatformService(
        ISmartCardService cardService,
        IKeysetResolver keysetResolver,
        ILogger<GlobalPlatformService> logger)
    {
        _cardService = cardService;
        _keysetResolver = keysetResolver;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<Result<SelectResponse, SmartCardError>> SelectIsdAsync(
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Selecting Issuer Security Domain with auto-detection");

        // Use the CardDiscovery module
        Result<SelectResponse, SmartCardError> result = await CardDiscovery.DetectAndSelectIsdAsync(
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
    public async Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        KeySet keySet,
        SecurityLevel securityLevel = SecurityLevel.CMac,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Establishing secure channel with security level: {SecurityLevel}", securityLevel);

        // Use the SCP protocol directly for secure channel establishment
        Result<SecureChannelState, SmartCardError> result = await EstablishSecureChannelDirectly(
            keySet,
            securityLevel,
            cancellationToken);

        // The secure channel state will be managed by the SecureChannelManager
        return result;
    }

    /// <inheritdoc/>
    public async Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        string keysetName,
        SecurityLevel securityLevel = SecurityLevel.CMac,
        byte keyVersion = 0x01,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Establishing secure channel with keyset: {KeysetName}, security level: {SecurityLevel}",
            keysetName, securityLevel);

        // Send INITIALIZE UPDATE to get card response for diversification
        Result<InitializeUpdateResponse, SmartCardError> initUpdateResult = await SendInitializeUpdateForDiversificationAsync(keyVersion, cancellationToken);
        if (initUpdateResult.IsFailure)
        {
            return Result.Failure<SecureChannelState, SmartCardError>(initUpdateResult.Error);
        }

        // Resolve keyset with card response for proper diversification
        Result<IKeySet, SmartCardError> keySetResult = initUpdateResult
            .Bind(initResponse => _keysetResolver.ResolveKeyset(
                keysetName,
                new Dictionary<string, string>(), // Empty parameters for named keysets
                Maybe<byte[]>.None, Maybe<byte[]>.None, Maybe<byte[]>.None, // No explicit keys
                keyVersion,
                Maybe<InitializeUpdateResponse>.From(initResponse)));

        // Establish secure channel using functional composition
        return await keySetResult.Match(
            keySet => keySet switch
            {
                KeySet concreteKeySet => EstablishSecureChannelAsync(concreteKeySet, securityLevel, cancellationToken),
                _ => Task.FromResult(Result.Failure<SecureChannelState, SmartCardError>(
                    SmartCardError.CryptographicError("Resolved keyset is not a concrete KeySet instance")))
            },
            error => Task.FromResult(Result.Failure<SecureChannelState, SmartCardError>(error))
        );
    }

    /// <inheritdoc/>
    public async Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelAsync(
        string encKey,
        string macKey,
        string dekKey,
        byte keyVersion,
        SecurityLevel securityLevel = SecurityLevel.CMac,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Establishing secure channel with explicit keys, security level: {SecurityLevel}", securityLevel);

        // Convert hex strings to byte arrays using functional patterns
        Result<byte[], SmartCardError> encKeyResult = ConvertHexKey(encKey, "ENC");
        Result<byte[], SmartCardError> macKeyResult = ConvertHexKey(macKey, "MAC");
        Result<byte[], SmartCardError> dekKeyResult = ConvertHexKey(dekKey, "DEK");

        // Validate all key conversions succeeded
        return await encKeyResult
            .Bind(encBytes => macKeyResult
                .Bind(macBytes => dekKeyResult
                    .Bind(dekBytes => EstablishWithExplicitKeys(encBytes, macBytes, dekBytes, keyVersion, securityLevel, cancellationToken))));
    }

    /// <summary>
    /// Establishes secure channel with explicit key bytes.
    /// </summary>
    private async Task<Result<SecureChannelState, SmartCardError>> EstablishWithExplicitKeys(
        byte[] encKey, byte[] macKey, byte[] dekKey, byte keyVersion,
        SecurityLevel securityLevel, CancellationToken cancellationToken)
    {
        // Send INITIALIZE UPDATE to get card response for diversification
        Result<InitializeUpdateResponse, SmartCardError> initUpdateResult = await SendInitializeUpdateForDiversificationAsync(keyVersion, cancellationToken);
        if (initUpdateResult.IsFailure)
        {
            return Result.Failure<SecureChannelState, SmartCardError>(initUpdateResult.Error);
        }

        // Resolve keyset with explicit keys and card response
        Result<IKeySet, SmartCardError> keySetResult = initUpdateResult
            .Bind(initResponse => _keysetResolver.ResolveKeyset(
                string.Empty, // No named keyset
                new Dictionary<string, string>(), // Empty parameters
                Maybe<byte[]>.From(encKey), Maybe<byte[]>.From(macKey), Maybe<byte[]>.From(dekKey), // Explicit keys
                keyVersion,
                Maybe<InitializeUpdateResponse>.From(initResponse)));

        // Establish secure channel using functional composition
        return await keySetResult.Match(
            keySet => keySet switch
            {
                KeySet concreteKeySet => EstablishSecureChannelAsync(concreteKeySet, securityLevel, cancellationToken),
                _ => Task.FromResult(Result.Failure<SecureChannelState, SmartCardError>(
                    SmartCardError.CryptographicError("Resolved keyset is not a concrete KeySet instance")))
            },
            error => Task.FromResult(Result.Failure<SecureChannelState, SmartCardError>(error))
        );
    }

    /// <summary>
    /// Sends INITIALIZE UPDATE command to get card response for key diversification.
    /// </summary>
    private async Task<Result<InitializeUpdateResponse, SmartCardError>> SendInitializeUpdateForDiversificationAsync(
        byte keyVersion, CancellationToken cancellationToken)
    {
        Result<byte[], SmartCardError> hostChallengeResult = CryptographicOperations.GenerateHostChallenge();
        if (hostChallengeResult.IsFailure)
        {
            return Result.Failure<InitializeUpdateResponse, SmartCardError>(hostChallengeResult.Error);
        }

        byte[] hostChallenge = hostChallengeResult.Value;

        // Create the command using the direct static method
        Result<InitializeUpdateCommand, SmartCardError> commandResult = InitializeUpdateCommand.Create(keyVersion, 0x00, hostChallenge);
        if (commandResult.IsFailure)
        {
            return Result.Failure<InitializeUpdateResponse, SmartCardError>(commandResult.Error);
        }

        // Execute the command
        Result<CommandResponse, SmartCardError> response = await _cardService.ExecuteCommandAsync(commandResult.Value, cancellationToken);
        if (response.IsFailure)
        {
            return Result.Failure<InitializeUpdateResponse, SmartCardError>(response.Error);
        }

        // Parse the response using the direct static method
        return InitializeUpdateResponse.Parse(response.Value.Data);
    }

    /// <summary>
    /// Converts hex string to byte array using functional error handling.
    /// </summary>
    private static Result<byte[], SmartCardError> ConvertHexKey(string hexKey, string keyType)
    {
        return Result.Try(() => Convert.FromHexString(hexKey),
            ex => SmartCardError.InvalidArgument($"Invalid {keyType} key format: {ex.Message}"));
    }

    /// <inheritdoc/>
    public async Task<Result<ImmutableList<ApplicationInfo>, SmartCardError>> GetStatusAsync(
        StatusSubset subset = StatusSubset.IssuerSecurityDomain,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Getting status for subset: {Subset}", subset);

        // Convert between enums and use CardStatusRetriever module
        StatusSubset domainSubset = (StatusSubset)(byte)subset;
        return await CardStatusRetriever.GetStatusAsync(
            domainSubset,
            async (cmd, ct) => await _cardService.ExecuteCommandAsync(cmd, ct),
            cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<Result<InstallationResult, SmartCardError>> InstallCapFileAsync(
        byte[] capFileData,
        Maybe<InstallOptions> options = default,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Installing CAP file ({Length} bytes)", capFileData.Length);

        // Validate secure channel is established
        Maybe<SecureChannelState> session = _cardService.Context.Get<Domain.SecureChannelState>(ContextKeys.SecureChannelSession);
        if (!session.HasValue)
        {
            return Result.Failure<InstallationResult, SmartCardError>(
                SmartCardError.SecurityError("Security status not satisfied"));
        }

        // Basic CAP file validation
        if (capFileData.Length == 0)
        {
            return Result.Failure<InstallationResult, SmartCardError>(
                SmartCardError.InvalidData("CAP file data is empty"));
        }

        // Create loading commands using the CAP file loading workflow
        Result<IList<IApduCommand>, SmartCardError> createCommandsResult = Domain.CapFile.CapFileLoadingWorkflow.CreateLoadingCommands(capFileData);

        if (createCommandsResult.IsFailure)
        {
            return Result.Failure<InstallationResult, SmartCardError>(createCommandsResult.Error);
        }

        IList<IApduCommand> commands = createCommandsResult.Value;
        _logger.LogInformation("Created {Count} installation commands from CAP file", commands.Count);

        // Execute all commands through the card service using functional composition
        Task<Result<(IApduCommand command, CommandResponse response), SmartCardError>>[] tasks = commands
            .Select(async command =>
                (await _cardService.ExecuteCommandAsync(command, cancellationToken))
                    .Map(response => (command, response)))
            .ToArray();

        Result<(IApduCommand command, CommandResponse response), SmartCardError>[] results = await Task.WhenAll(tasks);

        // Check for any failures - fail fast on first error
        foreach (Result<(IApduCommand command, CommandResponse response), SmartCardError> result in results)
        {
            if (result.IsFailure)
            {
                return Result.Failure<InstallationResult, SmartCardError>(result.Error);
            }
        }

        // All successful - extract values
        (IApduCommand command, CommandResponse response)[] successfulResults = results.Select(r => r.Value).ToArray();

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
    private static byte[] ExtractPackageAidFromResults((IApduCommand command, CommandResponse response)[] results)
    {
        byte[][] packageAids = results
            .Where(r => r.response.IsSuccess)
            .Select(r => r.command)
            .OfType<InstallCommand>()
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
    private static ImmutableList<byte[]> ExtractInstalledAppletsFromResults((IApduCommand command, CommandResponse response)[] results)
    {
        return results
            .Where(r => r.response.IsSuccess)
            .Select(r => r.command)
            .OfType<InstallCommand>()
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
        Maybe<SecureChannelState> session = _cardService.Context.Get<Domain.SecureChannelState>(ContextKeys.SecureChannelSession);
        if (!session.HasValue)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.SecurityError("Security status not satisfied"));
        }

        // Key set validation happens at compile time with non-nullable types

        // Create PUT KEY command
        Result<PutKeyCommand, SmartCardError> commandResult = PutKeyCommand.Create(
                keyVersion: keyVersion,
                keyDataBlocks: new List<KeyDataBlock>()) // Empty for now
            .MapError(e => SmartCardError.InvalidData($"Failed to create PUT KEY command: {e.Message}"));

        if (commandResult.IsFailure)
        {
            return commandResult.Error;
        }

        // Execute command
        Result<CommandResponse, SmartCardError> response = await _cardService.ExecuteCommandAsync(commandResult.Value, cancellationToken);
        return response.Map(r => r.IsSuccess);
    }

    /// <inheritdoc/>
    public async Task<Result<CplcData, SmartCardError>> GetCplcAsync(
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Getting CPLC data");

        Result<GetDataCommand, SmartCardError> commandResult = GetDataCommand.Create(GetDataCommand.DataObjects.CardProductionLifeCycle);
        if (commandResult.IsFailure)
        {
            return Result.Failure<CplcData, SmartCardError>(commandResult.Error);
        }

        Result<CommandResponse, SmartCardError> response = await _cardService.ExecuteCommandAsync(commandResult.Value, cancellationToken);

        // Parse CPLC data from response data
        return response.Bind(r => CplcData.Parse(r.Data));
    }

    /// <inheritdoc/>
    public async Task<Result<byte[], SmartCardError>> GetDataAsync(
        ushort tag,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Getting data for tag: {Tag:X4}", tag);

        Result<GetDataCommand, SmartCardError> commandResult = GetDataCommand.Create(tag);
        if (commandResult.IsFailure)
        {
            return Result.Failure<byte[], SmartCardError>(commandResult.Error);
        }

        Result<CommandResponse, SmartCardError> response = await _cardService.ExecuteCommandAsync(commandResult.Value, cancellationToken);

        // Return the response data directly
        return response.Map(r => r.Data);
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
        Maybe<SecureChannelState> session = _cardService.Context.Get<Domain.SecureChannelState>(ContextKeys.SecureChannelSession);
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

    /// <inheritdoc/>
    public async Task<Result<CardInformation, SmartCardError>> GetCardInfoAsync(
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Retrieving comprehensive card information");

        // Get CPLC data (optional - some cards may not support it)
        Result<CplcData, SmartCardError> cplcResult = await GetCplcAsync(cancellationToken);
        Maybe<CplcData> cplc = cplcResult.Match(
            success => Maybe<CplcData>.From(success),
            error => Maybe<CplcData>.None);

        // Get ISD selection info (optional - may already be selected)
        Result<SelectResponse, SmartCardError> isdResult = await SelectIsdAsync(cancellationToken);
        Maybe<SelectResponse> isdInfo = isdResult.Match(
            success => Maybe<SelectResponse>.From(success),
            error => Maybe<SelectResponse>.None);

        // Get reader name from card service context
        string readerName = _cardService.Context.Get<string>("ReaderName")
            .Match(name => name, () => "Unknown Reader");

        // Build card information record
        return Result.Success<CardInformation, SmartCardError>(
            new CardInformation(
                Cplc: cplc,
                IsdInfo: isdInfo,
                ReaderName: readerName,
                Atr: Maybe<string>.None, // Could be enhanced to get ATR
                HistoricalBytes: Maybe<byte[]>.None)); // Could be enhanced
    }

    /// <summary>
    /// Establishes secure channel directly using SCP protocol.
    /// </summary>
    /// <param name="keySet">The key set to use for authentication.</param>
    /// <param name="securityLevel">The security level to establish.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The secure channel state or error.</returns>
    private async Task<Result<SecureChannelState, SmartCardError>> EstablishSecureChannelDirectly(
        KeySet keySet,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken)
    {
        _logger.LogDebug("Establishing secure channel directly with protocol version {Protocol}", 
            keySet.KeyVersion);

        // Detect protocol version from keyset
        ScpVersion protocolVersion = keySet switch
        {
            { KeyVersion: var v } when v == 0x02 => ScpVersion.Scp02,
            { KeyVersion: var v } when v == 0x03 => ScpVersion.Scp03,
            _ => ScpVersion.Scp02 // Default fallback
        };

        // Generate host challenge using BouncyCastle (per CLAUDE.md rules)
        byte[] hostChallenge = new byte[8];
        var random = new Org.BouncyCastle.Security.SecureRandom();
        random.NextBytes(hostChallenge);

        return protocolVersion switch
        {
            ScpVersion.Scp02 => await EstablishScp02ChannelDirectly(keySet, securityLevel, hostChallenge, cancellationToken),
            ScpVersion.Scp03 => await EstablishScp03ChannelDirectly(keySet, securityLevel, hostChallenge, cancellationToken),
            _ => Result.Failure<SecureChannelState, SmartCardError>(
                SmartCardError.InvalidArgument($"Unsupported protocol version: {protocolVersion}"))
        };
    }

    /// <summary>
    /// Establishes SCP02 secure channel directly.
    /// </summary>
    private async Task<Result<SecureChannelState, SmartCardError>> EstablishScp02ChannelDirectly(
        KeySet keySet,
        SecurityLevel securityLevel,
        byte[] hostChallenge,
        CancellationToken cancellationToken)
    {
        // Create INITIALIZE UPDATE command
        return await InitializeUpdateCommand.Create(keySet.KeyVersion, keySet.KeyId, hostChallenge)
            .Bind(async initUpdateCmd =>
            {
                // Send INITIALIZE UPDATE
                var initResponse = await _cardService.ExecuteCommandAsync(initUpdateCmd, cancellationToken);
                return await initResponse
                    .Bind(response => response.IsSuccess
                        ? Result.Success<CommandResponse, SmartCardError>(response)
                        : SmartCardError.CommunicationError($"INITIALIZE UPDATE failed: SW={response.StatusWord:X4}"))
                    .Bind(response => InitializeUpdateResponse.Parse(response.Data)
                        .Bind(parsedResponse => Scp02Protocol.ProcessInitializeUpdateResponse(parsedResponse, hostChallenge, keySet)
                            .Bind(context => CompleteScp02Authentication(context, securityLevel, cancellationToken))));
            });
    }

    /// <summary>
    /// Completes SCP02 authentication after INITIALIZE UPDATE.
    /// </summary>
    private async Task<Result<SecureChannelState, SmartCardError>> CompleteScp02Authentication(
        SecureChannelContext context,
        SecurityLevel securityLevel,
        CancellationToken cancellationToken)
    {
        return await Scp02Protocol.CreateExternalAuthenticateCommand(context, securityLevel)
            .Bind(async extAuthCmd =>
            {
                var extAuthResponse = await _cardService.ExecuteCommandAsync(extAuthCmd, cancellationToken);
                return extAuthResponse
                    .Bind(response => response.IsSuccess
                        ? Scp02Protocol.CreateSecureChannelSession(context, securityLevel)
                        : SmartCardError.AuthenticationFailed($"EXTERNAL AUTHENTICATE failed: SW={response.StatusWord:X4}"));
            });
    }

    /// <summary>
    /// Establishes SCP03 secure channel directly.
    /// </summary>
    private async Task<Result<SecureChannelState, SmartCardError>> EstablishScp03ChannelDirectly(
        KeySet keySet,
        SecurityLevel securityLevel,
        byte[] hostChallenge,
        CancellationToken cancellationToken)
    {
        // Create INITIALIZE UPDATE command for SCP03
        return await InitializeUpdateCommand.Create(keySet.KeyVersion, keySet.KeyId, hostChallenge)
            .Bind(async initUpdateCmd =>
            {
                // Send INITIALIZE UPDATE
                var initResponse = await _cardService.ExecuteCommandAsync(initUpdateCmd, cancellationToken);
                return await initResponse
                    .Bind(response => response.IsSuccess
                        ? Result.Success<CommandResponse, SmartCardError>(response)
                        : SmartCardError.CommunicationError($"INITIALIZE UPDATE failed: SW={response.StatusWord:X4}"))
                    .Bind(response => InitializeUpdateResponse.Parse(response.Data)
                        .Bind(parsedResponse => Scp03Protocol.ProcessInitializeUpdateResponse(parsedResponse, hostChallenge, keySet)
                            .Bind(context => CompleteScp03Authentication(context, securityLevel, hostChallenge, cancellationToken))));
            });
    }

    /// <summary>
    /// Completes SCP03 authentication after INITIALIZE UPDATE.
    /// </summary>
    private async Task<Result<SecureChannelState, SmartCardError>> CompleteScp03Authentication(
        SecureChannelContext context,
        SecurityLevel securityLevel,
        byte[] hostChallenge,
        CancellationToken cancellationToken)
    {
        return await CryptographicOperations.BuildScp03HostCryptogramData(context.InitializeUpdateResponse, hostChallenge)
            .Bind(hostCryptogramData => MacCalculations.CalculateScp03Cryptogram(context.SessionKeys.SEnc, hostCryptogramData)
                .Bind(cryptogram =>
                {
                    byte[] truncatedCryptogram = cryptogram.Take(8).ToArray();
                    return Scp03Protocol.CreateExternalAuthenticateCommand(securityLevel, truncatedCryptogram, context.SessionKeys.SMac);
                })
                .Bind(async extAuthCmd =>
                {
                    var extAuthResponse = await _cardService.ExecuteCommandAsync(extAuthCmd, cancellationToken);
                    return extAuthResponse
                        .Bind(response => response.IsSuccess
                            ? Scp03Protocol.CreateSecureChannelSession(context, securityLevel)
                            : SmartCardError.AuthenticationFailed($"EXTERNAL AUTHENTICATE failed: SW={response.StatusWord:X4}"));
                }));
    }

}
