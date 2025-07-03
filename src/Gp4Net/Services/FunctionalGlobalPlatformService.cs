using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.CapFile;
using Gp4Net.Domain.CardInfo;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using Gp4Net.Domain.Keys;
using Gp4Net.Domain.Protocol;
using Gp4Net.Pipeline;
using Microsoft.Extensions.Logging;

namespace Gp4Net.Services
{
    /// <summary>
    /// Functional implementation of GlobalPlatform operations.
    /// </summary>
    public class FunctionalGlobalPlatformService : IGlobalPlatformService
    {
        private readonly ISmartCardService _cardService;
        private readonly ISecureChannelManager _secureChannelManager;
        private readonly ILogger<FunctionalGlobalPlatformService>? _logger;

        /// <summary>
        /// Initializes a new instance of the FunctionalGlobalPlatformService class.
        /// </summary>
        public FunctionalGlobalPlatformService(
            ISmartCardService cardService,
            ISecureChannelManager secureChannelManager,
            ILogger<FunctionalGlobalPlatformService>? logger = null)
        {
            _cardService = cardService ?? throw new ArgumentNullException(nameof(cardService));
            _secureChannelManager = secureChannelManager ?? throw new ArgumentNullException(nameof(secureChannelManager));
            _logger = logger;
        }

        /// <summary>
        /// Selects the Issuer Security Domain (ISD).
        /// </summary>
        public async Task<Result<SelectResponse, SmartCardError>> SelectIsdAsync(
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Selecting Issuer Security Domain with auto-detection");

            // First try empty SELECT for auto-detection
            var emptySelect = SelectCommand.CreateEmptySelect();
            var result = await _cardService.ExecuteCommandAsync(emptySelect, cancellationToken);

            return await result.MatchAsync(
                async success => await ProcessSelectResponse(success, emptySelect),
                async failure => await TryKnownIsdAids(cancellationToken));
        }

        /// <summary>
        /// Establishes a secure channel with the card.
        /// </summary>
        public async Task<Result<SecureChannelSession, SmartCardError>> EstablishSecureChannelAsync(
            KeySet keySet,
            SecurityLevel securityLevel = SecurityLevel.CMac,
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Establishing secure channel with security level: {SecurityLevel}", securityLevel);

            // Initialize Update command
            var hostChallenge = GenerateHostChallenge();
            var initUpdate = new InitializeUpdateCommand(keySet.KeyVersion, keySet.KeyId, hostChallenge);

            var result = await _cardService.ExecuteCommandAsync(initUpdate, cancellationToken);

            return await result.MatchAsync(
                async success => await EstablishSecureChannelFromResponse(success, keySet, securityLevel),
                failure => Task.FromResult(Result<SecureChannelSession, SmartCardError>.Fail(failure)));
        }

        /// <summary>
        /// Gets the status of applications on the card.
        /// </summary>
        public async Task<Result<ImmutableList<ApplicationInfo>, SmartCardError>> GetStatusAsync(
            StatusSubset subset = StatusSubset.IssuerSecurityDomain,
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Getting status for subset: {Subset}", subset);

            var getStatus = new GetStatusCommand((GetStatusCommand.StatusSubset)(byte)subset);
            var result = await _cardService.ExecuteCommandAsync(getStatus, cancellationToken);

            return result.Map(response => ParseStatusResponse(response.Data));
        }

        /// <summary>
        /// Installs a CAP file on the card.
        /// </summary>
        public async Task<Result<InstallationResult, SmartCardError>> InstallCapFileAsync(
            byte[] capFileData,
            InstallOptions? options = null,
            CancellationToken cancellationToken = default)
        {
            options ??= InstallOptions.Default;
            _logger?.LogInformation("Installing CAP file ({Length} bytes)", capFileData.Length);

            // Validate CAP file
            var validationResult = ValidateCapFile(capFileData);
            if (validationResult.IsFailure)
                return Result<InstallationResult, SmartCardError>.Fail(validationResult.Error);

            var capFile = validationResult.Value;

            // Get ISD AID from context
            var isdAid = _cardService.Context.Get<byte[]>(ContextKeys.IssuerSecurityDomainAid);
            
            // Create loading commands
            var commands = CreateLoadingCommands(capFile, capFileData, isdAid, options);

            // Execute commands
            return await ExecuteInstallationCommands(commands, capFile, cancellationToken);
        }

        /// <summary>
        /// Deletes an application from the card.
        /// </summary>
        public async Task<Result<Unit, SmartCardError>> DeleteApplicationAsync(
            byte[] aid,
            bool deleteRelated = false,
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Deleting application: {AID}", Convert.ToHexString(aid));

            var deleteCommand = DeleteCommand.CreateForApplication(aid, deleteRelated);
            var result = await _cardService.ExecuteCommandAsync(deleteCommand, cancellationToken);

            return result.Map(_ => Unit.Value);
        }

        /// <summary>
        /// Performs a PUT KEY operation to change card keys.
        /// </summary>
        public async Task<Result<Unit, SmartCardError>> PutKeysAsync(
            KeySet keySet,
            byte keyVersion,
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Performing PUT KEY operation with key version: {KeyVersion}", keyVersion);

            try
            {
                // Create key data blocks based on the key set type
                var keyDataBlocks = new List<KeyDataBlock>();
                
                if (keySet is Scp02KeySet scp02KeySet)
                {
                    // SCP02 uses 3DES keys
                    keyDataBlocks.Add(KeyDataBlock.CreateTripleDes2Key(scp02KeySet.EncKey)); // ENC key
                    keyDataBlocks.Add(KeyDataBlock.CreateTripleDes2Key(scp02KeySet.MacKey)); // MAC key  
                    keyDataBlocks.Add(KeyDataBlock.CreateTripleDes2Key(scp02KeySet.DekKey)); // DEK key
                }
                else if (keySet is Scp03KeySet scp03KeySet)
                {
                    // SCP03 uses AES keys
                    keyDataBlocks.Add(KeyDataBlock.CreateAes128Key(scp03KeySet.EncKey)); // ENC key
                    keyDataBlocks.Add(KeyDataBlock.CreateAes128Key(scp03KeySet.MacKey)); // MAC key
                    keyDataBlocks.Add(KeyDataBlock.CreateAes128Key(scp03KeySet.DekKey)); // DEK key
                }
                else
                {
                    return Result<Unit, SmartCardError>.Fail(
                        SmartCardError.InvalidData($"Unsupported key set type: {keySet.GetType().Name}"));
                }

                // Create PUT KEY command
                var putKeyCommand = new PutKeyCommand(
                    PutKeyCommand.KeyUsageQualifier.MultipleKeys,
                    PutKeyCommand.KeyEncryptionKeyIdentifier.None, // Plain text for now
                    keyDataBlocks
                );

                // Execute the command
                var result = await _cardService.ExecuteCommandAsync(putKeyCommand, cancellationToken);
                
                return result.Map(_ => Unit.Value);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to perform PUT KEY operation");
                return Result<Unit, SmartCardError>.Fail(
                    SmartCardError.CommunicationError("PUT KEY operation failed", ex));
            }
        }

        /// <summary>
        /// Gets the Card Production Life Cycle (CPLC) data from the card.
        /// </summary>
        public async Task<Result<CplcData, SmartCardError>> GetCplcAsync(
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Getting CPLC data from card");

            try
            {
                // GET DATA for CPLC (tag 9F7F)
                var getDataCommand = new GetDataCommand(GetDataCommand.DataObjects.CardProductionLifeCycle);
                var result = await _cardService.ExecuteCommandAsync(getDataCommand, cancellationToken);
                
                return result.Map(response => CplcData.Parse(response.Data));
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to get CPLC data");
                return Result<CplcData, SmartCardError>.Fail(
                    SmartCardError.CommunicationError("Failed to get CPLC data", ex));
            }
        }

        /// <summary>
        /// Gets data from the card using GET DATA command.
        /// </summary>
        public async Task<Result<byte[], SmartCardError>> GetDataAsync(
            ushort tag,
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Getting data for tag: {Tag:X4}", tag);

            try
            {
                var getDataCommand = new GetDataCommand(tag);
                var result = await _cardService.ExecuteCommandAsync(getDataCommand, cancellationToken);
                
                return result.Map(response => response.Data);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to get data for tag {Tag:X4}", tag);
                return Result<byte[], SmartCardError>.Fail(
                    SmartCardError.CommunicationError($"Failed to get data for tag {tag:X4}", ex));
            }
        }

        /// <summary>
        /// Sets the lifecycle state of an application.
        /// </summary>
        public async Task<Result<Unit, SmartCardError>> SetLifecycleStateAsync(
            byte[] aid,
            LifecycleState state,
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Setting lifecycle state for AID {AID} to {State}", Convert.ToHexString(aid), state);

            // TODO: Implement SET STATUS command for lifecycle state change
            // For now, return a not implemented error
            return Result<Unit, SmartCardError>.Fail(
                SmartCardError.Unsupported("SetLifecycleState is not yet implemented - requires SET STATUS command implementation"));
        }

        // Private helper methods

        private async Task<Result<SelectResponse, SmartCardError>> ProcessSelectResponse(
            CommandResponse response,
            SelectCommand command)
        {
            var selectResponse = SelectResponse.Parse(response.Data);

            if (selectResponse.Fci?.ApplicationAid != null)
            {
                var detectedAid = selectResponse.Fci.ApplicationAid;
                _logger?.LogInformation("Auto-detected ISD: {AID}", Convert.ToHexString(detectedAid));
                
                // Update context with ISD AID
                var newService = _cardService.WithContextValue(ContextKeys.IssuerSecurityDomainAid, detectedAid);
                // Note: In a pure functional approach, we'd return the new service instance
                
                return Result<SelectResponse, SmartCardError>.Ok(selectResponse);
            }

            return Result<SelectResponse, SmartCardError>.Fail(
                SmartCardError.InvalidResponse("No AID in SELECT response"));
        }

        private async Task<Result<SelectResponse, SmartCardError>> TryKnownIsdAids(
            CancellationToken cancellationToken)
        {
            var knownIsdAids = new[]
            {
                "A000000003000000", // Standard GP ISD
                "A000000151000000", // Common alternative ISD
                "A000000018434D00", // Another common ISD variant
            };

            foreach (var aidHex in knownIsdAids)
            {
                var aid = Convert.FromHexString(aidHex);
                var selectCommand = new SelectCommand(aid);
                var result = await _cardService.ExecuteCommandAsync(selectCommand, cancellationToken);

                if (result.IsSuccess)
                {
                    _logger?.LogInformation("Successfully selected ISD with AID: {AID}", aidHex);
                    
                    // Update context with ISD AID
                    var newService = _cardService.WithContextValue(ContextKeys.IssuerSecurityDomainAid, aid);
                    
                    return result.Map(response => SelectResponse.Parse(response.Data));
                }
            }

            return Result<SelectResponse, SmartCardError>.Fail(
                SmartCardError.CardError("No ISD found on card"));
        }

        private async Task<Result<SecureChannelSession, SmartCardError>> EstablishSecureChannelFromResponse(
            CommandResponse response,
            KeySet keySet,
            SecurityLevel securityLevel)
        {
            try
            {
                // Get card channel and transport from context
                var channel = _cardService.Context.Get<ICardChannel>("CardChannel");
                var transport = _cardService.Context.Get<IApduTransport>("ApduTransport");
                
                if (channel == null || transport == null)
                {
                    return Result<SecureChannelSession, SmartCardError>.Fail(
                        SmartCardError.SecurityError("Missing card channel or transport for secure channel establishment"));
                }

                // Use the secure channel manager to establish the session
                var session = await _secureChannelManager.EstablishAsync(
                    channel, 
                    transport, 
                    keySet, 
                    securityLevel);

                // Update service context with secure channel session
                var newService = _cardService.WithContextValue(ContextKeys.SecureChannelSession, session);

                return Result<SecureChannelSession, SmartCardError>.Ok(session);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to establish secure channel");
                return Result<SecureChannelSession, SmartCardError>.Fail(
                    SmartCardError.SecurityError("Failed to establish secure channel", response.StatusWord));
            }
        }

        // SecurityLevel conversion no longer needed - using single enum

        private Result<CapFileStructure, SmartCardError> ValidateCapFile(byte[] capFileData)
        {
            try
            {
                var validationResult = CapFileLoadingWorkflow.ValidateCapFile(capFileData);
                if (!validationResult.IsValid)
                {
                    return Result<CapFileStructure, SmartCardError>.Fail(
                        SmartCardError.InvalidData($"Invalid CAP file: {validationResult.ErrorMessage}"));
                }

                return Result<CapFileStructure, SmartCardError>.Ok(validationResult.CapFile!);
            }
            catch (Exception ex)
            {
                return Result<CapFileStructure, SmartCardError>.Fail(
                    SmartCardError.InvalidData($"Failed to parse CAP file: {ex.Message}"));
            }
        }

        private ImmutableList<IApduCommand> CreateLoadingCommands(
            CapFileStructure capFile,
            byte[] capFileData,
            byte[]? isdAid,
            InstallOptions options)
        {
            var commands = new List<IApduCommand>();

            // INSTALL [for load]
            var installForLoad = InstallCommandBuilder.CreateForLoad(
                capFile.PackageAid,
                isdAid,
                hash: null,
                loadParameters: null,
                installToken: options.UseToken ? GenerateInstallToken() : null);
            commands.Add(installForLoad);

            // LOAD commands
            var loadCommands = LoadCommand.CreateFromCapFile(capFileData, options.MaxLoadBlockSize);
            commands.AddRange(loadCommands);

            // INSTALL [for install] commands
            if (options.InstallApplets && capFile.Applets.Any())
            {
                foreach (var applet in capFile.Applets)
                {
                    var installCommand = options.MakeSelectable
                        ? InstallCommandBuilder.CreateForInstallAndMakeSelectable(
                            capFile.PackageAid,
                            applet.Aid,
                            privileges: options.DefaultPrivileges)
                        : InstallCommandBuilder.CreateForInstall(
                            capFile.PackageAid,
                            applet.Aid,
                            privileges: options.DefaultPrivileges);

                    commands.Add(installCommand);
                }
            }

            return commands.ToImmutableList();
        }

        private async Task<Result<InstallationResult, SmartCardError>> ExecuteInstallationCommands(
            ImmutableList<IApduCommand> commands,
            CapFileStructure capFile,
            CancellationToken cancellationToken)
        {
            var installedApplets = new List<byte[]>();
            var executedCommands = 0;

            foreach (var command in commands)
            {
                var result = await _cardService.ExecuteCommandAsync(command, cancellationToken);

                if (result.IsFailure)
                {
                    return Result<InstallationResult, SmartCardError>.Fail(
                        result.Error.WithContext("Command", command.GetType().Name)
                                    .WithContext("ExecutedCommands", executedCommands));
                }

                executedCommands++;

                // Track installed applets
                if (command is InstallCommand.InstallForInstallCommand installCmd)
                {
                    installedApplets.Add(installCmd.AppletAid.ToArray());
                }
            }

            var installResult = new InstallationResult(
                capFile.PackageAid,
                installedApplets.ToImmutableList(),
                executedCommands);

            return Result<InstallationResult, SmartCardError>.Ok(installResult);
        }

        private ImmutableList<ApplicationInfo> ParseStatusResponse(byte[] responseData)
        {
            // TODO: Implement proper TLV parsing of GET STATUS response
            // For now, return empty list
            return ImmutableList<ApplicationInfo>.Empty;
        }

        private static byte[] GenerateHostChallenge()
        {
            var challenge = new byte[8];
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(challenge);
            return challenge;
        }

        private static byte[]? GenerateInstallToken()
        {
            // TODO: Implement proper token generation if needed
            return null;
        }
    }

    /// <summary>
    /// Options for CAP file installation.
    /// </summary>
    public record InstallOptions(
        bool InstallApplets = true,
        bool MakeSelectable = true,
        int MaxLoadBlockSize = 245,
        bool UseToken = false,
        byte[]? DefaultPrivileges = null)
    {
        /// <summary>
        /// Default installation options.
        /// </summary>
        public static InstallOptions Default { get; } = new();
    }

    /// <summary>
    /// Result of a CAP file installation.
    /// </summary>
    // InstallationResult moved to Domain.Results for consolidation

    /// <summary>
    /// Status subset options for GET STATUS command.
    /// </summary>
    public enum StatusSubset : byte
    {
        /// <summary>
        /// Issuer Security Domain only.
        /// </summary>
        IssuerSecurityDomain = 0x80,

        /// <summary>
        /// Applications and supplementary security domains.
        /// </summary>
        Applications = 0x40,

        /// <summary>
        /// Executable load files.
        /// </summary>
        ExecutableLoadFiles = 0x20,

        /// <summary>
        /// Executable load files and their executable modules.
        /// </summary>
        ExecutableModules = 0x10
    }


    /// <summary>
    /// Unit type for operations with no return value.
    /// </summary>
    public readonly struct Unit
    {
        /// <summary>
        /// The single value of Unit type.
        /// </summary>
        public static Unit Value { get; } = new();
    }
}