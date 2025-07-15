using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Core.Tlv;
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
    /// GlobalPlatform operations service implementation.
    /// </summary>
    public class GlobalPlatformService : IGlobalPlatformService
    {
        private readonly ISmartCardService _cardService;
        private readonly ISecureChannelManager _secureChannelManager;
        private readonly ILogger<GlobalPlatformService>? _logger;

        /// <summary>
        /// Initializes a new instance of the GlobalPlatformService class.
        /// </summary>
        public GlobalPlatformService(
            ISmartCardService cardService,
            ISecureChannelManager secureChannelManager,
            ILogger<GlobalPlatformService>? logger = null)
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
            var selectResult = SelectCommand.CreateForIssuerSecurityDomain();
            return await selectResult.MatchAsync<Result<SelectResponse, SmartCardError>>(
                async emptySelect =>
                {
                    var result = await _cardService.ExecuteCommandAsync(emptySelect, cancellationToken);
                    return await result.MatchAsync(
                        async success => await ProcessSelectResponse(success, emptySelect),
                        async failure => await TryKnownIsdAids(cancellationToken));
                },
                async error => await Task.FromResult(Result<SelectResponse, SmartCardError>.Fail(error)));
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
            var initUpdateResult = InitializeUpdateCommand.Create(keySet.KeyVersion, keySet.KeyId, hostChallenge);
            
            if (initUpdateResult.IsFailure)
            {
                return Result<SecureChannelSession, SmartCardError>.Fail(initUpdateResult.Error);
            }
            
            var initUpdate = initUpdateResult.Value;

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

            var commandResult = GetStatusCommand.Create((GetStatusCommand.StatusSubset)(byte)subset);
            if (commandResult.IsFailure)
                return Result<ImmutableList<ApplicationInfo>, SmartCardError>.Fail(commandResult.Error);

            var result = await _cardService.ExecuteCommandAsync(commandResult.Value, cancellationToken);

            return result.Bind(response => 
            {
                var parseResult = GetStatusResponse.Parse(response.Data);
                return parseResult.Map(parsed => ConvertToApplicationInfos(parsed));
            });
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
            var commandsResult = CreateLoadingCommands(capFile, capFileData, isdAid, options);
            if (commandsResult.IsFailure)
            {
                return Result<InstallationResult, SmartCardError>.Fail(commandsResult.Error);
            }

            // Execute commands
            return await ExecuteInstallationCommands(commandsResult.Value, capFile, cancellationToken);
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

            var createResult = DeleteCommand.CreateForApplication(aid, deleteRelated);
            return await createResult.BindAsync(async deleteCommand =>
            {
                var result = await _cardService.ExecuteCommandAsync(deleteCommand, cancellationToken);
                return result.Map(_ => Unit.Value);
            });
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
                    var encKeyResult = KeyDataBlock.CreateTripleDes2Key(scp02KeySet.EncKey);
                    if (encKeyResult.IsFailure)
                        return encKeyResult.Error;
                    keyDataBlocks.Add(encKeyResult.Value);

                    var macKeyResult = KeyDataBlock.CreateTripleDes2Key(scp02KeySet.MacKey);
                    if (macKeyResult.IsFailure)
                        return macKeyResult.Error;
                    keyDataBlocks.Add(macKeyResult.Value);

                    var dekKeyResult = KeyDataBlock.CreateTripleDes2Key(scp02KeySet.DekKey);
                    if (dekKeyResult.IsFailure)
                        return dekKeyResult.Error;
                    keyDataBlocks.Add(dekKeyResult.Value);
                }
                else if (keySet is Scp03KeySet scp03KeySet)
                {
                    // SCP03 uses AES keys
                    var encKeyResult = KeyDataBlock.CreateAes128Key(scp03KeySet.EncKey);
                    if (encKeyResult.IsFailure)
                        return encKeyResult.Error;
                    keyDataBlocks.Add(encKeyResult.Value);

                    var macKeyResult = KeyDataBlock.CreateAes128Key(scp03KeySet.MacKey);
                    if (macKeyResult.IsFailure)
                        return macKeyResult.Error;
                    keyDataBlocks.Add(macKeyResult.Value);

                    var dekKeyResult = KeyDataBlock.CreateAes128Key(scp03KeySet.DekKey);
                    if (dekKeyResult.IsFailure)
                        return dekKeyResult.Error;
                    keyDataBlocks.Add(dekKeyResult.Value);
                }
                else
                {
                    return Result<Unit, SmartCardError>.Fail(
                        SmartCardError.InvalidData($"Unsupported key set type: {keySet.GetType().Name}"));
                }

                // Create PUT KEY command
                var putKeyCommandResult = PutKeyCommand.Create(keyVersion, keyDataBlocks);
                if (putKeyCommandResult.IsFailure)
                {
                    return putKeyCommandResult.Error;
                }

                // Execute the command
                var result = await _cardService.ExecuteCommandAsync(putKeyCommandResult.Value, cancellationToken);
                
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
                var commandResult = GetDataCommand.Create(GetDataCommand.DataObjects.CardProductionLifeCycle);
                if (commandResult.IsFailure)
                {
                    return Result<CplcData, SmartCardError>.Fail(commandResult.Error);
                }
                
                var result = await _cardService.ExecuteCommandAsync(commandResult.Value, cancellationToken);
                
                return result.Map(response =>
                {
                    // Extract the TLV value from the response
                    var cplcBytes = ExtractTlvValue(response.Data, GetDataCommand.DataObjects.CardProductionLifeCycle);
                    if (cplcBytes == null || cplcBytes.Length == 0)
                    {
                        throw new InvalidOperationException("CPLC data not found in response");
                    }
                    return CplcData.Parse(cplcBytes);
                });
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
                var commandResult = GetDataCommand.Create(tag);
                if (commandResult.IsFailure)
                {
                    return Result<byte[], SmartCardError>.Fail(commandResult.Error);
                }
                
                var result = await _cardService.ExecuteCommandAsync(commandResult.Value, cancellationToken);
                
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
        public Task<Result<Unit, SmartCardError>> SetLifecycleStateAsync(
            byte[] aid,
            LifecycleState state,
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Setting lifecycle state for AID {AID} to {State}", Convert.ToHexString(aid), state);

            // TODO: Implement SET STATUS command for lifecycle state change
            // For now, return a not implemented error
            return Task.FromResult(Result<Unit, SmartCardError>.Fail(
                SmartCardError.Unsupported("SetLifecycleState is not yet implemented - requires SET STATUS command implementation")));
        }


        // Private helper methods

        private async Task<Result<SelectResponse, SmartCardError>> ProcessSelectResponse(
            CommandResponse response,
            SelectCommand command)
        {
            var parseResult = SelectResponse.Parse(response.Data);
            return await parseResult.MatchAsync<Result<SelectResponse, SmartCardError>>(
                async selectResponse =>
                {
                    if (selectResponse.Fci?.ApplicationAid != null)
                    {
                        var detectedAid = selectResponse.Fci.ApplicationAid;
                        _logger?.LogInformation("Auto-detected ISD: {AID}", Convert.ToHexString(detectedAid));
                        
                        // Update context with ISD AID
                        var newService = _cardService.WithContextValue(ContextKeys.IssuerSecurityDomainAid, detectedAid);
                        // Note: In a pure functional approach, we'd return the new service instance
                        
                        return await Task.FromResult(Result<SelectResponse, SmartCardError>.Ok(selectResponse));
                    }

                    return await Task.FromResult(Result<SelectResponse, SmartCardError>.Fail(
                        SmartCardError.InvalidResponse("No AID in SELECT response")));
                },
                async error => await Task.FromResult(Result<SelectResponse, SmartCardError>.Fail(error)));
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
                var selectResult = SelectCommand.Create(aid);
                
                if (selectResult.IsFailure)
                {
                    continue;
                }
                
                var selectCommand = selectResult.Value;
                var result = await _cardService.ExecuteCommandAsync(selectCommand, cancellationToken);

                if (result.IsSuccess)
                {
                    _logger?.LogInformation("Successfully selected ISD with AID: {AID}", aidHex);
                    
                    // Update context with ISD AID
                    var newService = _cardService.WithContextValue(ContextKeys.IssuerSecurityDomainAid, aid);
                    
                    return await result.MatchAsync<Result<SelectResponse, SmartCardError>>(
                        async response => 
                        {
                            var parseResult = SelectResponse.Parse(response.Data);
                            return await Task.FromResult(parseResult);
                        },
                        async error => await Task.FromResult(Result<SelectResponse, SmartCardError>.Fail(error)));
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

        private Result<ImmutableList<IApduCommand>, SmartCardError> CreateLoadingCommands(
            CapFileStructure capFile,
            byte[] capFileData,
            byte[]? isdAid,
            InstallOptions options)
        {
            var commands = new List<IApduCommand>();

            // INSTALL [for load]
            var installForLoadResult = InstallCommandBuilder.CreateForLoad(
                capFile.PackageAid,
                isdAid,
                hash: null,
                maxDataBlockSize: (ushort?)options.MaxLoadBlockSize,
                installToken: options.UseToken ? GenerateInstallToken() : null);
            
            if (installForLoadResult.IsFailure)
            {
                return Result<ImmutableList<IApduCommand>, SmartCardError>.Fail(installForLoadResult.Error);
            }
            commands.Add(installForLoadResult.Value);

            // LOAD commands
            var loadCommandsResult = LoadCommand.CreateFromCapFile(capFileData, options.MaxLoadBlockSize);
            if (loadCommandsResult.IsFailure)
            {
                return Result<ImmutableList<IApduCommand>, SmartCardError>.Fail(loadCommandsResult.Error);
            }
            commands.AddRange(loadCommandsResult.Value);

            // INSTALL [for install] commands
            if (options.InstallApplets && capFile.Applets.Any())
            {
                foreach (var applet in capFile.Applets)
                {
                    var installCommandResult = options.MakeSelectable
                        ? InstallCommandBuilder.CreateForInstallAndMakeSelectable(
                            capFile.PackageAid,
                            applet.Aid,
                            privileges: options.DefaultPrivileges)
                        : InstallCommandBuilder.CreateForInstall(
                            capFile.PackageAid,
                            applet.Aid,
                            privileges: options.DefaultPrivileges);

                    if (installCommandResult.IsFailure)
                    {
                        return Result<ImmutableList<IApduCommand>, SmartCardError>.Fail(installCommandResult.Error);
                    }
                    
                    commands.Add(installCommandResult.Value);
                }
            }

            return Result<ImmutableList<IApduCommand>, SmartCardError>.Ok(commands.ToImmutableList());
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

        /// <summary>
        /// Parses the response data from a GET STATUS command to extract application information.
        /// </summary>
        /// <param name="responseData">The raw response data from the GET STATUS command.</param>
        /// <returns>
        /// An immutable list of ApplicationInfo objects representing the applications found on the card.
        /// Returns an empty list if no applications are found or if the response data is invalid.
        /// </returns>
        /// <remarks>
        /// <para>This method implements parsing of GlobalPlatform GET STATUS response format per Card Specification v2.3.1:</para>
        /// <list type="bullet">
        /// <item><description><strong>Entry Format:</strong> Each application entry starts with tag E3 followed by length and data</description></item>
        /// <item><description><strong>TLV Structure:</strong> Within each entry, TLV elements provide AID, lifecycle state, and privileges</description></item>
        /// <item><description><strong>Two-byte Tags:</strong> Special handling for 9F70 (lifecycle state) tag</description></item>
        /// </list>
        /// 
        /// <para><strong>Supported TLV Tags:</strong></para>
        /// <list type="table">
        /// <listheader>
        /// <term>Tag</term>
        /// <description>Content</description>
        /// </listheader>
        /// <item><term>4F</term><description>Application AID</description></item>
        /// <item><term>84</term><description>Alternative AID tag</description></item>
        /// <item><term>9F70</term><description>Lifecycle state (2-byte tag)</description></item>
        /// <item><term>C5</term><description>Privileges byte</description></item>
        /// <item><term>CF</term><description>Executable Load File indicators</description></item>
        /// </list>
        /// 
        /// <para><strong>Application Type Detection:</strong></para>
        /// <para>Application types are determined based on privileges and lifecycle state:
        /// Security Domains have privilege 0x80, Executable Load Files have lifecycle bit 0x01.</para>
        /// </remarks>
        private ImmutableList<ApplicationInfo> ParseStatusResponse(byte[] responseData)
        {
            var applications = ImmutableList.CreateBuilder<ApplicationInfo>();
            
            if (responseData == null || responseData.Length == 0)
            {
                return applications.ToImmutable();
            }

            int offset = 0;
            
            // GET STATUS response format:
            // Each entry starts with tag E3 followed by length and data
            while (offset < responseData.Length)
            {
                // Check for E3 tag
                if (offset + 2 > responseData.Length || responseData[offset] != 0xE3)
                {
                    break;
                }
                offset++; // Skip E3 tag
                
                // Read length
                int entryLength = responseData[offset++];
                if (entryLength == 0x81 && offset < responseData.Length)
                {
                    // Extended length
                    entryLength = responseData[offset++];
                }
                
                if (offset + entryLength > responseData.Length)
                {
                    break;
                }
                
                // Parse the entry data
                var entryData = new byte[entryLength];
                Array.Copy(responseData, offset, entryData, 0, entryLength);
                offset += entryLength;
                
                // Parse the TLV structure within the entry
                var app = ParseApplicationEntry(entryData);
                if (app != null)
                {
                    applications.Add(app);
                }
            }
            
            return applications.ToImmutable();
        }

        /// <summary>
        /// Converts a GetStatusResponse to a list of ApplicationInfo objects.
        /// </summary>
        /// <param name="response">The parsed GET STATUS response.</param>
        /// <returns>A list of ApplicationInfo objects.</returns>
        private ImmutableList<ApplicationInfo> ConvertToApplicationInfos(GetStatusResponse response)
        {
            var applications = ImmutableList.CreateBuilder<ApplicationInfo>();
            
            foreach (var entry in response.Applications)
            {
                // Map lifecycle state from GetStatusResponse to domain model
                var lcState = entry.State switch
                {
                    ApplicationStatusEntry.LifecycleState.Installed => LifecycleState.Installed,
                    ApplicationStatusEntry.LifecycleState.Selectable => LifecycleState.Selectable,
                    ApplicationStatusEntry.LifecycleState.Personalized => LifecycleState.Personalized,
                    ApplicationStatusEntry.LifecycleState.Blocked => LifecycleState.Locked,
                    ApplicationStatusEntry.LifecycleState.Locked => LifecycleState.Locked,
                    _ => LifecycleState.Unknown
                };
                
                // Parse privileges from the first byte of privileges array
                var privList = ImmutableList.CreateBuilder<Privilege>();
                if (entry.Privileges.Length > 0)
                {
                    var privileges = entry.Privileges[0];
                    if ((privileges & 0x80) != 0) privList.Add(Privilege.SecurityDomain);
                    if ((privileges & 0x40) != 0) privList.Add(Privilege.DapVerification);
                    if ((privileges & 0x20) != 0) privList.Add(Privilege.DelegatedManagement);
                    if ((privileges & 0x10) != 0) privList.Add(Privilege.CardLock);
                    if ((privileges & 0x08) != 0) privList.Add(Privilege.CardTerminate);
                    if ((privileges & 0x04) != 0) privList.Add(Privilege.CardReset);
                    if ((privileges & 0x02) != 0) privList.Add(Privilege.CvmManagement);
                    if ((privileges & 0x01) != 0) privList.Add(Privilege.MandatedDapVerification);
                }
                
                // Determine application type based on privileges
                var appType = privList.Contains(Privilege.SecurityDomain) 
                    ? ApplicationType.IssuerSecurityDomain 
                    : ApplicationType.Application;
                
                applications.Add(new ApplicationInfo(
                    entry.Aid,
                    lcState,
                    privList.ToImmutable(),
                    appType));
            }
            
            return applications.ToImmutable();
        }

        /// <summary>
        /// Parses a single application entry from GET STATUS response data.
        /// </summary>
        /// <param name="entryData">The TLV data for a single application entry (content of an E3 tag).</param>
        /// <returns>
        /// An ApplicationInfo object if parsing succeeds, or null if the entry data is invalid or incomplete.
        /// </returns>
        /// <remarks>
        /// <para>This method handles the detailed parsing of application entry TLV structure:</para>
        /// <list type="bullet">
        /// <item><description><strong>AID Extraction:</strong> Looks for 4F or 84 tags containing the application AID</description></item>
        /// <item><description><strong>Lifecycle Parsing:</strong> Handles both single-byte and 9F70 two-byte lifecycle tags</description></item>
        /// <item><description><strong>Privilege Parsing:</strong> Converts privilege byte to individual privilege flags</description></item>
        /// <item><description><strong>Type Detection:</strong> Determines application type based on privileges and state</description></item>
        /// </list>
        /// 
        /// <para><strong>Error Handling:</strong></para>
        /// <para>The method is designed to be robust against malformed data. If any critical
        /// information (like AID) is missing, it returns null rather than throwing exceptions.
        /// This ensures that partial parsing failures don't prevent processing of other entries.</para>
        /// </remarks>
        private ApplicationInfo? ParseApplicationEntry(byte[] entryData)
        {
            try
            {
                int offset = 0;
                byte[]? aid = null;
                byte lifecycleState = 0;
                byte privileges = 0;
                ApplicationType appType = ApplicationType.Application;
                
                // Parse TLV elements within the entry
                while (offset < entryData.Length)
                {
                    if (offset + 2 > entryData.Length)
                        break;
                        
                    byte tag = entryData[offset++];
                    byte length = entryData[offset++];
                    
                    if (offset + length > entryData.Length)
                        break;
                    
                    switch (tag)
                    {
                        case 0x4F: // AID
                        case 0x84: // Alternative AID tag
                            aid = new byte[length];
                            Array.Copy(entryData, offset, aid, 0, length);
                            break;
                            
                        // Note: 0x9F70 is handled separately below as it's a 2-byte tag
                            
                        case 0xC5: // Privileges
                            if (length >= 1)
                                privileges = entryData[offset];
                            break;
                            
                        case 0xCF: // Executable Load File or Module indicators
                            // This helps determine the application type
                            if (length >= 1 && (entryData[offset] & 0x80) != 0)
                                appType = ApplicationType.ExecutableLoadFile;
                            break;
                    }
                    
                    offset += length;
                }
                
                // Handle two-byte tags (9F70 for lifecycle)
                if (aid != null && offset < entryData.Length)
                {
                    // Re-parse looking for 9F70
                    offset = 0;
                    while (offset + 3 < entryData.Length)
                    {
                        if (entryData[offset] == 0x9F && entryData[offset + 1] == 0x70)
                        {
                            offset += 2;
                            byte len = entryData[offset++];
                            if (offset + len <= entryData.Length && len >= 1)
                            {
                                lifecycleState = entryData[offset];
                            }
                            break;
                        }
                        offset++;
                    }
                }
                
                if (aid == null)
                    return null;
                
                // Determine application type based on lifecycle state and privileges
                if ((privileges & 0x80) != 0) // Security Domain
                {
                    appType = ApplicationType.IssuerSecurityDomain;
                }
                else if ((lifecycleState & 0x01) != 0) // Executable Load File
                {
                    appType = ApplicationType.ExecutableLoadFile;
                }
                
                // Parse privileges
                var privList = ImmutableList.CreateBuilder<Privilege>();
                if ((privileges & 0x80) != 0) privList.Add(Privilege.SecurityDomain);
                if ((privileges & 0x40) != 0) privList.Add(Privilege.DapVerification);
                if ((privileges & 0x20) != 0) privList.Add(Privilege.DelegatedManagement);
                if ((privileges & 0x10) != 0) privList.Add(Privilege.CardLock);
                if ((privileges & 0x08) != 0) privList.Add(Privilege.CardTerminate);
                if ((privileges & 0x04) != 0) privList.Add(Privilege.CardReset);
                if ((privileges & 0x02) != 0) privList.Add(Privilege.CvmManagement);
                if ((privileges & 0x01) != 0) privList.Add(Privilege.MandatedDapVerification);
                
                // Map lifecycle state
                var lcState = (lifecycleState & 0x0F) switch
                {
                    0x01 => LifecycleState.Loaded,
                    0x03 => LifecycleState.Installed,
                    0x07 => LifecycleState.Selectable,
                    0x0F => LifecycleState.Personalized,
                    0x7F => LifecycleState.Locked,
                    0xFF => LifecycleState.Terminated,
                    _ => LifecycleState.Unknown
                };
                
                return new ApplicationInfo(
                    aid,
                    lcState,
                    privList.ToImmutable(),
                    appType
                );
            }
            catch
            {
                return null;
            }
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

        /// <summary>
        /// Extracts the value portion from TLV (Tag-Length-Value) encoded data for a specific tag.
        /// Supports both single-byte and two-byte tags commonly used in GlobalPlatform responses.
        /// </summary>
        /// <param name="data">The TLV-encoded data to parse.</param>
        /// <param name="expectedTag">The tag to look for (single-byte: 0x00-0xFF, two-byte: 0x9F7F, etc.).</param>
        /// <returns>
        /// The value bytes for the specified tag, or null if the tag is not found or data is malformed.
        /// </returns>
        /// <remarks>
        /// <para>This method handles the complexity of TLV parsing in GlobalPlatform GET DATA responses:</para>
        /// <list type="bullet">
        /// <item><description><strong>Two-byte Tags:</strong> Special handling for tags like 9F7F (CPLC), 9F70 (lifecycle)</description></item>
        /// <item><description><strong>Length Encoding:</strong> Supports both short form (0x00-0x7F) and long form (0x81-0x84) lengths</description></item>
        /// <item><description><strong>Fallback Logic:</strong> If no TLV structure is found, attempts simple tag matching</description></item>
        /// <item><description><strong>Single Element:</strong> Returns content of single TLV element if no specific tag match</description></item>
        /// </list>
        /// 
        /// <para><strong>Common Use Cases:</strong></para>
        /// <list type="bullet">
        /// <item><description>Extracting CPLC data from 9F7F-tagged GET DATA responses</description></item>
        /// <item><description>Parsing Key Information Templates from E0-wrapped responses</description></item>
        /// <item><description>Handling card capabilities and other structured data</description></item>
        /// </list>
        /// </remarks>
        private static byte[]? ExtractTlvValue(byte[] data, ushort expectedTag)
        {
            if (data == null || data.Length < 2)
                return null;

            // For two-byte tags like 9F7F, we need to handle them specially
            if (expectedTag > 0xFF && data.Length >= 3)
            {
                byte firstByte = (byte)(expectedTag >> 8);
                byte secondByte = (byte)(expectedTag & 0xFF);
                
                if (data[0] == firstByte && data[1] == secondByte)
                {
                    // This is a two-byte tag
                    int offset = 2;
                    int length = ParseLength(data, ref offset);
                    
                    if (length >= 0 && offset + length <= data.Length)
                    {
                        byte[] content = new byte[length];
                        Array.Copy(data, offset, content, 0, length);
                        return content;
                    }
                }
            }

            // Try single-byte tag parsing
            var elements = SimpleTlvParser.Enumerate(data).ToList();
            if (elements.Count == 0)
                return data; // Not TLV format, return as-is

            // Look for the expected tag (only works for single-byte tags)
            if (expectedTag <= 0xFF)
            {
                var element = elements.FirstOrDefault(e => e.Tag == (byte)expectedTag);
                if (element.Content != null)
                    return element.Content;
            }

            // If we have a single TLV element and no specific tag match,
            // return its content (common for GET DATA responses)
            if (elements.Count == 1)
                return elements[0].Content;

            return null;
        }

        private static int ParseLength(byte[] data, ref int offset)
        {
            if (offset >= data.Length)
                return -1;

            byte lenByte = data[offset++];

            if ((lenByte & 0x80) == 0)
            {
                // Short form
                return lenByte;
            }
            else
            {
                // Long form
                int lenLength = lenByte & 0x7F;

                if (lenLength == 0 || lenLength > 4 || offset + lenLength > data.Length)
                {
                    return -1; // invalid or unsupported
                }

                int contentLength = 0;
                for (int i = 0; i < lenLength; i++)
                {
                    contentLength = (contentLength << 8) | data[offset++];
                }

                return contentLength;
            }
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