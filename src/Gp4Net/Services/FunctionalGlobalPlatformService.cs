using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
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
    /// Functional implementation of IGlobalPlatformService using pure functions.
    /// Built alongside the existing service for gradual migration.
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

        /// <inheritdoc/>
        public async Task<Result<SelectResponse, SmartCardError>> SelectIsdAsync(
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Selecting Issuer Security Domain with auto-detection");

            // Pure function approach: create command
            var selectResult = CreateSelectIsdCommand();
            if (selectResult.IsFailure)
                return Result.Failure<SelectResponse, SmartCardError>(selectResult.Error);

            // Execute command
            var response = await _cardService.ExecuteCommandAsync(selectResult.Value, cancellationToken);
            
            // Process response with pure function
            return await response.Bind(r => ProcessSelectResponse(r))
                .Match(
                    onSuccess: async selectResp => await Task.FromResult(Result.Success<SelectResponse, SmartCardError>(selectResp)),
                    onFailure: async _ => await TryKnownIsdAids(cancellationToken));
        }

        /// <inheritdoc/>
        public async Task<Result<SecureChannelSession, SmartCardError>> EstablishSecureChannelAsync(
            KeySet keySet,
            SecurityLevel securityLevel = SecurityLevel.CMac,
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Establishing secure channel with security level: {SecurityLevel}", securityLevel);

            // Generate host challenge
            var hostChallenge = GenerateHostChallenge();
            
            // Create INITIALIZE UPDATE command
            var initUpdateResult = CreateInitializeUpdateCommand(keySet.KeyVersion, keySet.KeyId, hostChallenge);
            if (initUpdateResult.IsFailure)
                return Result.Failure<SecureChannelSession, SmartCardError>(initUpdateResult.Error);

            // Execute command
            var response = await _cardService.ExecuteCommandAsync(initUpdateResult.Value, cancellationToken);
            if (response.IsFailure)
                return Result.Failure<SecureChannelSession, SmartCardError>(response.Error);

            // Process response and establish secure channel
            return await EstablishSecureChannelFromResponse(response.Value, keySet, securityLevel, hostChallenge);
        }

        /// <inheritdoc/>
        public async Task<Result<ImmutableList<ApplicationInfo>, SmartCardError>> GetStatusAsync(
            StatusSubset subset = StatusSubset.IssuerSecurityDomain,
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Getting status for subset: {Subset}", subset);

            var commandResult = CreateGetStatusCommand(subset);
            if (commandResult.IsFailure)
                return Result.Failure<ImmutableList<ApplicationInfo>, SmartCardError>(commandResult.Error);

            var result = await _cardService.ExecuteCommandAsync(commandResult.Value, cancellationToken);

            return result.Bind(response => ProcessGetStatusResponse(response));
        }

        /// <inheritdoc/>
        public async Task<Result<InstallationResult, SmartCardError>> InstallCapFileAsync(
            byte[] capFileData,
            InstallOptions? options = null,
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Installing CAP file ({Length} bytes)", capFileData.Length);
            
            // Validate secure channel is established
            var session = _cardService.Context.Get<SecureChannelSession>(ContextKeys.SecureChannelSession);
            if (!session.HasValue)
            {
                return Result.Failure<InstallationResult, SmartCardError>(
                    SmartCardError.SecurityStatusNotSatisfied());
            }

            // Basic CAP file validation
            if (capFileData == null || capFileData.Length == 0)
            {
                return Result.Failure<InstallationResult, SmartCardError>(
                    SmartCardError.InvalidData("CAP file data is empty"));
            }

            // For now, return a not-implemented result with meaningful error
            // Full implementation would parse CAP file and send LOAD/INSTALL commands
            return await Task.FromResult(Result.Failure<InstallationResult, SmartCardError>(
                SmartCardError.Unsupported("CAP file installation requires LOAD and INSTALL command implementation")));
        }

        /// <inheritdoc/>
        public async Task<Result<bool, SmartCardError>> DeleteApplicationAsync(
            byte[] aid,
            bool deleteRelated = false,
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Deleting application with AID: {AID}", Convert.ToHexString(aid));

            var commandResult = CreateDeleteCommand(aid, deleteRelated);
            if (commandResult.IsFailure)
                return Result.Failure<bool, SmartCardError>(commandResult.Error);

            var response = await _cardService.ExecuteCommandAsync(commandResult.Value, cancellationToken);
            return response.Map(_ => true);
        }

        /// <inheritdoc/>
        public async Task<Result<bool, SmartCardError>> PutKeysAsync(
            KeySet keySet,
            byte keyVersion,
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Putting keys with version: {KeyVersion}", keyVersion);
            
            // Validate secure channel is established
            var session = _cardService.Context.Get<SecureChannelSession>(ContextKeys.SecureChannelSession);
            if (!session.HasValue)
            {
                return Result.Failure<bool, SmartCardError>(
                    SmartCardError.SecurityStatusNotSatisfied());
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
                return commandResult.Error;

            // Execute command
            var response = await _cardService.ExecuteCommandAsync(commandResult.Value, cancellationToken);
            return response.Map(r => r.IsSuccess);
        }

        /// <inheritdoc/>
        public async Task<Result<CplcData, SmartCardError>> GetCplcAsync(
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Getting CPLC data");

            var commandResult = CreateGetDataCommand(GetDataCommand.DataObjects.CardProductionLifeCycle);
            if (commandResult.IsFailure)
                return Result.Failure<CplcData, SmartCardError>(commandResult.Error);

            var response = await _cardService.ExecuteCommandAsync(commandResult.Value, cancellationToken);
            
            return response.Bind(r => ProcessCplcResponse(r));
        }

        /// <inheritdoc/>
        public async Task<Result<byte[], SmartCardError>> GetDataAsync(
            ushort tag,
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Getting data for tag: {Tag:X4}", tag);

            var commandResult = CreateGetDataCommand(tag);
            if (commandResult.IsFailure)
                return Result.Failure<byte[], SmartCardError>(commandResult.Error);

            var response = await _cardService.ExecuteCommandAsync(commandResult.Value, cancellationToken);
            
            return response.Map(r => r.Data);
        }

        /// <inheritdoc/>
        public async Task<Result<bool, SmartCardError>> SetLifecycleStateAsync(
            byte[] aid,
            LifecycleState state,
            CancellationToken cancellationToken = default)
        {
            _logger?.LogInformation("Setting lifecycle state for AID: {AID} to {State}", 
                Convert.ToHexString(aid), state);
            
            // Validate secure channel is established
            var session = _cardService.Context.Get<SecureChannelSession>(ContextKeys.SecureChannelSession);
            if (!session.HasValue)
            {
                return Result.Failure<bool, SmartCardError>(
                    SmartCardError.SecurityStatusNotSatisfied());
            }

            // Map lifecycle state to P1 value for SET STATUS command
            var p1 = state switch
            {
                LifecycleState.Installed => (byte)0x07,     // Make selectable
                LifecycleState.Selectable => (byte)0x07,    // Already selectable
                LifecycleState.Personalized => (byte)0x0F,  // Personalize
                LifecycleState.Locked => (byte)0x80,        // Lock
                LifecycleState.Terminated => (byte)0x00,    // Terminate
                _ => (byte)0x00
            };

            // Create SET STATUS command (0x80 0xF0 P1 P2 Lc AID)
            var command = new byte[5 + aid.Length];
            command[0] = 0x80; // CLA
            command[1] = 0xF0; // INS (SET STATUS)
            command[2] = p1;   // P1 (lifecycle state)
            command[3] = 0x00; // P2
            command[4] = (byte)aid.Length; // Lc
            Array.Copy(aid, 0, command, 5, aid.Length);

            // Execute command using raw command data
            // Since SET STATUS command is not yet implemented, return unsupported for now
            return await Task.FromResult(Result.Failure<bool, SmartCardError>(
                SmartCardError.Unsupported("SET STATUS command implementation not available")));
        }

        // Pure function implementations

        private static Result<SelectCommand, SmartCardError> CreateSelectIsdCommand()
        {
            return SelectCommand.CreateForIssuerSecurityDomain();
        }

        private static Result<SelectCommand, SmartCardError> CreateSelectCommand(byte[] aid)
        {
            return SelectCommand.Create(aid);
        }

        private static Result<SelectResponse, SmartCardError> ProcessSelectResponse(CommandResponse response)
        {
            if (!response.IsSuccess)
                return Result.Failure<SelectResponse, SmartCardError>(
                    SmartCardError.FromStatusWord(response.StatusWord));

            return SelectResponse.Parse(response.Data);
        }

        private static byte[] GenerateHostChallenge()
        {
            var challenge = new byte[8];
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(challenge);
            return challenge;
        }

        private static Result<InitializeUpdateCommand, SmartCardError> CreateInitializeUpdateCommand(
            byte keyVersion, byte keyId, byte[] hostChallenge)
        {
            return InitializeUpdateCommand.Create(keyVersion, keyId, hostChallenge);
        }

        private async Task<Result<SecureChannelSession, SmartCardError>> EstablishSecureChannelFromResponse(
            CommandResponse response,
            KeySet keySet,
            SecurityLevel securityLevel,
            byte[] hostChallenge)
        {
            try
            {
                // Parse INITIALIZE UPDATE response
                InitializeUpdateResponse initUpdateResponse;
                try
                {
                    initUpdateResponse = InitializeUpdateResponse.Parse(response.Data);
                }
                catch (Exception ex)
                {
                    return Result.Failure<SecureChannelSession, SmartCardError>(
                        SmartCardError.InvalidData($"Failed to parse INITIALIZE UPDATE response: {ex.Message}"));
                }

                // Get card channel and transport from context
                var channel = _cardService.Context.Get<ICardChannel>("CardChannel");
                var transport = _cardService.Context.Get<IApduTransport>("ApduTransport");
                
                if (!channel.HasValue || !transport.HasValue)
                {
                    return Result.Failure<SecureChannelSession, SmartCardError>(
                        SmartCardError.SecurityError("Missing card channel or transport for secure channel establishment"));
                }

                // Use the secure channel manager to establish the session
                var sessionResult = await _secureChannelManager.EstablishAsync(
                    channel.Value, 
                    transport.Value, 
                    keySet, 
                    securityLevel);

                if (sessionResult.IsFailure)
                {
                    return Result.Failure<SecureChannelSession, SmartCardError>(sessionResult.Error);
                }

                var session = sessionResult.Value;

                // Update service context with secure channel session
                var newService = _cardService.WithContextValue(ContextKeys.SecureChannelSession, session);

                return Result.Success<SecureChannelSession, SmartCardError>(session);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to establish secure channel");
                return Result.Failure<SecureChannelSession, SmartCardError>(
                    SmartCardError.SecurityError("Failed to establish secure channel", response.StatusWord));
            }
        }

        private static Result<GetStatusCommand, SmartCardError> CreateGetStatusCommand(StatusSubset subset)
        {
            // Convert between enums
            var domainSubset = (GetStatusCommand.StatusSubset)(byte)subset;
            return GetStatusCommand.Create(domainSubset);
        }

        private static Result<ImmutableList<ApplicationInfo>, SmartCardError> ProcessGetStatusResponse(
            CommandResponse response)
        {
            if (!response.IsSuccess)
                return Result.Failure<ImmutableList<ApplicationInfo>, SmartCardError>(
                    SmartCardError.FromStatusWord(response.StatusWord));

            var parseResult = GetStatusResponse.Parse(response.Data);
            return parseResult.Map(parsed => ConvertToApplicationInfos(parsed));
        }

        private static ImmutableList<ApplicationInfo> ConvertToApplicationInfos(GetStatusResponse response)
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

        private static Result<DeleteCommand, SmartCardError> CreateDeleteCommand(byte[] aid, bool deleteRelated)
        {
            return DeleteCommand.CreateForApplication(aid, deleteRelated);
        }

        private static Result<GetDataCommand, SmartCardError> CreateGetDataCommand(ushort tag)
        {
            return GetDataCommand.Create(tag);
        }

        private static Result<CplcData, SmartCardError> ProcessCplcResponse(CommandResponse response)
        {
            if (!response.IsSuccess)
                return Result.Failure<CplcData, SmartCardError>(
                    SmartCardError.FromStatusWord(response.StatusWord));

            // Extract the TLV value from the response
            var cplcBytes = ExtractTlvValue(response.Data, GetDataCommand.DataObjects.CardProductionLifeCycle);
            if (cplcBytes == null || cplcBytes.Length == 0)
            {
                return Result.Failure<CplcData, SmartCardError>(
                    SmartCardError.InvalidData("CPLC data not found in response"));
            }
            
            return CplcData.TryParse(cplcBytes);
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
                var selectResult = CreateSelectCommand(aid);
                
                if (selectResult.IsFailure)
                {
                    continue;
                }
                
                var response = await _cardService.ExecuteCommandAsync(selectResult.Value, cancellationToken);

                if (response.IsSuccess)
                {
                    _logger?.LogInformation("Successfully selected ISD with AID: {AID}", aidHex);
                    
                    // Update context with ISD AID
                    var newService = _cardService.WithContextValue(ContextKeys.IssuerSecurityDomainAid, aid);
                    
                    return ProcessSelectResponse(response.Value);
                }
            }

            return Result.Failure<SelectResponse, SmartCardError>(
                SmartCardError.CardError("No ISD found on card"));
        }

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
}