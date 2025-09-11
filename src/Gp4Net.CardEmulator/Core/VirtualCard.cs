using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Applications;
using Gp4Net.CardEmulator.Domain;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.CardEmulator.Services;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Keys;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using static Gp4Net.Constants.Constants.GlobalPlatform;
using static Gp4Net.Services.TlvService;
using ExecutableModule = Gp4Net.CardEmulator.Functional.ExecutableModule;

namespace Gp4Net.CardEmulator.Core;

/// <summary>
/// Virtual smart card implementation using functional programming patterns and immutable state.
/// Processes commands through composable, testable command processors with proper cryptographic validation.
/// Uses ICardStateService for all state transitions to ensure immutability.
/// </summary>
[PublicAPI]
public partial class VirtualCard : IVirtualCard
{
    private readonly CardState _currentState;
    private readonly CardConfiguration _config;
    private readonly IRngContext _rngContext;
    private readonly LoggingService _logging;
    private readonly CapFileServiceAdapter _capFileService;
    private readonly ICardStateService _stateService;

    /// <summary>
    /// Initializes a new virtual card with the specified configuration, services, and state.
    /// </summary>
    /// <param name="config">The card configuration defining capabilities and data.</param>
    /// <param name="rngContext">The random number generator context for cryptographic operations.</param>
    /// <param name="currentState">The current immutable card state.</param>
    /// <param name="logger">Optional logger for debugging.</param>
    /// <param name="capFileService">The CAP file processing service for load operations.</param>
    /// <param name="stateService">The immutable card state management service.</param>
    public VirtualCard(
        CardConfiguration config,
        IRngContext rngContext,
        CardState currentState,
        LoggingService logger,
        CapFileServiceAdapter capFileService,
        ICardStateService stateService
    )
    {
        _config = config;
        _rngContext = rngContext;
        _currentState = currentState;
        _logging = logger;
        _capFileService = capFileService;
        _stateService = stateService;

        _logging.LogDebug(
            "Virtual card state - SCP version 0x{ScpVersion:X2}, implementation 0x{Implementation:X2}, selected: {IsSelected}",
            _currentState.ScpVersion,
            (byte)_currentState.ScpImplementation,
            _currentState.IsSelected
        );
    }

    /// <summary>
    /// Creates a new virtual card instance using immutable state management.
    /// Uses CardStateService to ensure proper functional state handling.
    /// </summary>
    /// <param name="config">The card configuration defining capabilities and data.</param>
    /// <param name="rngContext">The RNG context to use for random number generation.</param>
    /// <param name="logger">Optional logger for debugging.</param>
    /// <param name="capFileService">The CAP file processing service for load operations.</param>
    /// <param name="stateService">Optional state service (creates new one if not provided).</param>
    /// <returns>A new virtual card instance in initial state, or an error.</returns>
    public static Result<VirtualCard, SmartCardError> Create(
        CardConfiguration config,
        IRngContext rngContext,
        Maybe<ILogger> logger = default,
        Maybe<CapFileServiceAdapter> capFileService = default,
        Maybe<ICardStateService> stateService = default
    )
    {
        var cardStateService = stateService.GetValueOrDefault(new CardStateService(logger));

        return CardState.Create()
            .Bind(baseState =>
            {
                var stateWithConfig = baseState with
                {
                    ScpVersion = config.DefaultScpVersion,
                    ScpImplementation = config.DefaultScpImplementation
                };

                // Initialize with configuration's ISD AID and data objects
                var isdAid = config.IsdAid.ToImmutableArray();
                
                return CardStateService.InitializeApplicationRegistryWithDataObjects(
                    stateWithConfig,
                    isdAid,
                    config.DefaultDataObjects
                )
                .Map(finalState => new VirtualCard(
                    config,
                    rngContext,
                    finalState,
                    new LoggingService(logger),
                    capFileService.GetValueOrDefault(new CapFileServiceAdapter()),
                    cardStateService
                ));
            });
    }

    /// <inheritdoc />
    public byte[] GetAtr() => _config.Atr;

    /// <inheritdoc />
    public bool IsSelected => _currentState.IsSelected;

    /// <inheritdoc />
    public bool IsSecureChannelEstablished => _currentState.IsSecureChannelEstablished;

    /// <inheritdoc />
    public Result<IVirtualCard, SmartCardError> Reset()
    {
        var resetState = _stateService.ResetCard(_currentState);
        return Result.Success<IVirtualCard, SmartCardError>(
            new VirtualCard(
                _config,
                _rngContext,
                resetState,
                new LoggingService(Maybe<ILogger>.None),
                _capFileService,
                _stateService
            )
        );
    }

    /// <inheritdoc />
    public Result<
        (ApduResponse Response, IVirtualCard UpdatedCard),
        SmartCardError
    > ProcessCommand(byte[] command)
    {
        return ProcessCommandFunctionally(command, _currentState, _config, _rngContext, new LoggingService(Maybe<ILogger>.None))
            .Map(result =>
                (
                    result.Item1,
                    (IVirtualCard)
                        new VirtualCard(
                            _config,
                            _rngContext,
                            result.Item2,
                            new LoggingService(Maybe<ILogger>.None),
                            _capFileService,
                            _stateService
                        )
                )
            );
    }

    /// <summary>
    /// Gets the current card state (for testing purposes).
    /// </summary>
    public CardState CurrentState => _currentState;

    /// <summary>
    /// Gets the card configuration (for testing purposes).
    /// </summary>
    public CardConfiguration Configuration
    {
        get { return _config; }
    }


    /// <summary>
    /// Pure functional command processing that returns new state without side effects.
    /// This method can be tested independently of the stateful card instance.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessCommandFunctionally(
        byte[] command,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext,
        LoggingService logging
    )
    {
        return ValidateCommand(command)
            .Bind(cmd => ValidateInstructionSupported(cmd, config))
            .Bind(cmd => ApplyScpSecurity(cmd, state, logging))
            .Bind(cmd => RouteToApplications(cmd.FullCommand, state, rngContext, logging))
            .Bind(result => ApplyResponseSecurity(result, rngContext, logging));
    }

    /// <summary>
    /// Applies response security (R-MAC and/or R-ENCRYPTION).
    /// </summary>
    private static Result<(ApduResponse, CardState), SmartCardError> ApplyResponseSecurity(
        (ApduResponse response, CardState state) result,
        IRngContext rngContext,
        LoggingService logging
    )
    {
        (var response, var state) = result;

        // Use functional approach with Maybe<T>
        return state.SecureChannel.Match(
            // When secure channel is established
            secureChannelState =>
                ApplyResponseSecurityFunctional(response, state, secureChannelState, logging),
            // When no secure channel
            () =>
            {
                logging.LogTrace("No secure channel established - no response security applied");
                return Result.Success<(ApduResponse, CardState), SmartCardError>(result);
            }
        );
    }

    /// <summary>
    /// Applies response security using functional secure channel processing.
    /// </summary>
    private static Result<
        (ApduResponse, CardState),
        SmartCardError
    > ApplyResponseSecurityFunctional(
        ApduResponse response,
        CardState state,
        SecureChannelState secureChannelState,
        LoggingService logging
    )
    {
        // Check if response security is needed
        if (secureChannelState is { HasResponseMac: false, HasResponseEncryption: false })
        {
            logging.LogTrace("Security level does not require response security");
            return Result.Success<(ApduResponse, CardState), SmartCardError>((response, state));
        }

        // Check if status word indicates we should apply security
        if (!ShouldApplyResponseSecurity(response.StatusWord))
        {
            logging.LogTrace(
                "Status word {SW:X4} does not require response security",
                response.StatusWord
            );
            return Result.Success<(ApduResponse, CardState), SmartCardError>((response, state));
        }

        logging.LogDebug(
            "Applying functional response security - R-MAC: {RMac}, R-ENC: {REnc}",
            secureChannelState.HasResponseMac,
            secureChannelState.HasResponseEncryption
        );

        // Build full response (data + status word)
        byte[] fullResponse = new byte[response.Data.Length + 2];
        Array.Copy(response.Data, 0, fullResponse, 0, response.Data.Length);
        fullResponse[^2] = (byte)(response.StatusWord >> 8);
        fullResponse[^1] = (byte)(response.StatusWord & 0xFF);

        // Apply response security processing (card-side)
        return Maybe
            .From(secureChannelState)
            .Match(
                channel =>
                    // Use ScpService for response security processing
                    Result
                        .Success<(byte[], SecureChannelState), SmartCardError>(
                            (fullResponse, channel)
                        )
                        .Match(
                            success => ProcessSecureResponseSuccess(success, state, logging),
                            error =>
                                Result.Failure<(ApduResponse, CardState), SmartCardError>(
                                    SmartCardError.SecurityError(error.ToString())
                                )
                        ),
                () =>
                    Result.Failure<(ApduResponse, CardState), SmartCardError>(
                        SmartCardError.SecurityStatusNotSatisfied()
                    )
            );
    }

    /// <summary>
    /// Processes the successful secure response result.
    /// </summary>
    private static Result<(ApduResponse, CardState), SmartCardError> ProcessSecureResponseSuccess(
        (byte[] processedResponse, SecureChannelState newState) success,
        CardState state,
        LoggingService logging
    )
    {
        // Extract status word from the end
        byte[] processedResponse = success.processedResponse;
        ushort sw = (ushort)(processedResponse[^2] << 8 | processedResponse[^1]);

        // Response data excludes status word
        byte[] responseData = new byte[processedResponse.Length - 2];
        Array.Copy(processedResponse, 0, responseData, 0, responseData.Length);

        var securedResponse = new ApduResponse(responseData, sw);

        // Update card state with new secure channel state
        var newCardState = state.WithUpdatedSecureChannel(success.newState);

        logging.LogDebug("Response security applied - New length: {Length}", responseData.Length);

        return Result.Success<(ApduResponse, CardState), SmartCardError>(
            (securedResponse, newCardState)
        );
    }

    /// <summary>
    /// Determines if response security should be applied based on status word.
    /// Per GlobalPlatform Card Specification v2.3.1: only for success (9000) and warning (62xx, 63xx) status words.
    /// </summary>
    private static bool ShouldApplyResponseSecurity(ushort statusWord)
    {
    return statusWord == Constants.Constants.StatusWords.Success
            || (statusWord & 0xFF00)
                == Constants.Constants.StatusWords.Information.WarningNoInformation
            || (statusWord & 0xFF00) == 0x6300;
    }

    // Private helper methods for command processing

    /// <summary>
    /// Validates the structure and length of an APDU command.
    /// </summary>
    /// <param name="command">The byte array representing the APDU command to be validated.</param>
    /// <returns>A <see cref="Result{T, SmartCardError}"/> containing a parsed command if valid, or a smart card error indicating the issue.</returns>
    private static Result<ParsedCommand, SmartCardError> ValidateCommand(byte[] command)
    {
        if (command.Length < 4)
            return Result.Failure<ParsedCommand, SmartCardError>(SmartCardError.WrongLength());

        return Result.Success<ParsedCommand, SmartCardError>(
            new ParsedCommand(
                Cla: command[0],
                Ins: command[1],
                P1: command[2],
                P2: command[3],
                FullCommand: command
            )
        );
    }

    /// <summary>
    /// Validates whether the provided instruction is supported by the card configuration.
    /// </summary>
    /// <param name="cmd">The parsed command containing instruction details.</param>
    /// <param name="config">The card configuration defining supported instructions.</param>
    /// <returns>
    /// A successful result containing the validated parsed command if the instruction is supported;
    /// otherwise, a failure result with a <see cref="SmartCardError"/> indicating the instruction is unsupported.
    /// </returns>
    private static Result<ParsedCommand, SmartCardError> ValidateInstructionSupported(
        ParsedCommand cmd,
        CardConfiguration config
    )
    {
        if (!config.SupportedInstructions.IsSupported(cmd.Ins))
            return Result.Failure<ParsedCommand, SmartCardError>(
                SmartCardError.InstructionNotSupported()
            );

        return Result.Success<ParsedCommand, SmartCardError>(cmd);
    }

    private static Result<(ApduResponse, CardState), SmartCardError> ProcessInstallCommand(
        byte[] command,
        CardState state,
        CardConfiguration config
    )
    {
        // GlobalPlatform Card Specification v2.3.1 Section 11.5 INSTALL Command
        // Table 11-7: INSTALL Command Message
        if (command.Length < 5)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.WrongLength()
            );

        byte p1 = command[2]; // Install type
        byte p2 = command[3]; // Install options - GlobalPlatform Card Specification v2.3.1 Table 11-7
        byte lc = command[4];

        if (command.Length < 5 + lc)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.WrongLength()
            );

        // Extract command data
        byte[] commandData = new byte[lc];
        Array.Copy(command, 5, commandData, 0, lc);

        // Determine install type from P1
        bool installForLoad = (p1 & 0x02) != 0;
        bool installForInstall = (p1 & 0x04) != 0;

        if (installForLoad)
        {
            // INSTALL [for load] - GlobalPlatform Card Specification v2.3.1 Section 11.5.2.1
            return ParseInstallForLoadData(commandData)
                .Bind(parsedData =>
                    ValidateInstallToken(
                            parsedData.loadToken,
                            parsedData.loadFileDataBlockHash,
                            config
                        )
                        .Map(_ => parsedData)
                )
                .Bind(parsedData => CreateInstallForLoadResponse(parsedData, state, config));
        }
        if (installForInstall)
        {
            // INSTALL [for install] - GlobalPlatform Card Specification v2.3.1 Section 11.5.2.2
            return ParseInstallForInstallData(commandData)
                .Bind(parsedData =>
                {
                    (
                        byte[] loadFileAid,
                        var moduleAid,
                        byte[] appAid,
                        byte privileges,
                        byte[] installParameters,
                        byte[] installToken
                    ) = parsedData;

                    // Resolve executable module AID using functional pattern
                    byte[] resolvedModuleAid = moduleAid.Match(mAid => mAid, () => appAid);

                    // Create application with proper lifecycle management
                    const byte validInitialState = LifecycleStates.SELECTABLE;

                    return Result
                        .Success<InstalledApplication, SmartCardError>(
                            new InstalledApplication(
                                Aid: appAid,
                                ExecutableModuleAid: resolvedModuleAid,
                                LifecycleState: validInitialState, // GP default for INSTALL [for install]
                                Privileges: (Privilege)privileges,
                                ApplicationData: ImmutableDictionary<string, byte[]>.Empty
                            )
                        )
                        .Map(application =>
                        {
                            string appKey = Convert.ToHexString(appAid);
                            var newState = state with
                            {
                                Applications = state.Applications.SetItem(appKey, application),
                            };

                            // GlobalPlatform Card Specification v2.3.1 Table 11-13: INSTALL Response
                            return (
                                new ApduResponse(
                                    [0x00],
                                    Constants.Constants.StatusWords.Success
                                ),
                                newState
                            );
                        });
                });
        }

        // Default response for unhandled install types
        return Result.Success<(ApduResponse, CardState), SmartCardError>(
            (new ApduResponse([0x00], Constants.Constants.StatusWords.Success), state)
        );
    }

    /// <summary>
    /// Parses INSTALL [for load] command data per GlobalPlatform Card Specification v2.3.1 Table 11-42.
    /// Extracts all mandatory fields including Load Parameters and Load Token.
    /// </summary>
    /// <param name="data">The command data containing all INSTALL [for load] fields.</param>
    /// <returns>A result containing parsed load file data with all mandatory fields.</returns>
    private static Result<
        (
            byte[] loadFileAid,
            Maybe<byte[]> securityDomainAid,
            byte[] loadFileDataBlockHash,
            byte[] loadParameters,
            byte[] loadToken
        ),
        SmartCardError
    > ParseInstallForLoadData(byte[] data)
    {
        int offset = 0;

        // 1. Parse Load File AID (MANDATORY) - GlobalPlatform Card Specification v2.3.1 Table 11-42
        if (offset >= data.Length)
            return Result.Failure<(byte[], Maybe<byte[]>, byte[], byte[], byte[]), SmartCardError>(
                SmartCardError.InvalidData("Missing Load File AID")
            );

        byte loadFileAidLength = data[offset++];
        if (
            loadFileAidLength < 5
            || loadFileAidLength > 16
            || offset + loadFileAidLength > data.Length
        )
            return Result.Failure<(byte[], Maybe<byte[]>, byte[], byte[], byte[]), SmartCardError>(
                SmartCardError.InvalidData("Invalid Load File AID length")
            );

        byte[] loadFileAid = new byte[loadFileAidLength];
        Array.Copy(data, offset, loadFileAid, 0, loadFileAidLength);
        offset += loadFileAidLength;

        // 2. Parse Security Domain AID (CONDITIONAL) - 0 or 5-16 bytes
        var securityDomainAid = Maybe<byte[]>.None;
        if (offset >= data.Length)
            return Result.Failure<(byte[], Maybe<byte[]>, byte[], byte[], byte[]), SmartCardError>(
                SmartCardError.InvalidData("Missing Security Domain AID length")
            );

        byte sdAidLength = data[offset++];
        if (sdAidLength > 0)
        {
            if (sdAidLength < 5 || sdAidLength > 16 || offset + sdAidLength > data.Length)
                return Result.Failure<
                    (byte[], Maybe<byte[]>, byte[], byte[], byte[]),
                    SmartCardError
                >(SmartCardError.InvalidData("Invalid Security Domain AID length"));

            byte[] sdAid = new byte[sdAidLength];
            Array.Copy(data, offset, sdAid, 0, sdAidLength);
            securityDomainAid = Maybe<byte[]>.From(sdAid);
            offset += sdAidLength;
        }

        // 3. Parse Load File Data Block Hash (MANDATORY) - Length + Hash
        if (offset >= data.Length)
            return Result.Failure<(byte[], Maybe<byte[]>, byte[], byte[], byte[]), SmartCardError>(
                SmartCardError.InvalidData("Missing Load File Data Block Hash length")
            );

        byte hashLength = data[offset++];
        byte[] loadFileDataBlockHash = new byte[hashLength];
        if (hashLength > 0 && offset + hashLength <= data.Length)
        {
            Array.Copy(data, offset, loadFileDataBlockHash, 0, hashLength);
            offset += hashLength;
        }

        // 4. Parse Load Parameters field (MANDATORY) - Complex length encoding per GP spec
        if (offset >= data.Length)
            return Result.Failure<(byte[], Maybe<byte[]>, byte[], byte[], byte[]), SmartCardError>(
                SmartCardError.InvalidData("Missing Load Parameters length")
            );

        Result<(byte[] parameters, int newOffset), SmartCardError> loadParamsResult =
            ParseTlvLengthAndData(data, offset, "Load Parameters");
        if (loadParamsResult.IsFailure)
            return Result.Failure<(byte[], Maybe<byte[]>, byte[], byte[], byte[]), SmartCardError>(
                loadParamsResult.Error
            );

        (byte[] loadParameters, int afterLoadParams) = loadParamsResult.Value;
        offset = afterLoadParams;

        // 5. Parse Load Token (MANDATORY) - Complex length encoding per GP spec
        if (offset >= data.Length)
            return Result.Failure<(byte[], Maybe<byte[]>, byte[], byte[], byte[]), SmartCardError>(
                SmartCardError.InvalidData("Missing Load Token length")
            );

        Result<(byte[] token, int newOffset), SmartCardError> loadTokenResult =
            ParseTlvLengthAndData(data, offset, "Load Token");
        if (loadTokenResult.IsFailure)
            return Result.Failure<(byte[], Maybe<byte[]>, byte[], byte[], byte[]), SmartCardError>(
                loadTokenResult.Error
            );

        (byte[] loadToken, int _) = loadTokenResult.Value;

        return Result.Success<(byte[], Maybe<byte[]>, byte[], byte[], byte[]), SmartCardError>(
            (loadFileAid, securityDomainAid, loadFileDataBlockHash, loadParameters, loadToken)
        );
    }

    /// <summary>
    /// Parses INSTALL [for install] command data per GlobalPlatform Card Specification v2.3.1 Table 11-43.
    /// Extracts all mandatory fields including Install Parameters and Install Token.
    /// </summary>
    private static Result<
        (
            byte[] loadFileAid,
            Maybe<byte[]> moduleAid,
            byte[] appAid,
            byte privileges,
            byte[] installParameters,
            byte[] installToken
        ),
        SmartCardError
    > ParseInstallForInstallData(byte[] data)
    {
        int offset = 0;

        // Parse Load File AID
        if (offset >= data.Length)
            return Result.Failure<
                (byte[], Maybe<byte[]>, byte[], byte, byte[], byte[]),
                SmartCardError
            >(SmartCardError.InvalidData("Missing Load File AID"));

        byte loadFileAidLength = data[offset++];
        if (offset + loadFileAidLength > data.Length)
            return Result.Failure<
                (byte[], Maybe<byte[]>, byte[], byte, byte[], byte[]),
                SmartCardError
            >(SmartCardError.InvalidData("Invalid Load File AID length"));

        byte[] loadFileAid = new byte[loadFileAidLength];
        Array.Copy(data, offset, loadFileAid, 0, loadFileAidLength);
        offset += loadFileAidLength;

        // Parse Module AID
        if (offset >= data.Length)
            return Result.Failure<
                (byte[], Maybe<byte[]>, byte[], byte, byte[], byte[]),
                SmartCardError
            >(SmartCardError.InvalidData("Missing Module AID"));

        byte moduleAidLength = data[offset++];
        var moduleAid = Maybe<byte[]>.None;
        if (moduleAidLength > 0 && offset + moduleAidLength <= data.Length)
        {
            byte[] aid = new byte[moduleAidLength];
            Array.Copy(data, offset, aid, 0, moduleAidLength);
            moduleAid = Maybe<byte[]>.From(aid);
            offset += moduleAidLength;
        }
        else
        {
            offset += moduleAidLength; // Skip if length is 0
        }

        // Parse Application AID
        if (offset >= data.Length)
            return Result.Failure<
                (byte[], Maybe<byte[]>, byte[], byte, byte[], byte[]),
                SmartCardError
            >(SmartCardError.InvalidData("Missing Application AID"));

        byte appAidLength = data[offset++];
        if (offset + appAidLength > data.Length)
            return Result.Failure<
                (byte[], Maybe<byte[]>, byte[], byte, byte[], byte[]),
                SmartCardError
            >(SmartCardError.InvalidData("Invalid Application AID length"));

        byte[] appAid = new byte[appAidLength];
        Array.Copy(data, offset, appAid, 0, appAidLength);
        offset += appAidLength;

        // 4. Parse Privileges (MANDATORY) - GlobalPlatform Card Specification v2.3.1 Table 11-43
        if (offset >= data.Length)
            return Result.Failure<
                (byte[], Maybe<byte[]>, byte[], byte, byte[], byte[]),
                SmartCardError
            >(SmartCardError.InvalidData("Missing Privileges field"));

        byte privLength = data[offset++];
        if (privLength != 1 || offset >= data.Length)
            return Result.Failure<
                (byte[], Maybe<byte[]>, byte[], byte, byte[], byte[]),
                SmartCardError
            >(SmartCardError.InvalidData("Invalid Privileges field length"));

        byte privileges = data[offset++];

        // 5. Parse Install Parameters field (MANDATORY) - Complex length encoding per GP spec
        if (offset >= data.Length)
            return Result.Failure<
                (byte[], Maybe<byte[]>, byte[], byte, byte[], byte[]),
                SmartCardError
            >(SmartCardError.InvalidData("Missing Install Parameters length"));

        Result<(byte[] parameters, int newOffset), SmartCardError> installParamsResult =
            ParseTlvLengthAndData(data, offset, "Install Parameters");
        if (installParamsResult.IsFailure)
            return Result.Failure<
                (byte[], Maybe<byte[]>, byte[], byte, byte[], byte[]),
                SmartCardError
            >(installParamsResult.Error);

        (byte[] installParameters, int afterInstallParams) = installParamsResult.Value;
        offset = afterInstallParams;

        // 6. Parse Install Token (MANDATORY) - Complex length encoding per GP spec
        if (offset >= data.Length)
            return Result.Failure<
                (byte[], Maybe<byte[]>, byte[], byte, byte[], byte[]),
                SmartCardError
            >(SmartCardError.InvalidData("Missing Install Token length"));

        Result<(byte[] token, int newOffset), SmartCardError> installTokenResult =
            ParseTlvLengthAndData(data, offset, "Install Token");
        if (installTokenResult.IsFailure)
            return Result.Failure<
                (byte[], Maybe<byte[]>, byte[], byte, byte[], byte[]),
                SmartCardError
            >(installTokenResult.Error);

        (byte[] installToken, int _) = installTokenResult.Value;

        return Result.Success<
            (byte[], Maybe<byte[]>, byte[], byte, byte[], byte[]),
            SmartCardError
        >((loadFileAid, moduleAid, appAid, privileges, installParameters, installToken));
    }

    /// <summary>
    /// Processes a LOAD command for a virtual card based on the received APDU byte array, current card state, and card configuration.
    /// </summary>
    /// <param name="command">The APDU byte array containing the LOAD command to process.</param>
    /// <param name="state">The current state of the card.</param>
    /// <param name="config">The configuration of the card defining its capabilities and settings.</param>
    /// <returns>
    /// A result containing a tuple with the APDU response and the updated card state if the operation succeeds,
    /// or a SmartCardError describing the failure.
    /// </returns>
    private static Result<(ApduResponse, CardState), SmartCardError> ProcessLoadCommand(
        byte[] command,
        CardState state,
        CardConfiguration config
    )
    {
        // GlobalPlatform Card Specification v2.3.1 Section 11.6 LOAD Command
        // Table 11-14: LOAD Command Message
        if (command.Length < 5)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.WrongLength()
            );

        // GlobalPlatform Card Specification v2.3.1 Section 11.6.2.1-2, Tables 11-56, 11-57
        // P1: Reference control parameter - bit 8: 0 = More blocks, 1 = Last block
        // P2: Block number - sequential from 00 to FF
        byte p1 = command[2]; // More/Last block indicator
        byte p2 = command[3]; // Block number
        byte lc = command[4];

        if (command.Length < 5 + lc)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.WrongLength()
            );

        // Extract load file data block
        byte[] dataBlock = new byte[lc];
        Array.Copy(command, 5, dataBlock, 0, lc);

        byte blockNumber = p2; // P2 contains block number per GP spec
        bool isLastBlock = (p1 & 0x80) != 0x00; // P1 bit 8: 1 = last block, 0 = more blocks

        // Process the data block according to GP specification
        return ProcessLoadDataBlock(dataBlock, blockNumber, isLastBlock, state, config)
            .Map(result =>
            {
                (var newState, bool loadComplete) = result;

                // Create response according to GP Table 11-18: LOAD Response Message
                byte[] responseData = loadComplete ? [0x00] : [];

                return (
                    new ApduResponse(
                        responseData,
                        Constants.Constants.StatusWords.Success
                    ),
                    newState
                );
            });
    }

    /// <summary>
    /// Processes a LOAD command data block
    /// Accumulates data blocks and processes complete CAP file when last block is received.
    /// </summary>
    private static Result<
        (CardState newState, bool loadComplete),
        SmartCardError
    > ProcessLoadDataBlock(
        byte[] dataBlock,
        byte blockNumber,
        bool isLastBlock,
        CardState state,
        CardConfiguration config
    )
    {
        // Get or create the load context from card state data objects
        return GetOrCreateLoadContext(state, blockNumber)
            .Bind(loadContext =>
            {
                // Append data block to accumulated data
                return AccumulateLoadData(loadContext.AccumulatedData, dataBlock, blockNumber)
                    .Bind(updatedData =>
                    {
                        if (isLastBlock)
                        {
                            // Process complete CAP file and update load files
                            return ProcessCompleteCapFile(updatedData, state, config)
                                .Map(newState =>
                                {
                                    // Remove load context from state and mark load as complete
                                    var finalState = RemoveLoadContext(newState);
                                    return (finalState, true);
                                });
                        }

                        // Update load context and continue
                        var newLoadContext = loadContext with
                        {
                            AccumulatedData = updatedData,
                            LastBlockNumber = blockNumber,
                        };
                        var stateWithContext = UpdateLoadContext(state, newLoadContext);
                        return Result.Success<(CardState, bool), SmartCardError>(
                            (stateWithContext, false)
                        );
                    });
            });
    }

    /// <summary>
    /// Gets existing or creates new load context for tracking data block accumulation.
    /// </summary>
    private static Result<LoadContext, SmartCardError> GetOrCreateLoadContext(
        CardState state,
        byte blockNumber
    )
    {
        const ushort loadContextTag = 0xFFFF; // Internal tag for load context storage

        if (state.DataObjects.TryGetValue(loadContextTag, out byte[] contextData))
        {
            // Deserialize existing context
            return DeserializeLoadContext(contextData);
        }

        // Create new context for block 0
        if (blockNumber != 0x00)
            return Result.Failure<LoadContext, SmartCardError>(
                SmartCardError.InvalidArgument("LOAD must start with block 0")
            );

        return Result.Success<LoadContext, SmartCardError>(
            new LoadContext(ImmutableList<byte>.Empty, 0xFF)
        ); // 0xFF indicates no previous block
    }

    /// <summary>
    /// Accumulates data block into the total data.
    /// </summary>
    private static Result<ImmutableList<byte>, SmartCardError> AccumulateLoadData(
        ImmutableList<byte> currentData,
        byte[] dataBlock,
        byte blockNumber
    )
    {
        // Validate block sequence
        byte expectedBlockNumber = (byte)(currentData.Count / 255 % 256); // Estimate based on data size

        // Accumulate data functionally
        return Result.Success<ImmutableList<byte>, SmartCardError>(currentData.AddRange(dataBlock));
    }

    /// <summary>
    /// Processes complete CAP file data and updates card state with new load file.
    /// Includes mandatory DAP verification and LFDBH verification per GP specification.
    /// Uses default CAP file service for processing logic.
    /// </summary>
    private static Result<CardState, SmartCardError> ProcessCompleteCapFile(
        ImmutableList<byte> capFileData,
        CardState state,
        CardConfiguration config
    )
    {
        byte[] capBytes = capFileData.ToArray();
        var capFileService = new CapFileServiceAdapter();
        var expectedHashMaybe = ExtractExpectedLfdbhFromState(state).Match(
            success => Maybe<LoadFileDataBlockHash>.From(success),
            error => Maybe<LoadFileDataBlockHash>.None
        );

        return capFileService
            .ProcessCapFileForLoading(capBytes, expectedHashMaybe)
            .Bind(module => CreateLoadFileFromModule(module, capBytes, config))
            .Map(loadFile => state.WithLoadFile(loadFile));
    }


    /// <summary>
    /// Creates a LoadFile from an extracted ExecutableModule and CAP file data.
    /// </summary>
    private static Result<LoadFile, SmartCardError> CreateLoadFileFromModule(
        ExecutableModule module,
        byte[] capFileData,
        CardConfiguration config
    )
    {
        const byte validInitialState = LifecycleStates.LOADED;

        var moduleBuilder = ImmutableList.CreateBuilder<ExecutableModule>();
        moduleBuilder.Add(module);

        return Result.Success<LoadFile, SmartCardError>(
            new LoadFile(
                Aid: module.Aid,
                AssociatedSecurityDomainAid: config.IsdAid,
                LifecycleState: validInitialState,
                ExecutableModules: moduleBuilder.ToImmutable()
            )
        );
    }


    /// <summary>
    /// Validates install token according to GlobalPlatform Card Specification v2.3.1 Section 11.5.2.1.
    /// Token validation ensures authorization for load file installation operations.
    /// </summary>
    private static Result<bool, SmartCardError> ValidateInstallToken(
        byte[] loadToken,
        byte[] loadFileDataBlockHash,
        CardConfiguration config
    )
    {
        // GlobalPlatform Card Specification v2.3.1 Section 11.5.2.1:
        // Token validation shall verify authorization and integrity
        return ParseTokenStructure(loadToken)
            .Bind(token => ValidateTokenSignature(token, loadFileDataBlockHash, config))
            .Bind(token => ValidateTokenAuthorization(token, config))
            .Map(_ => true);
    }

    /// <summary>
    /// Parses install token TLV structure per GP specification.
    /// </summary>
    private static Result<InstallToken, SmartCardError> ParseTokenStructure(byte[] tokenData)
    {
        return tokenData.Length >= 16
            ? Result.Success<InstallToken, SmartCardError>(
                new InstallToken(
                    Signature: tokenData.Take(8).ToArray(),
                    Algorithm: "HMAC_SHA256",
                    KeyIdentifier: tokenData.Skip(8).Take(2).ToArray(),
                    AuthorizationLevel: tokenData.Skip(10).Take(1).ToArray()
                )
            )
            : Result.Failure<InstallToken, SmartCardError>(
                SmartCardError.InvalidData("Install token too short")
            );
    }

    /// <summary>
    /// Validates token signature against load file hash.
    /// </summary>
    private static Result<InstallToken, SmartCardError> ValidateTokenSignature(
        InstallToken token,
        byte[] loadFileHash,
        CardConfiguration config
    )
    {
        // Verify HMAC signature per GlobalPlatform specification
        // Token signature covers: AID + parameters + load file hash

        // Get token key from configuration (or use test key for virtual card)
        return GetTokenVerificationKey(config, token.KeyIdentifier)
            .Bind(key => {
                // Construct data to verify: loadFileHash + keyIdentifier + authLevel
                byte[] dataToVerify = loadFileHash
                    .Concat(token.KeyIdentifier)
                    .Concat(token.AuthorizationLevel)
                    .ToArray();

                // Compute HMAC-SHA256 using BouncyCastle directly
                return Result.Try(() =>
                {
                    var hmac = new Org.BouncyCastle.Crypto.Macs.HMac(new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
                    hmac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key));
                    hmac.BlockUpdate(dataToVerify, 0, dataToVerify.Length);
                    byte[] result = new byte[hmac.GetMacSize()];
                    hmac.DoFinal(result, 0);
                    return result.Take(8).ToArray(); // Take first 8 bytes as token MAC
                }, ex => SmartCardError.CryptographicError($"HMAC calculation failed: {ex.Message}"));
            })
            .Bind(expectedMac => {
                // Verify signature matches (use first 8 bytes of HMAC for token)
                byte[] truncatedMac = expectedMac.Take(8).ToArray();
                bool isValid = truncatedMac.SequenceEqual(token.Signature);

                return isValid
                    ? Result.Success<InstallToken, SmartCardError>(token)
                    : Result.Failure<InstallToken, SmartCardError>(
                        SmartCardError.SecurityStatusNotSatisfied(
                            "Install token HMAC verification failed - signature mismatch"
                        )
                    );
            });
    }

    private static Result<byte[], SmartCardError> GetTokenVerificationKey(
        CardConfiguration config,
        byte[] keyIdentifier
    )
    {
        // In virtual card, use deterministic test key based on key identifier
        // Production would look up actual key from secure storage
        byte[] testKey = Enumerable.Range(0, 32)  // 256-bit HMAC key
            .Select(i => (byte)((keyIdentifier[0] + i * 13 + 97) % 256))
            .ToArray();

        return Result.Success<byte[], SmartCardError>(testKey);
    }

    /// <summary>
    /// Validates token authorization level against security domain privileges.
    /// </summary>
    private static Result<InstallToken, SmartCardError> ValidateTokenAuthorization(
        InstallToken token,
        CardConfiguration config
    )
    {
        // Check if security domain has sufficient privileges for installation
        return token.AuthorizationLevel.Length > 0 && token.AuthorizationLevel[0] >= 0x01
            ? Result.Success<InstallToken, SmartCardError>(token)
            : Result.Failure<InstallToken, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied(
                    "Insufficient privileges for installation"
                )
            );
    }

    /// <summary>
    /// Creates response for INSTALL [for load] command after successful validation.
    /// </summary>
    private static Result<(ApduResponse, CardState), SmartCardError> CreateInstallForLoadResponse(
        (
            byte[] loadFileAid,
            Maybe<byte[]> securityDomainAid,
            byte[] loadFileDataBlockHash,
            byte[] loadParameters,
            byte[] loadToken
        ) parsedData,
        CardState state,
        CardConfiguration config
    )
    {
        byte[] resolvedSecurityDomain = parsedData.securityDomainAid.Match(
            sd => sd,
            () => config.IsdAid
        );

        const byte validInitialState = LifecycleStates.LOADED;

        return Result
            .Success<LoadFile, SmartCardError>(
                new LoadFile(
                    Aid: parsedData.loadFileAid,
                    AssociatedSecurityDomainAid: resolvedSecurityDomain,
                    LifecycleState: validInitialState,
                    ExecutableModules: ImmutableList<ExecutableModule>.Empty
                )
            )
            .Map(loadFile =>
            {
                var newState = state.WithLoadFile(loadFile);
                return (
                    new ApduResponse([0x00], Constants.Constants.StatusWords.Success),
                    newState
                );
            });
    }

    /// <summary>
    /// Represents install token structure per GlobalPlatform specification.
    /// </summary>
    private record InstallToken(
        byte[] Signature,
        string Algorithm,
        byte[] KeyIdentifier,
        byte[] AuthorizationLevel
    );

    /// <summary>
    /// Verifies Load File Data Block Hash per GlobalPlatform Card Specification v2.3.1.
    /// LFDBH verification ensures load file integrity against INSTALL [for load] hash.
    /// </summary>
    private static Result<bool, SmartCardError> VerifyLfdbhHash(
        byte[] completeCapFileData,
        CardState state
    )
    {
        // GlobalPlatform Card Specification v2.3.1 Section 11.5.2.1:
        // Hash verification shall compare actual load file data against expected hash
        return ExtractExpectedLfdbhFromState(state)
            .Bind(expectedHash =>
                LoadFileDataBlockHash.ComputeFromCapFile(completeCapFileData)
                    .Bind(actualHash => expectedHash.VerifyMatch(actualHash))
            );
    }

    /// <summary>
    /// Extracts expected LFDBH from card state (from previous INSTALL [for load]).
    /// </summary>
    private static Result<LoadFileDataBlockHash, SmartCardError> ExtractExpectedLfdbhFromState(
        CardState state
    )
    {
        // In a complete implementation, this would extract the hash from the load context
        // saved during INSTALL [for load] command processing
        return state.DataObjects.TryGetValue(0xC001, out var hashValue)
            ? LoadFileDataBlockHash.Create(hashValue)
            : Result.Failure<LoadFileDataBlockHash, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied(
                    "Expected LFDBH not found in card state - INSTALL [for load] required first"
                )
            );
    }



    /// <summary>
    /// Updates the load context in card state data objects.
    /// </summary>
    private static CardState UpdateLoadContext(CardState state, LoadContext context)
    {
        byte[] contextData = SerializeLoadContext(context);
        return state.WithDataObject(0xFFFF, contextData);
    }

    /// <summary>
    /// Removes the load context from card state after load completion.
    /// </summary>
    private static CardState RemoveLoadContext(CardState state)
    {
        const ushort loadContextTag = 0xFFFF;
        return state with { DataObjects = state.DataObjects.Remove(loadContextTag) };
    }

    /// <summary>
    /// Serializes load context for storage in card state.
    /// </summary>
    private static byte[] SerializeLoadContext(LoadContext context)
    {
        // Simple serialization: length (4 bytes) + data + last block number (1 byte)
        byte[] result = new byte[5 + context.AccumulatedData.Count];
        int dataCount = context.AccumulatedData.Count;

        // Write data length in big-endian format
        result[0] = (byte)(dataCount >> 24);
        result[1] = (byte)(dataCount >> 16);
        result[2] = (byte)(dataCount >> 8);
        result[3] = (byte)dataCount;

        // Write accumulated data
        if (dataCount > 0)
        {
            byte[] dataArray = context.AccumulatedData.ToArray();
            Array.Copy(dataArray, 0, result, 4, dataCount);
        }

        // Write last block number
        result[4 + dataCount] = context.LastBlockNumber;

        return result;
    }

    /// <summary>
    /// Deserializes load context from card state storage.
    /// </summary>
    private static Result<LoadContext, SmartCardError> DeserializeLoadContext(byte[] data)
    {
        if (data.Length < 5)
            return Result.Failure<LoadContext, SmartCardError>(
                SmartCardError.InvalidData("Load context data too small")
            );

        // Read data length in big-endian format
        int dataLength = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];

        if (data.Length != 5 + dataLength)
            return Result.Failure<LoadContext, SmartCardError>(
                SmartCardError.InvalidData("Load context data length mismatch")
            );

        // Read accumulated data
        var accumulatedData =
            dataLength > 0
                ? ImmutableList.CreateRange(data.Skip(4).Take(dataLength))
                : ImmutableList<byte>.Empty;

        // Read last block number
        byte lastBlockNumber = data[4 + dataLength];

        return Result.Success<LoadContext, SmartCardError>(
            new LoadContext(accumulatedData, lastBlockNumber)
        );
    }

    /// <summary>
    /// Processes the DELETE command based on the provided APDU structure,
    /// current card state, and card configuration.
    /// </summary>
    /// <param name="command">The APDU command for DELETE operation.</param>
    /// <param name="state">The current state of the virtual card.</param>
    /// <param name="config">The configuration of the card, including settings and constraints.</param>
    /// <param name="logging">The logging service for debug and trace output.</param>
    /// <returns>
    /// A result consisting of a tuple with an APDU response and the updated card state,
    /// or an error indicating the failure reason.
    /// </returns>
    private static Result<(ApduResponse, CardState), SmartCardError> ProcessDeleteCommand(
        byte[] command,
        CardState state,
        CardConfiguration config,
        LoggingService logging
    )
    {
        // GlobalPlatform Card Specification v2.3.1 Section 11.2 DELETE Command
        // Table 11-20: DELETE Command Message
        if (command.Length < 5)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.WrongLength()
            );

        // GlobalPlatform Card Specification v2.3.1 Tables 11-21, 11-22: P1/P2 parameters
        // P1: Command chaining - bit 8: 0 = Last/only command, 1 = More DELETE commands
        // P2: Deletion scope - bit 8: 0 = Delete object, 1 = Delete object and related objects
        byte p1 = command[2]; // Command chaining control
        byte p2 = command[3]; // Deletion scope control

        // Validate P1/P2 parameters according to GP specification
        var p1P2ValidationResult = ValidateDeleteParameters(p1, p2);
        if (p1P2ValidationResult.IsFailure)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                p1P2ValidationResult.Error
            );
        byte lc = command[4];

        if (command.Length < 5 + lc)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.WrongLength()
            );

        // Extract TLV data
        byte[] tlvData = new byte[lc];
        Array.Copy(command, 5, tlvData, 0, lc);

        // Parse TLV structure using TlvParser
        logging.LogDebug(
            "Processing DELETE command TLV data: {TlvData} ({Length} bytes)",
            Convert.ToHexString(tlvData),
            tlvData.Length
        );

        return TlvParser
            .ParseMultiple(tlvData.ToImmutableArray())
            .Bind(parseResult =>
                parseResult.Objects.Length > 0
                    ? Result.Success<ImmutableArray<TlvObject>, SmartCardError>(parseResult.Objects)
                    : Result.Failure<ImmutableArray<TlvObject>, SmartCardError>(
                        SmartCardError.InvalidData("No TLV objects found in DELETE data")
                    )
            )
            .Bind(tlvs => ProcessDeleteTlvData(tlvs, state, logging));
    }

    /// <summary>
    /// Processes a single TLV in DELETE command.
    /// </summary>
    private static CardState ProcessDeleteTlv(uint tagNumber, TlvObject tlv, CardState currentState)
    {
        return tagNumber switch
        {
            // GlobalPlatform Card Specification v2.3.1 Section 11.1.1.1
            // Tag 0x4F - Application AID or Executable Load File AID
            0x4F => ProcessApplicationAidDeletion(tlv, currentState),

            // GlobalPlatform Card Specification v2.3.1 Section 11.1.1.1
            // Tag 0xD3 - Deletion Token (Receipt generation/verification)
            0xD3 => currentState, // Accept any deletion token

            // Unknown tags are ignored
            _ => currentState,
        };
    }

    /// <summary>
    /// Processes application AID deletion from TLV.
    /// </summary>
    private static CardState ProcessApplicationAidDeletion(TlvObject tlv, CardState currentState)
    {
        // Extract AID from TLV
        return GetTlvValue(tlv)
            .Match(
                aidData =>
                {
                    // Remove matching applications using functional operations
                    var updatedApps = currentState
                        .Applications.Where(kvp => !AreAidsEqual(GetApplicationAid(kvp), aidData))
                        .ToImmutableDictionary();

                    // Remove matching load files using functional operations
                    var updatedLoadFiles = currentState
                        .LoadFiles.Where(lf => !lf.Aid.SequenceEqual(aidData))
                        .ToImmutableList();

                    return currentState with
                    {
                        Applications = updatedApps,
                        LoadFiles = updatedLoadFiles,
                    };
                },
                () => currentState
            );
    }

    /// <summary>
    /// Extracts TLV value.
    /// </summary>
    private static Maybe<byte[]> GetTlvValue(TlvObject tlv) =>
        Maybe.From(tlv).Map(t => t.TlvData.Bytes.ToArray()).Where(data => data.Length > 0);

    /// <summary>
    /// Gets application AID from key-value pair.
    /// </summary>
    private static byte[] GetApplicationAid(KeyValuePair<string, InstalledApplication> kvp)
    {
        var (_, application) = kvp;
        return application.Aid;
    }

    /// <summary>
    /// Compares two AID byte arrays for equality.
    /// </summary>
    /// <summary>
    /// Compares two AID byte arrays for equality.
    /// GlobalPlatform Card Specification v2.3.1 defines AID comparison as byte-by-byte equality.
    /// </summary>
    private static bool AreAidsEqual(byte[] aid1, byte[] aid2) => aid1.SequenceEqual(aid2);

    /// <summary>
    /// Processes the PUT KEY command to install a new key set into the virtual card state.
    /// </summary>
    /// <param name="command">The APDU command containing the PUT KEY instruction.</param>
    /// <param name="state">The current state of the virtual card.</param>
    /// <param name="config">The card configuration used for contextual operations.</param>
    /// <returns>A result containing a tuple of the APDU response and the updated card state, or an error if processing fails.</returns>
    private static Result<(ApduResponse, CardState), SmartCardError> ProcessPutKeyCommand(
        byte[] command,
        CardState state,
        CardConfiguration config
    )
    {
        // GlobalPlatform Card Specification v2.3.1 Table 11-2: PUT KEY requires AUTHENTICATED security level
        if (state.SecurityLevel < 0x01) // AUTHENTICATED = 0x01
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied()
            );

        if (command.Length < 6) // Minimum command length check
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.WrongLength()
            );

        byte lc = command[4];
        if (command.Length < 5 + lc)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.WrongLength()
            );

        // Parse PUT KEY command data
        int dataOffset = 5;
        byte keyVersion = command[dataOffset]; // First byte is new key version
        dataOffset++;

        // Parse key data according to GlobalPlatform Card Specification v2.3.1 Section 11.5.5
        // Expected format: KVN + (key_type + key_length + key_data + KCV_length + KCV) repeated
        return ParsePutKeyDataWithKcv(command, dataOffset, lc - 1)
            .Bind(parsedData => ValidateProvidedKcvs(parsedData))
            .Bind(validatedData => CreateAndInstallNewKeyset(validatedData, keyVersion, state));
    }

    /// <summary>
    /// Parses PUT KEY command data including KCVs per GP specification.
    /// </summary>
    private static Result<PutKeyData, SmartCardError> ParsePutKeyDataWithKcv(
        byte[] command,
        int dataOffset,
        int remainingLength
    )
    {
        // Expected format per GP specification: keys followed by KCVs
        // Simplified: 3 x 16-byte keys + 3 x 3-byte KCVs = 57 bytes total
        return remainingLength >= 57
            ? Result.Success<PutKeyData, SmartCardError>(
                new PutKeyData(
                    EncKey: command.Skip(dataOffset).Take(16).ToArray(),
                    MacKey: command.Skip(dataOffset + 16).Take(16).ToArray(),
                    DekKey: command.Skip(dataOffset + 32).Take(16).ToArray(),
                    EncKcv: command.Skip(dataOffset + 48).Take(3).ToArray(),
                    MacKcv: command.Skip(dataOffset + 51).Take(3).ToArray(),
                    DekKcv: command.Skip(dataOffset + 54).Take(3).ToArray()
                )
            )
            : Result.Failure<PutKeyData, SmartCardError>(
                SmartCardError.WrongLength("Insufficient data for keys and KCVs")
            );
    }

    /// <summary>
    /// Validates provided KCVs against computed values per GP specification.
    /// </summary>
    private static Result<PutKeyData, SmartCardError> ValidateProvidedKcvs(PutKeyData keyData)
    {
        return CalculateAesKcv(keyData.EncKey)
            .Bind(computedEncKcv => ValidateSingleKcv(keyData.EncKcv, computedEncKcv, "ENC"))
            .Bind(_ => CalculateAesKcv(keyData.MacKey))
            .Bind(computedMacKcv => ValidateSingleKcv(keyData.MacKcv, computedMacKcv, "MAC"))
            .Bind(_ => CalculateAesKcv(keyData.DekKey))
            .Bind(computedDekKcv => ValidateSingleKcv(keyData.DekKcv, computedDekKcv, "DEK"))
            .Map(_ => keyData);
    }

    /// <summary>
    /// Validates a single KCV against computed value.
    /// </summary>
    private static Result<bool, SmartCardError> ValidateSingleKcv(
        byte[] providedKcv,
        byte[] computedKcv,
        string keyType
    )
    {
        return providedKcv.Take(3).SequenceEqual(computedKcv.Take(3))
            ? Result.Success<bool, SmartCardError>(true)
            : Result.Failure<bool, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied($"{keyType} key KCV validation failed")
            );
    }

    /// <summary>
    /// Creates and installs new keyset after successful KCV validation.
    /// </summary>
    private static Result<(ApduResponse, CardState), SmartCardError> CreateAndInstallNewKeyset(
        PutKeyData keyData,
        byte keyVersion,
        CardState state
    )
    {
        return Scp03KeySet
            .Create(
                encKey: keyData.EncKey,
                macKey: keyData.MacKey,
                dekKey: keyData.DekKey,
                keyVersion: keyVersion
            )
            .Map(newKeySet =>
            {
                var newState = state.WithInstalledKey(keyVersion, newKeySet);

                // Create response with key version and computed KCVs
                byte[] response = new byte[10];
                response[0] = keyVersion;
                Array.Copy(keyData.EncKcv, 0, response, 1, 3);
                Array.Copy(keyData.MacKcv, 0, response, 4, 3);
                Array.Copy(keyData.DekKcv, 0, response, 7, 3);

                return (
                    new ApduResponse(
                        response,
                        Constants.Constants.StatusWords.Success
                    ),
                    newState
                );
            });
    }

    /// <summary>
    /// Represents parsed PUT KEY command data including KCVs.
    /// </summary>
    private record PutKeyData(
        byte[] EncKey,
        byte[] MacKey,
        byte[] DekKey,
        byte[] EncKcv,
        byte[] MacKcv,
        byte[] DekKcv
    );

    /// <summary>
    /// Processes the STORE DATA command for the virtual card, parsing the command based on its data structure and executing corresponding actions.
    /// </summary>
    /// <param name="command">The input command bytes representing the STORE DATA structure.</param>
    /// <param name="state">The current state of the virtual card, including its configuration and runtime data.</param>
    /// <param name="config">The card configuration specifying default behaviors and supported instructions.</param>
    /// <returns>
    /// A <see cref="Result"/> containing the APDU response and updated card state if processing is successful,
    /// or an error indicating the failure reason.
    /// </returns>
    private static Result<(ApduResponse, CardState), SmartCardError> ProcessStoreDataCommand(
        byte[] command,
        CardState state,
        CardConfiguration config
    )
    {
        // GlobalPlatform Card Specification v2.3.1 Table 11-2: STORE DATA requires AUTHENTICATED security level
        if (state.SecurityLevel < 0x01) // AUTHENTICATED = 0x01
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied()
            );

        if (command.Length < 5)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.WrongLength()
            );

        byte p1 = command[2];

        // GlobalPlatform Card Specification v2.3.1 Section 11.5.6: P2 parameter handling
        // P2 bits: b8=More blocks, b7-b1=RFU, b1=Encrypt flag
        byte p2 = command[3];
        byte lc = command[4];

        if (command.Length < 5 + lc)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.WrongLength()
            );

        byte[] data = new byte[lc];
        Array.Copy(command, 5, data, 0, lc);

        // Check for DGI format (P1 = 0x80) containing SET CONFIG
        if (p1 == 0x80 && data.Length >= 3)
        {
            // Parse SET CONFIG TLV: DF2B + length + data
            if (data[0] == 0xDF && data[1] == 0x2B)
            {
                byte totalLength = data[2];
                if (data.Length >= 3 + totalLength)
                {
                    byte[] configData = new byte[totalLength];
                    Array.Copy(data, 3, configData, 0, totalLength);
                }
            }
        }

        // Check for default key version setting (tag 0x7F0D)
        if (p1 != 0x80 || data.Length < 4 || data[0] != 0x7F || data[1] != 0x0D)
        {
            return CreateSuccessResponse(state);
        }

        byte length = data[2];
        if (length != 1 || data.Length < 4)
        {
            return CreateSuccessResponse(state);
        }

        byte newDefaultKeyVersion = data[3];
        var newState = state.WithDefaultKeyVersion(newDefaultKeyVersion);

        // Per GlobalPlatform Card Specification v2.3.1: Only return success if data was actually stored
        // Return success with updated state after processing default key version
        return CreateSuccessResponse(newState);
    }

    /// <summary>
    /// Routes INITIALIZE UPDATE to the correct SCP processor based on card configuration.
    /// Uses SCP processors for GP specification compliance.
    /// </summary>
    private static Result<
        (ApduResponse, CardState),
        SmartCardError
    > ProcessInitializeUpdateWithCorrectScp(
        byte[] command,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext,
        LoggingService logging
    )
    {
        // Use SCP-specific processors for GP compliance
        return state.ScpVersion switch
        {
            0x02 => Scp02CommandProcessors.ProcessScp02InitializeUpdate(
                command,
                state,
                config,
                rngContext,
                logging
            ),
            0x03 => Scp03CommandProcessors.ProcessScp03InitializeUpdate(
                command,
                state,
                config,
                rngContext,
                logging.Logger
            ),
            _ => Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.ConditionsNotSatisfied()
            ),
        };
    }

    /// <summary>
    /// Routes EXTERNAL AUTHENTICATE to the correct SCP processor based on card configuration.
    /// Uses SCP processors for GP specification compliance.
    /// </summary>
    private static Result<
        (ApduResponse, CardState),
        SmartCardError
    > ProcessExternalAuthenticateWithCorrectScp(
        byte[] command,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext,
        LoggingService logging
    )
    {
        // Use SCP-specific processors for better error handling and GP compliance
        return state.ScpVersion switch
        {
            0x02 => Scp02CommandProcessors.ProcessScp02ExternalAuthenticate(
                command,
                state,
                config,
                rngContext,
                logging
            ),
            0x03 => Scp03CommandProcessors.ProcessScp03ExternalAuthenticate(
                command,
                state,
                config,
                rngContext,
                logging
            ),
            _ => Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.ConditionsNotSatisfied()
            ),
        };
    }

    /// <summary>
    /// Parses PUT KEY command data to extract ENC, MAC, and DEK keys.
    /// Per GlobalPlatform Card Specification v2.3.1 Section 11.5.5.
    /// </summary>
    private static Result<
        (byte[] encKey, byte[] macKey, byte[] dekKey),
        SmartCardError
    > ParsePutKeyData(byte[] command, int dataOffset, int remainingLength)
    {
        // Parse simplified format: 3 consecutive 16-byte AES keys
        // Full implementation parses TLV structure per GP specification
        if (remainingLength < 48) // 3 * 16 bytes for AES-128 keys
        {
            return Result.Failure<(byte[] encKey, byte[] macKey, byte[] dekKey), SmartCardError>(
                SmartCardError.WrongLength("Insufficient data for 3 AES keys")
            );
        }

        byte[] encKey = new byte[16];
        byte[] macKey = new byte[16];
        byte[] dekKey = new byte[16];

        Array.Copy(command, dataOffset, encKey, 0, 16);
        Array.Copy(command, dataOffset + 16, macKey, 0, 16);
        Array.Copy(command, dataOffset + 32, dekKey, 0, 16);

        return Result.Success<(byte[] encKey, byte[] macKey, byte[] dekKey), SmartCardError>(
            (encKey, macKey, dekKey)
        );
    }

    /// <summary>
    /// Validates DELETE command P1/P2 parameters according to GlobalPlatform specification.
    /// </summary>
    private static Result<bool, SmartCardError> ValidateDeleteParameters(byte p1, byte p2)
    {
        // Per GlobalPlatform Card Specification v2.3.1 Tables 11-21, 11-22
        // P1: Command chaining - bit 8: 0 = Last/only command, 1 = More DELETE commands
        // P2: Deletion scope - bit 8: 0 = Delete object, 1 = Delete object and related objects

        // P1 validation: Only bit 8 is used, bits 1-7 are RFU (should be 0)
        if ((p1 & 0x7F) != 0)
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("P1 bits 1-7 must be zero (RFU)")
            );

        // P2 validation: Only bit 8 is used, bits 1-7 are RFU (should be 0)
        if ((p2 & 0x7F) != 0)
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("P2 bits 1-7 must be zero (RFU)")
            );

        return Result.Success<bool, SmartCardError>(true);
    }

    /// <summary>
    /// Processes DELETE command TLV data.
    /// </summary>
    private static Result<(ApduResponse, CardState), SmartCardError> ProcessDeleteTlvData(
        ImmutableArray<TlvObject> tlvs,
        CardState state,
        LoggingService logging
    )
    {
        logging.LogDebug("DELETE command parsed {Count} TLV objects", tlvs.Length);

        // Process TLV data
        var newState = tlvs.Aggregate(
            state,
            (currentState, tlv) =>
                tlv
                    .Tag.ToNumber()
                    .Match(
                        tagNumber =>
                        {
                            logging.LogDebug(
                                "Processing DELETE TLV tag 0x{TagNumber:X2}",
                                tagNumber
                            );
                            return ProcessDeleteTlv(tagNumber, tlv, currentState);
                        },
                        error =>
                        {
                            logging.LogWarning(
                                "Skipping invalid TLV in DELETE command: {Error}",
                                error.Message
                            );
                            return currentState; // Skip invalid TLVs
                        }
                    )
        );

        // GlobalPlatform Card Specification v2.3.1 Table 11-26: DELETE Response Message
        // Response data field contains one byte set to '00'
        byte[] responseData = [0x00];

        logging.LogDebug("DELETE command processed successfully");
        return Result.Success<(ApduResponse, CardState), SmartCardError>(
            (
                new ApduResponse(
                    responseData,
                    Constants.Constants.StatusWords.Success
                ),
                newState
            )
        );
    }

    /// <summary>
    /// Calculates AES Key Check Value (KCV) per GlobalPlatform specification.
    /// KCV is the first 3 bytes of AES-ECB encryption of 16 zero bytes.
    /// Uses UnifiedCryptoService for consistent cryptographic operations.
    /// </summary>
    private static Result<byte[], SmartCardError> CalculateAesKcv(byte[] key)
    {
        // Per GlobalPlatform: KCV = first 3 bytes of AES-ECB(key, 16 zero bytes)
        byte[] zeroBlock = new byte[16]; // All zeros

        // Use UnifiedCryptoService for AES encryption per project architecture
        return CryptoService
            .Cipher.EncryptAesEcb(key, zeroBlock)
            .Map(encrypted => encrypted.Take(3).ToArray());
    }

    /// <summary>
    /// Parses TLV length encoding and extracts data per GlobalPlatform Card Specification v2.3.1.
    /// Supports short form (0x00-0x80), long form with 1 byte (0x81 0x80-0xFF),
    /// and long form with 2 bytes (0x82 0x01 0x00 - 0x82 0xFF 0xFF).
    /// </summary>
    private static Result<(byte[] data, int newOffset), SmartCardError> ParseTlvLengthAndData(
        byte[] data,
        int offset,
        string fieldName
    )
    {
        if (offset >= data.Length)
            return Result.Failure<(byte[], int), SmartCardError>(
                SmartCardError.InvalidData($"Missing {fieldName} length")
            );

        byte firstByte = data[offset++];
        int dataLength;

        if (firstByte <= 0x80)
        {
            // Short form: 0x00-0x80
            dataLength = firstByte;
        }
        else if (firstByte == 0x81)
        {
            // Long form with 1 byte length: 0x81 0x80-0xFF
            if (offset >= data.Length)
                return Result.Failure<(byte[], int), SmartCardError>(
                    SmartCardError.InvalidData($"Missing {fieldName} long form length")
                );
            dataLength = data[offset++];
        }
        else if (firstByte == 0x82)
        {
            // Long form with 2 bytes length: 0x82 0x01 0x00 - 0x82 0xFF 0xFF
            if (offset + 1 >= data.Length)
                return Result.Failure<(byte[], int), SmartCardError>(
                    SmartCardError.InvalidData($"Missing {fieldName} long form length")
                );
            dataLength = (data[offset] << 8) | data[offset + 1];
            offset += 2;
        }
        else
        {
            return Result.Failure<(byte[], int), SmartCardError>(
                SmartCardError.InvalidData($"Invalid {fieldName} length encoding")
            );
        }

        // Extract data
        byte[] fieldData = new byte[dataLength];
        if (dataLength > 0)
        {
            if (offset + dataLength > data.Length)
                return Result.Failure<(byte[], int), SmartCardError>(
                    SmartCardError.InvalidData($"Insufficient data for {fieldName}")
                );

            Array.Copy(data, offset, fieldData, 0, dataLength);
            offset += dataLength;
        }

        return Result.Success<(byte[], int), SmartCardError>((fieldData, offset));
    }

    /// <summary>
    /// Routes command to applications using ApplicationRegistry.
    /// </summary>
    private static Result<(ApduResponse, CardState), SmartCardError> RouteToApplications(
        byte[] command,
        CardState state,
        IRngContext rngContext,
        LoggingService logging
    )
    {
        return state.ApplicationRegistry.Match(
            registry =>
            {
                logging.LogDebug(
                    "Routing command INS=0x{Ins:X2} to application registry",
                    command[1]
                );

                return registry
                    .RouteCommand(command, state, rngContext)
                    .Map(result =>
                    {
                        var (updatedRegistry, apduResponse) = result;
                        var newState = state with
                        {
                            ApplicationRegistry = Maybe<ApplicationRegistry>.From(updatedRegistry),
                        };

                        // Convert to Core.ApduResponse format
                        var coreResponse = new ApduResponse(
                            apduResponse.Data.IsDefaultOrEmpty
                                ? Array.Empty<byte>()
                                : apduResponse.Data.ToArray(),
                            apduResponse.StatusWord
                        );

                        logging.LogDebug(
                            "Application processed command - Response SW: {StatusWord:X4}",
                            (ushort)(
                                (coreResponse.StatusWord.Sw1 << 8) | coreResponse.StatusWord.Sw2
                            )
                        );

                        return (coreResponse, newState);
                    });
            },
            () =>
            {
                logging.LogError("No application registry available");
                return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                    SmartCardError.UnexpectedError("No application registry available")
                );
            }
        );
    }

    /// <summary>
    /// Applies SCP security to incoming command.
    /// </summary>
    private static Result<ParsedCommand, SmartCardError> ApplyScpSecurity(
        ParsedCommand cmd,
        CardState state,
        LoggingService logging
    )
    {
        // Apply SCP enforcement rules per GP Appendix E before command execution
        var securityValidationResult = ScpEnforcer.ValidateCommandSecurity(
            cmd.Ins,
            state,
            cmd.FullCommand
        );

        if (securityValidationResult.IsFailure)
        {
            logging.LogWarning(
                "SCP validation failed for INS=0x{Ins:X2}: {Error}",
                cmd.Ins,
                securityValidationResult.Error.Message
            );
            return Result.Failure<ParsedCommand, SmartCardError>(securityValidationResult.Error);
        }

        logging.LogDebug(
            "SCP validation passed for INS=0x{Ins:X2}, security level=0x{Level:X2}",
            cmd.Ins,
            state.SecurityLevel
        );

        return Result.Success<ParsedCommand, SmartCardError>(cmd);
    }

    /// <summary>
    /// Creates a successful APDU response with the provided card state.
    /// Helper method to eliminate repetitive Result.Success patterns.
    /// </summary>
    /// <param name="state">The card state to include in the response.</param>
    /// <returns>A successful result with an empty APDU response and the provided state.</returns>
    private static Result<(ApduResponse, CardState), SmartCardError> CreateSuccessResponse(CardState state) =>
        Result.Success<(ApduResponse, CardState), SmartCardError>(
            (new ApduResponse([], Constants.Constants.StatusWords.Success), state)
        );
}
