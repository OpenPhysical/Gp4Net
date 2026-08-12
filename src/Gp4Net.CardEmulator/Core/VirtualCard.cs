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
using Gp4Net.Transport;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using WSCT.ISO7816;
using static Gp4Net.Constants.Constants.GlobalPlatform;
using static Gp4Net.Services.TlvCodec;
using ExecutableModule = Gp4Net.CardEmulator.Functional.ExecutableModule;

namespace Gp4Net.CardEmulator.Core;

/// <summary>
/// Virtual smart card implementation using functional programming patterns and immutable state.
/// Processes commands through composable, testable command processors with proper cryptographic validation.
/// Uses  for all state transitions to ensure immutability.
/// </summary>
[PublicAPI]
public partial class VirtualCard : IVirtualCard
{
    private readonly CardState _currentState;
    private readonly CardState _initialState;
    private readonly CardConfiguration _config;
    private readonly IRngContext _rngContext;
    private readonly CardLogging _logging;
    private readonly EmulatorCapFiles _capFileService;
    private readonly CardStateTransitions _stateService;

    /// <summary>
    /// Initializes a new virtual card with the specified configuration, services, and state.
    /// </summary>
    /// <param name="config">The card configuration defining capabilities and data.</param>
    /// <param name="rngContext">The random number generator context for cryptographic operations.</param>
    /// <param name="currentState">The current immutable card state.</param>
    /// <param name="logger">Optional logger for debugging.</param>
    /// <param name="capFileService">The CAP file processing service for load operations.</param>
    /// <param name="stateService">The immutable card state management service.</param>
    /// <param name="initialState">Optional baseline state used for reset operations.</param>
    public VirtualCard(
        CardConfiguration config,
        IRngContext rngContext,
        CardState currentState,
        CardLogging logger,
        EmulatorCapFiles capFileService,
        CardStateTransitions stateService,
        Maybe<CardState> initialState = default
    )
    {
        _config = config;
        _rngContext = rngContext;
        _currentState = currentState;
        _initialState = initialState.Match(state => state, () => currentState);
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
    /// Uses CardStateTransitions to ensure proper functional state handling.
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
        Maybe<EmulatorCapFiles> capFileService = default,
        Maybe<CardStateTransitions> stateService = default
    )
    {
        var cardStateService = stateService.GetValueOrDefault(new CardStateTransitions(logger));

        return CardState
            .Create()
            .Bind(baseState =>
            {
                var stateWithConfig = baseState with
                {
                    ScpVersion = config.DefaultScpVersion,
                    ScpImplementation = config.DefaultScpImplementation,
                };

                // Initialize with configuration's ISD AID and data objects
                var isdAid = config.IsdAid.ToImmutableArray();

                return CardStateTransitions
                    .InitializeApplicationRegistryWithDataObjects(
                        stateWithConfig,
                        isdAid,
                        config.DefaultDataObjects
                    )
                    .Map(finalState => new VirtualCard(
                        config,
                        rngContext,
                        finalState,
                        new CardLogging(logger),
                        capFileService.GetValueOrDefault(new EmulatorCapFiles()),
                        cardStateService,
                        Maybe<CardState>.From(finalState)
                    ));
            });
    }

    /// <summary>Restores nonvolatile state and performs the reset required on card power-up.</summary>
    public static Result<VirtualCard, SmartCardError> Restore(
        CardConfiguration config,
        IRngContext rngContext,
        CardState persistedState
    )
    {
        CardState resetState = persistedState.Reset().WithoutApplicationRegistry();
        return CardStateTransitions
            .InitializeApplicationRegistryWithDataObjects(
                resetState,
                config.IsdAid.ToImmutableArray(),
                resetState.DataObjects
            )
            .Bind(state => SynchronizeApplicationRegistry(state, config))
            .Map(state => new VirtualCard(
                config,
                rngContext,
                state,
                new CardLogging(Maybe<ILogger>.None),
                new EmulatorCapFiles(),
                new CardStateTransitions(Maybe<ILogger>.None),
                Maybe<CardState>.From(state)
            ));
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
        return Result.Success<IVirtualCard, SmartCardError>(
            new VirtualCard(
                _config,
                _rngContext,
                _initialState,
                new CardLogging(Maybe<ILogger>.None),
                _capFileService,
                _stateService,
                Maybe<CardState>.From(_initialState)
            )
        );
    }

    /// <inheritdoc />
    public Result<(ApduResponse Response, IVirtualCard UpdatedCard), SmartCardError> ProcessCommand(
        byte[] command
    )
    {
        return ProcessCommandFunctionally(
                command,
                _currentState,
                _config,
                _rngContext,
                new CardLogging(Maybe<ILogger>.None)
            )
            .Map(result =>
            {
                var (response, updatedState) = result;

                var updatedCard = new VirtualCard(
                    _config,
                    _rngContext,
                    updatedState,
                    new CardLogging(Maybe<ILogger>.None),
                    _capFileService,
                    _stateService,
                    Maybe<CardState>.From(_initialState)
                );

                return (response, (IVirtualCard)updatedCard);
            });
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
        CardLogging logging
    )
    {
        return EnsureApplicationRegistry(state, config)
            .Bind(initializedState =>
                ValidateCommand(command)
                    .Bind(cmd => ValidateInstructionSupported(cmd, config))
                    .Bind(cmd =>
                    {
                        var securityResult = ApplyScpSecurity(cmd, initializedState, logging);
                        return securityResult.Match(
                            secured =>
                                RouteToApplications(
                                    secured.command.FullCommand,
                                    secured.state,
                                    config,
                                    rngContext,
                                    logging
                                ),
                            error => HandleSecureChannelFailure(error, initializedState, logging)
                        );
                    })
            )
            .Bind(result => ApplyResponseSecurity(result, rngContext, logging));
    }

    private static Result<(ApduResponse, CardState), SmartCardError> HandleSecureChannelFailure(
        SmartCardError error,
        CardState state,
        CardLogging logging
    )
    {
        if (!state.SecureChannel.HasValue)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(error);

        // GP Card Specification v2.3.1, Section 10.2 and Appendix E.1.6.
        logging.LogWarning("Secure Channel Session aborted after a command security error");
        return Result.Success<(ApduResponse, CardState), SmartCardError>(
            (ApduResponse.Error(0x6982), state.WithAbortedSecureChannel())
        );
    }

    /// <summary>
    /// Applies response security (R-MAC and/or R-ENCRYPTION).
    /// </summary>
    private static Result<(ApduResponse, CardState), SmartCardError> ApplyResponseSecurity(
        (ApduResponse response, CardState state) result,
        IRngContext rngContext,
        CardLogging logging
    )
    {
        (var response, var state) = result;

        if (state.IsSecureChannelAborted)
            return Result.Success<(ApduResponse, CardState), SmartCardError>(result);

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
        CardLogging logging
    )
    {
        if (secureChannelState is { HasResponseMac: false, HasResponseEncryption: false })
        {
            logging.LogTrace("Security level does not require response security");
            return Result.Success<(ApduResponse, CardState), SmartCardError>((response, state));
        }

        logging.LogDebug(
            "Applying functional response security - R-MAC: {RMac}, R-ENC: {REnc}",
            secureChannelState.HasResponseMac,
            secureChannelState.HasResponseEncryption
        );

        byte[] fullResponse = new byte[response.Data.Length + 2];
        Array.Copy(response.Data, 0, fullResponse, 0, response.Data.Length);
        fullResponse[^2] = (byte)(response.StatusWord >> 8);
        fullResponse[^1] = (byte)(response.StatusWord & 0xFF);

        return global::Gp4Net
            .Services.ScpOperations.Security.ApplyResponseSecurity(
                new ResponseAPDU(fullResponse),
                secureChannelState
            )
            .Bind(secured => ProcessSecureResponseSuccess(secured, state, logging));
    }

    /// <summary>
    /// Processes the successful secure response result.
    /// </summary>
    private static Result<(ApduResponse, CardState), SmartCardError> ProcessSecureResponseSuccess(
        (ResponseAPDU securedResponse, SecureChannelState newState) success,
        CardState state,
        CardLogging logging
    )
    {
        byte[] processedResponse = success.securedResponse.ToBytes();
        ushort sw = (ushort)(processedResponse[^2] << 8 | processedResponse[^1]);

        byte[] responseData = new byte[processedResponse.Length - 2];
        Array.Copy(processedResponse, 0, responseData, 0, responseData.Length);

        var securedResponse = new ApduResponse(responseData, sw);

        var newCardState = state.WithUpdatedSecureChannel(success.newState);

        logging.LogDebug("Response security applied - New length: {Length}", responseData.Length);

        return Result.Success<(ApduResponse, CardState), SmartCardError>(
            (securedResponse, newCardState)
        );
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

        if (installForLoad && !installForInstall)
        {
            // INSTALL [for load] - GlobalPlatform Card Specification v2.3.1 Section 11.5.2.1
            return ParseInstallForLoadData(commandData)
                .Bind(parsedData => ValidateInstallToken(parsedData.loadToken).Map(_ => parsedData))
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
                    byte validInitialState =
                        (p1 & 0x08) != 0
                            ? (byte)ApplicationLifecycleState.Selectable
                            : (byte)ApplicationLifecycleState.Installed;

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
                                new ApduResponse([0x00], Constants.Constants.StatusWords.Success),
                                newState
                            );
                        });
                });
        }

        return Result.Failure<(ApduResponse, CardState), SmartCardError>(
            SmartCardError.IncorrectP1P2()
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
                    new ApduResponse(responseData, Constants.Constants.StatusWords.Success),
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
        // INSTALL [for load] creates the only valid load context.
        return GetOrCreateLoadContext(state, blockNumber)
            .Bind(loadContext =>
            {
                byte expectedBlock =
                    loadContext.LastBlockNumber == 0xFF
                        ? (byte)0x00
                        : (byte)(loadContext.LastBlockNumber + 1);
                if (blockNumber != expectedBlock)
                    return Result.Failure<(CardState, bool), SmartCardError>(
                        SmartCardError.IncorrectP1P2()
                    );

                // Append data block to accumulated data
                return AccumulateLoadData(loadContext.AccumulatedData, dataBlock)
                    .Bind(updatedData =>
                    {
                        if (isLastBlock)
                        {
                            // Process complete CAP file and update load files
                            return ProcessCompleteCapFile(updatedData, state, loadContext)
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
    /// Gets the load context created by INSTALL [for load].
    /// </summary>
    private static Result<PendingLoadOperation, SmartCardError> GetOrCreateLoadContext(
        CardState state,
        byte blockNumber
    )
    {
        return state.PendingLoad.HasValue
            ? Result.Success<PendingLoadOperation, SmartCardError>(state.PendingLoad.Value)
            : Result.Failure<PendingLoadOperation, SmartCardError>(
                SmartCardError.ConditionsNotSatisfied()
            );
    }

    /// <summary>
    /// Accumulates data block into the total data.
    /// </summary>
    private static Result<ImmutableList<byte>, SmartCardError> AccumulateLoadData(
        ImmutableList<byte> currentData,
        byte[] dataBlock
    )
    {
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
        PendingLoadOperation loadContext
    )
    {
        byte[] capBytes = capFileData.ToArray();
        var capFileService = new EmulatorCapFiles();
        Result<Maybe<LoadFileDataBlockHash>, SmartCardError> expectedHash =
            loadContext.ExpectedHash.Length == 0
                ? Result.Success<Maybe<LoadFileDataBlockHash>, SmartCardError>(
                    Maybe<LoadFileDataBlockHash>.None
                )
                : LoadFileDataBlockHash
                    .Create(loadContext.ExpectedHash)
                    .Map(Maybe<LoadFileDataBlockHash>.From);

        return expectedHash.Bind(hash =>
            capFileService
                .ProcessCapFileForLoading(capBytes, hash)
                .Bind(module => CreateLoadFileFromModule(module, loadContext))
                .Map(loadFile => state.WithLoadFile(loadFile))
        );
    }

    /// <summary>
    /// Creates a LoadFile from the validated module and INSTALL [for load] context.
    /// </summary>
    private static Result<LoadFile, SmartCardError> CreateLoadFileFromModule(
        ExecutableModule module,
        PendingLoadOperation loadContext
    )
    {
        const byte validInitialState = (byte)ExecutableLoadFileLifecycleState.Loaded;

        var moduleBuilder = ImmutableList.CreateBuilder<ExecutableModule>();
        moduleBuilder.Add(module);

        if (!module.Aid.SequenceEqual(loadContext.LoadFileAid))
            return SmartCardError.InvalidData(
                "The loaded CAP package AID does not match INSTALL [for load]"
            );

        return Result.Success<LoadFile, SmartCardError>(
            new LoadFile(
                Aid: loadContext.LoadFileAid,
                AssociatedSecurityDomainAid: loadContext.SecurityDomainAid,
                LifecycleState: validInitialState,
                ExecutableModules: moduleBuilder.ToImmutable()
            )
        );
    }

    /// <summary>
    /// Validates install token according to GlobalPlatform Card Specification v2.3.1 Section 11.5.2.1.
    /// Token validation ensures authorization for load file installation operations.
    /// </summary>
    private static Result<bool, SmartCardError> ValidateInstallToken(byte[] loadToken)
    {
        // Token verification is conditional. This profile has no Token Verification key or
        // policy, so an omitted token is valid and a supplied token must not be simulated.
        return loadToken.Length == 0
            ? Result.Success<bool, SmartCardError>(true)
            : Result.Failure<bool, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied(
                    "The active card profile does not configure install-token verification"
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

        var pending = new PendingLoadOperation(
            (byte[])parsedData.loadFileAid.Clone(),
            (byte[])resolvedSecurityDomain.Clone(),
            (byte[])parsedData.loadFileDataBlockHash.Clone(),
            ImmutableList<byte>.Empty,
            0xFF
        );
        var newState = state with { PendingLoad = Maybe<PendingLoadOperation>.From(pending) };
        return Result.Success<(ApduResponse, CardState), SmartCardError>(
            (new ApduResponse([0x00], Constants.Constants.StatusWords.Success), newState)
        );
    }

    /// <summary>
    /// Updates the load context in card state data objects.
    /// </summary>
    private static CardState UpdateLoadContext(CardState state, PendingLoadOperation context) =>
        state with
        {
            PendingLoad = Maybe<PendingLoadOperation>.From(context)
        };

    /// <summary>
    /// Removes the load context from card state after load completion.
    /// </summary>
    private static CardState RemoveLoadContext(CardState state) =>
        state with
        {
            PendingLoad = Maybe<PendingLoadOperation>.None
        };

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
        CardLogging logging
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
            .ParseMultiple([.. tlvData])
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
    internal static Result<(ApduResponse, CardState), SmartCardError> ProcessPutKeyCommand(
        byte[] command,
        CardState state,
        CardConfiguration config
    )
    {
        // GP Card Specification v2.3.1, Tables 10-1 and 11-2: PUT KEY requires
        // entity authentication; C-MAC and C-DECRYPTION are separate indicators.
        if (!state.IsSecureChannelEstablished)
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

        // GP Card Specification v2.3.1, 11.8.2.1, Table 11-65: b8 is the
        // command-chaining indication and b7-b1 carry the replaced KVN.
        bool hasMoreCommands = (command[2] & 0x80) != 0;
        byte replacedKeyVersion = (byte)(command[2] & 0x7F);
        if (
            replacedKeyVersion != 0x00
            && !state.InstalledKeys.ContainsKey(replacedKeyVersion)
            && !config.StaticKeys.ContainsKey(replacedKeyVersion)
            && !state.InstalledKeyComponents.Keys.Any(key => key.Version == replacedKeyVersion)
        )
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.ReferencedDataNotFound()
            );

        // Parse PUT KEY command data
        int dataOffset = 5;
        byte keyVersion = command[dataOffset]; // First byte is new key version
        dataOffset++;
        if (keyVersion is 0x00 or > 0x7F)
            return SmartCardError.IncorrectData();

        // GP Card Specification v2.3.1, 11.8.2.2, Table 11-66: b8 marks
        // multiple keys and b7-b1 identify the first key.
        bool containsMultipleKeys = (command[3] & 0x80) != 0;
        byte firstKeyIdentifier = (byte)(command[3] & 0x7F);

        // Parse key data according to GlobalPlatform Card Specification v2.3.1 Section 11.8.2.3.
        // Expected format: KVN + (key_type + key_length + key_data + KCV_length + KCV) repeated
        return ParsePutKeyDataWithKcv(command, dataOffset, lc - 1, state)
            .Ensure(
                parsed => containsMultipleKeys == (parsed.KeyCount > 1),
                SmartCardError.InvalidData("PUT KEY P2 does not match the number of keys")
            )
            .Bind(parsedData => ValidateProvidedKcvs(parsedData))
            .Bind(validatedData =>
                ProcessValidatedPutKey(
                    validatedData,
                    replacedKeyVersion,
                    keyVersion,
                    firstKeyIdentifier,
                    hasMoreCommands,
                    state,
                    config
                )
            );
    }

    /// <summary>
    /// Parses PUT KEY command data including KCVs per GP specification.
    /// </summary>
    private static Result<PutKeyData, SmartCardError> ParsePutKeyDataWithKcv(
        byte[] command,
        int dataOffset,
        int remainingLength,
        CardState state
    )
    {
        return state
            .SecureChannel.ToResult(SmartCardError.SecurityStatusNotSatisfied())
            .Bind(channel =>
                channel.SessionKeys.Dek.ToResult(
                    SmartCardError.SecurityStatusNotSatisfied("Secure channel DEK is unavailable")
                )
            )
            .Bind(dek =>
                Result.Try(
                    () =>
                    {
                        int end = dataOffset + remainingLength;
                        var components = ImmutableArray.CreateBuilder<PutKeyComponent>();
                        while (dataOffset < end)
                        {
                            byte type = command[dataOffset++];
                            if (type is not 0x80 and not 0x88)
                                throw new InvalidOperationException(
                                    $"Unsupported symmetric key type {type:X2}"
                                );
                            bool blockIsAes = type == 0x88;
                            int componentLength = ReadPutKeyLength(command, ref dataOffset, end);
                            if (componentLength <= 0 || dataOffset + componentLength > end)
                                throw new InvalidOperationException(
                                    "Invalid PUT KEY component length"
                                );
                            byte[] componentBlock = command
                                .Skip(dataOffset)
                                .Take(componentLength)
                                .ToArray();
                            dataOffset += componentLength;
                            int blockSize = blockIsAes ? 16 : 8;
                            int clearLength = componentLength;
                            if (componentLength % blockSize != 0)
                            {
                                int clearLengthOffset = 0;
                                clearLength = ReadPutKeyLength(
                                    componentBlock,
                                    ref clearLengthOffset,
                                    componentBlock.Length
                                );
                                componentBlock = componentBlock[clearLengthOffset..];
                                if (componentBlock.Length % blockSize != 0)
                                    throw new InvalidOperationException(
                                        "Encrypted key component is not block aligned"
                                    );
                            }
                            var protocol = blockIsAes
                                ? Cryptography.CryptoOperations.ScpVersion.Scp03
                                : Cryptography.CryptoOperations.ScpVersion.Scp02;
                            byte[] key = global::Gp4Net.Services.GlobalPlatform.KeyChange.Unwrap(
                                componentBlock,
                                clearLength,
                                protocol,
                                dek
                            );
                            if (dataOffset >= end)
                                throw new InvalidOperationException(
                                    "Missing key check value length"
                                );
                            int kcvLength = command[dataOffset++];
                            if (kcvLength != 3 || dataOffset + kcvLength > end)
                                throw new InvalidOperationException(
                                    "DES and AES key check values must be 3 bytes"
                                );
                            byte[] kcv = command.Skip(dataOffset).Take(kcvLength).ToArray();
                            dataOffset += kcvLength;
                            components.Add(new PutKeyComponent(type, key, kcv));
                        }
                        if (components.Count == 0)
                            throw new InvalidOperationException("PUT KEY contains no keys");
                        return new PutKeyData(components.ToImmutable());
                    },
                    ex => SmartCardError.InvalidArgument(ex.Message)
                )
            );
    }

    private static int ReadPutKeyLength(byte[] data, ref int offset, int end)
    {
        if (offset >= end)
            throw new InvalidOperationException("Missing PUT KEY length");
        int first = data[offset++];
        if (first <= 0x80)
            return first;
        int octets = first & 0x7F;
        if (octets is < 1 or > 2 || offset + octets > end)
            throw new InvalidOperationException("Invalid PUT KEY BER length");
        int length = 0;
        for (int index = 0; index < octets; index++)
            length = (length << 8) | data[offset++];
        return length;
    }

    /// <summary>
    /// Validates provided KCVs against computed values per GP specification.
    /// </summary>
    private static Result<PutKeyData, SmartCardError> ValidateProvidedKcvs(PutKeyData keyData)
    {
        foreach (var component in keyData.Components)
        {
            byte[] computed = global::Gp4Net.Services.GlobalPlatform.KeyChange.CalculateKcv(
                component.Value,
                component.Type == 0x88
            );
            if (!component.CheckValue.SequenceEqual(computed))
                return SmartCardError.SecurityStatusNotSatisfied(
                    $"Key type {component.Type:X2} KCV validation failed"
                );
        }
        return keyData;
    }

    private static Result<(ApduResponse, CardState), SmartCardError> ProcessValidatedPutKey(
        PutKeyData keyData,
        byte replacedKeyVersion,
        byte keyVersion,
        byte firstKeyIdentifier,
        bool hasMoreCommands,
        CardState state,
        CardConfiguration config
    )
    {
        if (firstKeyIdentifier + keyData.KeyCount - 1 > 0x7F)
            return SmartCardError.InvalidData("PUT KEY identifier sequence exceeds 7F");

        var currentKeys = keyData
            .Components.Select(
                (component, index) =>
                    new KeyValuePair<byte, StoredKeyComponent>(
                        (byte)(firstKeyIdentifier + index),
                        new StoredKeyComponent(
                            component.Type,
                            component.Value.ToImmutableArray(),
                            component.CheckValue.ToImmutableArray()
                        )
                    )
            )
            .ToImmutableDictionary(pair => pair.Key, pair => pair.Value);
        var combinedKeys = currentKeys;
        if (state.PendingPutKey.HasValue)
        {
            var pending = state.PendingPutKey.Value;
            if (pending.ReplacedVersion != replacedKeyVersion || pending.NewVersion != keyVersion)
                return SmartCardError.InvalidData(
                    "Chained PUT KEY commands must use the same key version numbers"
                );
            if (currentKeys.Keys.Any(pending.Keys.ContainsKey))
                return SmartCardError.InvalidData(
                    "Chained symmetric PUT KEY commands contain a duplicate key identifier"
                );
            combinedKeys = pending.Keys.SetItems(currentKeys);
        }

        if (replacedKeyVersion != 0x00)
        {
            foreach (var (identifier, replacement) in combinedKeys)
            {
                var existing = FindExistingKeyComponent(
                    replacedKeyVersion,
                    identifier,
                    state,
                    config
                );
                if (!existing.HasValue)
                    return SmartCardError.ReferencedDataNotFound();
                if (
                    existing.Value.Type != replacement.Type
                    || existing.Value.Value.Length != replacement.Value.Length
                )
                    return SmartCardError.InvalidData(
                        "Replacement key type and length must match the existing key"
                    );
            }
        }

        // GP Card Specification v2.3.1, 11.8.2.3.3: chained PUT KEY
        // commands are committed atomically when the last command is received.
        if (hasMoreCommands)
        {
            var pendingState = state.WithPendingPutKey(
                new PendingPutKeyOperation(replacedKeyVersion, keyVersion, combinedKeys)
            );
            return (CreatePutKeyResponse(keyVersion, keyData), pendingState);
        }

        var installed = combinedKeys.Select(pair => new KeyValuePair<
            KeyReference,
            StoredKeyComponent
        >(new KeyReference(keyVersion, pair.Key), pair.Value));
        var newState = state.WithInstalledKeyComponents(installed).WithoutPendingPutKey();

        var orderedKeys = combinedKeys.OrderBy(pair => pair.Key).ToArray();
        bool formsSecureChannelKeySet =
            orderedKeys.Length == 3
            && orderedKeys[1].Key == orderedKeys[0].Key + 1
            && orderedKeys[2].Key == orderedKeys[1].Key + 1
            && orderedKeys.Select(pair => pair.Value.Type).Distinct().Count() == 1;
        if (formsSecureChannelKeySet)
        {
            var values = orderedKeys.Select(pair => pair.Value.Value.ToArray()).ToArray();
            Result<IKeySet, SmartCardError> keySet =
                orderedKeys[0].Value.Type == 0x88
                    ? Scp03KeySet
                        .Create(values[0], values[1], values[2], keyVersion, orderedKeys[0].Key)
                        .Bind(keys => Result.Success<IKeySet, SmartCardError>(keys))
                    : Scp02KeySet
                        .Create(values[0], values[1], values[2], keyVersion, orderedKeys[0].Key)
                        .Bind(keys => Result.Success<IKeySet, SmartCardError>(keys));
            if (keySet.IsFailure)
                return keySet.Error;
            newState = newState.WithInstalledKey(keyVersion, keySet.Value);
            if (keySet.Value is Scp03KeySet)
            {
                // SCP03 Amendment D v1.1.2, section 6.2.2.1.
                newState = newState.WithResetSequenceCounter(keyVersion);
            }
        }

        return (CreatePutKeyResponse(keyVersion, keyData), newState);
    }

    private static ApduResponse CreatePutKeyResponse(byte keyVersion, PutKeyData keyData)
    {
        // GP Card Specification v2.3.1, 11.8.3.1: KVN is followed by each KCV.
        byte[] data =
        [
            keyVersion,
            .. keyData.Components.SelectMany(component => component.CheckValue),
        ];
        return new ApduResponse(data, Constants.Constants.StatusWords.Success);
    }

    private static Maybe<StoredKeyComponent> FindExistingKeyComponent(
        byte version,
        byte identifier,
        CardState state,
        CardConfiguration config
    )
    {
        if (
            state.InstalledKeyComponents.TryGetValue(
                new KeyReference(version, identifier),
                out var component
            )
        )
            return component;

        IKeySet? keySet =
            state.InstalledKeys.GetValueOrDefault(version)
            ?? config.StaticKeys.GetValueOrDefault(version);
        if (keySet is null)
            return Maybe<StoredKeyComponent>.None;
        int offset = identifier - keySet.KeyId;
        byte[]? value = offset switch
        {
            0 => keySet.EncKey,
            1 => keySet.MacKey,
            2 => keySet.DekKey,
            _ => null,
        };
        if (value is null)
            return Maybe<StoredKeyComponent>.None;
        byte type = keySet is Scp03KeySet ? (byte)0x88 : (byte)0x80;
        byte[] kcv = global::Gp4Net.Services.GlobalPlatform.KeyChange.CalculateKcv(
            value,
            type == 0x88
        );
        return new StoredKeyComponent(type, value.ToImmutableArray(), kcv.ToImmutableArray());
    }

    /// <summary>
    /// Represents parsed PUT KEY command data including KCVs.
    /// </summary>
    private sealed record PutKeyComponent(byte Type, byte[] Value, byte[] CheckValue);

    private sealed record PutKeyData(ImmutableArray<PutKeyComponent> Components)
    {
        public int KeyCount => Components.Length;
    }

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

        byte p2 = command[3];
        byte lc = command[4];

        if (command.Length < 5 + lc)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.WrongLength()
            );

        byte[] data = new byte[lc];
        Array.Copy(command, 5, data, 0, lc);

        bool isLastBlock = (p1 & 0x80) != 0;
        byte encryption = (byte)(p1 & 0x60);
        byte structure = (byte)(p1 & 0x18);
        if (!isLastBlock || p2 != 0x00)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.ConditionsNotSatisfied()
            );
        if (encryption != 0x00)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.ConditionsNotSatisfied()
            );

        return structure switch
        {
            0x08 => StoreSingleDataObject(data, state, isDgi: true),
            0x10 => StoreSingleDataObject(data, state, isDgi: false),
            _
                => Result.Failure<(ApduResponse, CardState), SmartCardError>(
                    SmartCardError.IncorrectP1P2()
                ),
        };
    }

    private static Result<(ApduResponse, CardState), SmartCardError> StoreSingleDataObject(
        byte[] data,
        CardState state,
        bool isDgi
    )
    {
        if (data.Length < 3)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.InvalidData("STORE DATA object is incomplete")
            );

        int tagLength = isDgi || (data[0] & 0x1F) == 0x1F ? 2 : 1;
        if (data.Length <= tagLength)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.InvalidData("STORE DATA object has no length")
            );

        ushort tag = tagLength == 2 ? (ushort)(data[0] << 8 | data[1]) : data[0];
        int lengthOffset = tagLength;
        int valueOffset = lengthOffset + 1;
        int valueLength = data[lengthOffset];
        if (valueLength == 0xFF && isDgi)
        {
            if (data.Length < valueOffset + 2)
                return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                    SmartCardError.InvalidData("STORE DATA extended DGI length is incomplete")
                );
            valueLength = data[valueOffset] << 8 | data[valueOffset + 1];
            valueOffset += 2;
        }
        else if ((valueLength & 0x80) != 0)
        {
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.InvalidData("Unsupported STORE DATA length encoding")
            );
        }

        if (valueOffset + valueLength != data.Length)
            return Result.Failure<(ApduResponse, CardState), SmartCardError>(
                SmartCardError.InvalidData("STORE DATA object length does not match its value")
            );

        byte[] value = data.AsSpan(valueOffset, valueLength).ToArray();
        CardState updated = state.WithDataObject(tag, value);
        if (tag == 0x7F0D && value.Length == 1)
            updated = updated.WithDefaultKeyVersion(value[0]);
        return CreateSuccessResponse(updated);
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
        CardLogging logging
    )
    {
        // Use SCP-specific processors for GP compliance
        return state.ScpVersion switch
        {
            0x02
                => Scp02CommandProcessors.ProcessScp02InitializeUpdate(
                    command,
                    state,
                    config,
                    rngContext,
                    logging
                ),
            0x03
                => Scp03CommandProcessors.ProcessScp03InitializeUpdate(
                    command,
                    state,
                    config,
                    rngContext,
                    logging.Logger
                ),
            _
                => Result.Failure<(ApduResponse, CardState), SmartCardError>(
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
        CardLogging logging
    )
    {
        // Use SCP-specific processors for better error handling and GP compliance
        return state.ScpVersion switch
        {
            0x02
                => Scp02CommandProcessors.ProcessScp02ExternalAuthenticate(
                    command,
                    state,
                    config,
                    rngContext,
                    logging
                ),
            0x03
                => Scp03CommandProcessors.ProcessScp03ExternalAuthenticate(
                    command,
                    state,
                    config,
                    rngContext,
                    logging
                ),
            _
                => Result.Failure<(ApduResponse, CardState), SmartCardError>(
                    SmartCardError.ConditionsNotSatisfied()
                ),
        };
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
        CardLogging logging
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
            (new ApduResponse(responseData, Constants.Constants.StatusWords.Success), newState)
        );
    }

    /// <summary>
    /// Calculates AES Key Check Value (KCV) per GlobalPlatform specification.
    /// KCV is the first 3 bytes of AES-ECB encryption of 16 zero bytes.
    /// Uses CryptoOperations for consistent cryptographic operations.
    /// </summary>
    private static Result<byte[], SmartCardError> CalculateAesKcv(byte[] key)
    {
        // Per GlobalPlatform: KCV = first 3 bytes of AES-ECB(key, 16 zero bytes)
        byte[] zeroBlock = new byte[16]; // All zeros

        // Keep AES encryption aligned with the shared cryptographic operations.
        return CryptoOperations
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
        CardConfiguration config,
        IRngContext rngContext,
        CardLogging logging
    )
    {
        bool isIssuerSecurityDomainSelected = state.ApplicationRegistry.Match(
            registry =>
                registry.SelectedApplicationAid.Match(
                    aid => aid.AsSpan().SequenceEqual(config.IsdAid),
                    () => false
                ),
            () => false
        );
        Result<(ApduResponse, CardState), SmartCardError> managementResult =
            isIssuerSecurityDomainSelected
                ? command[1] switch
                {
                    Ins.INITIALIZE_UPDATE
                        => ProcessInitializeUpdateWithCorrectScp(
                            command,
                            state,
                            config,
                            rngContext,
                            logging
                        ),
                    Gp4Net.Constants.Apdu.Instructions.EXTERNAL_AUTHENTICATE
                        => ProcessExternalAuthenticateWithCorrectScp(
                            command,
                            state,
                            config,
                            rngContext,
                            logging
                        ),
                    Ins.INSTALL => ProcessInstallCommand(command, state, config),
                    Ins.LOAD => ProcessLoadCommand(command, state, config),
                    Ins.DELETE => ProcessDeleteCommand(command, state, config, logging),
                    Ins.PUT_KEY => ProcessPutKeyCommand(command, state, config),
                    Ins.STORE_DATA => ProcessStoreDataCommand(command, state, config),
                    Ins.GET_STATUS => ProcessGetStatusCommand(command, state, config),
                    Ins.SET_STATUS => ProcessSetStatusCommand(command, state),
                    _
                        => Result.Failure<(ApduResponse, CardState), SmartCardError>(
                            SmartCardError.InstructionNotSupported()
                        ),
                }
                : Result.Failure<(ApduResponse, CardState), SmartCardError>(
                    SmartCardError.InstructionNotSupported()
                );

        if (managementResult.IsSuccess)
            return managementResult.Bind(result =>
                SynchronizeApplicationRegistry(result.Item2, config)
                    .Map(synchronized => (result.Item1, synchronized))
            );

        if (
            managementResult.Error.StatusWord != SmartCardError.InstructionNotSupported().StatusWord
        )
            return managementResult;

        return state.ApplicationRegistry.Match(
            registry =>
            {
                logging.LogDebug(
                    "Routing command INS=0x{Ins:X2} to application registry",
                    command[1]
                );

                return registry
                    .RouteCommand(command, state, config, rngContext)
                    .Map(result =>
                    {
                        var (updatedRegistry, apduResponse, updatedState) = result;
                        var newState = updatedState.WithApplicationRegistry(updatedRegistry);

                        // Convert to Core.ApduResponse format
                        var coreResponse = new ApduResponse(
                            apduResponse.Data.IsDefaultOrEmpty ? [] : apduResponse.Data.ToArray(),
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

    private static Result<(ApduResponse, CardState), SmartCardError> ProcessGetStatusCommand(
        byte[] command,
        CardState state,
        CardConfiguration config
    )
    {
        if (command.Length < 5)
            return Result.Success<(ApduResponse, CardState), SmartCardError>(
                (ApduResponse.Error(0x6700), state)
            );

        byte p1 = command[2];
        byte p2 = command[3];
        if (p1 is not (0x80 or 0x40 or 0x20 or 0x10) || (p2 & 0xFC) != 0)
            return Result.Success<(ApduResponse, CardState), SmartCardError>(
                (ApduResponse.Error(0x6A86), state)
            );

        byte lc = command[4];
        if (command.Length < 5 + lc)
            return Result.Success<(ApduResponse, CardState), SmartCardError>(
                (ApduResponse.Error(0x6700), state)
            );

        bool getNext = (p2 & 0x01) != 0;
        if (getNext)
        {
            if (!state.PendingGetStatus.HasValue || state.PendingGetStatus.Value.Subset != p1)
                return Result.Success<(ApduResponse, CardState), SmartCardError>(
                    (ApduResponse.Error(0x6A83), state)
                );
            return CreateGetStatusPage(state.PendingGetStatus.Value, state);
        }

        byte[] aidFilter = ParseGetStatusAidFilter(command.AsSpan(5, lc));
        IEnumerable<byte[]> entries = p1 switch
        {
            0x80
                =>
                [
                    EncodeRegistryEntry(
                        config.IsdAid,
                        (byte)state.CardLifecycleState,
                        [(byte)Privilege.SecurityDomain, 0xFE, 0x80],
                        [],
                        []
                    )
                ],
            0x40
                => state.Applications.Values.Select(app =>
                    EncodeRegistryEntry(
                        app.Aid,
                        app.LifecycleState,
                        [(byte)app.Privileges],
                        config.IsdAid,
                        [app.ExecutableModuleAid]
                    )
                ),
            0x20
                => state.LoadFiles.Select(loadFile =>
                    EncodeRegistryEntry(
                        loadFile.Aid,
                        loadFile.LifecycleState,
                        [],
                        loadFile.AssociatedSecurityDomainAid,
                        []
                    )
                ),
            0x10
                => state.LoadFiles.Select(loadFile =>
                    EncodeRegistryEntry(
                        loadFile.Aid,
                        loadFile.LifecycleState,
                        [],
                        loadFile.AssociatedSecurityDomainAid,
                        loadFile.ExecutableModules.Select(module => module.Aid)
                    )
                ),
            _ => [],
        };

        ImmutableList<byte[]> matchingEntries = entries
            .Where(entry => aidFilter.Length == 0 || RegistryEntryMatchesAid(entry, aidFilter))
            .ToImmutableList();
        return CreateGetStatusPage(new PendingGetStatusOperation(p1, matchingEntries, 0), state);
    }

    private static Result<(ApduResponse, CardState), SmartCardError> CreateGetStatusPage(
        PendingGetStatusOperation operation,
        CardState state
    )
    {
        const int maximumPageLength = 240;
        List<byte> data = [];
        int nextIndex = operation.NextIndex;
        while (nextIndex < operation.Entries.Count)
        {
            byte[] entry = operation.Entries[nextIndex];
            if (data.Count > 0 && data.Count + entry.Length > maximumPageLength)
                break;
            data.AddRange(entry);
            nextIndex++;
        }

        bool hasMore = nextIndex < operation.Entries.Count;
        CardState updated = state with
        {
            PendingGetStatus = hasMore
                ? Maybe<PendingGetStatusOperation>.From(operation with { NextIndex = nextIndex })
                : Maybe<PendingGetStatusOperation>.None,
        };
        ushort status = hasMore ? (ushort)0x6310 : Constants.Constants.StatusWords.Success;
        return Result.Success<(ApduResponse, CardState), SmartCardError>(
            (new ApduResponse(data.ToArray(), status), updated)
        );
    }

    private static byte[] ParseGetStatusAidFilter(ReadOnlySpan<byte> data) =>
        data.Length >= 2 && data[0] == 0x4F && data[1] <= data.Length - 2
            ? data.Slice(2, data[1]).ToArray()
            : [];

    private static bool RegistryEntryMatchesAid(byte[] entry, byte[] aid) =>
        entry.AsSpan().IndexOf(aid) >= 0;

    private static byte[] EncodeRegistryEntry(
        byte[] aid,
        byte lifecycle,
        byte[] privileges,
        byte[] associatedSecurityDomain,
        IEnumerable<byte[]> modules
    )
    {
        List<byte> content = [];
        AppendSimpleTlv(content, 0x4F, aid);
        content.AddRange([0x9F, 0x70, 0x01, lifecycle]);
        if (privileges.Length > 0)
            AppendSimpleTlv(content, 0xC5, privileges);
        if (associatedSecurityDomain.Length > 0)
            AppendSimpleTlv(content, 0xCC, associatedSecurityDomain);
        foreach (byte[] module in modules)
            AppendSimpleTlv(content, 0x84, module);

        List<byte> result = [0xE3];
        AppendBerLength(result, content.Count);
        result.AddRange(content);
        return [.. result];
    }

    private static void AppendSimpleTlv(List<byte> target, byte tag, byte[] value)
    {
        target.Add(tag);
        AppendBerLength(target, value.Length);
        target.AddRange(value);
    }

    private static void AppendBerLength(List<byte> target, int length)
    {
        if (length < 0x80)
            target.Add((byte)length);
        else if (length <= 0xFF)
            target.AddRange([0x81, (byte)length]);
        else
            target.AddRange([0x82, (byte)(length >> 8), (byte)length]);
    }

    private static Result<(ApduResponse, CardState), SmartCardError> ProcessSetStatusCommand(
        byte[] command,
        CardState state
    )
    {
        if (command.Length < 4)
            return Result.Success<(ApduResponse, CardState), SmartCardError>(
                (ApduResponse.Error(0x6700), state)
            );

        byte p1 = command[2];
        byte newLifecycle = command[3];
        byte[] aid =
            command.Length >= 5 && command[4] > 0 && command.Length >= 5 + command[4]
                ? command.AsSpan(5, command[4]).ToArray()
                : [];

        if (p1 == 0x80)
        {
            if (!GlobalPlatformLifecycle.IsCardState(newLifecycle))
                return Result.Success<(ApduResponse, CardState), SmartCardError>(
                    (ApduResponse.Error(0x6A86), state)
                );

            var transition = state.WithCardLifecycleState((CardLifecycleState)newLifecycle);
            return transition.Match(
                updated =>
                    Result.Success<(ApduResponse, CardState), SmartCardError>(
                        (ApduResponse.Success([]), updated)
                    ),
                _ =>
                    Result.Success<(ApduResponse, CardState), SmartCardError>(
                        (ApduResponse.Error(0x6985), state)
                    )
            );
        }

        if (p1 is not (0x40 or 0x60) || aid.Length == 0)
            return Result.Success<(ApduResponse, CardState), SmartCardError>(
                (ApduResponse.Error(0x6A86), state)
            );

        string key = Convert.ToHexString(aid);
        if (!state.Applications.TryGetValue(key, out InstalledApplication? application))
            return Result.Success<(ApduResponse, CardState), SmartCardError>(
                (ApduResponse.Error(0x6A88), state)
            );
        if (!GlobalPlatformLifecycle.IsApplicationState(newLifecycle))
            return Result.Success<(ApduResponse, CardState), SmartCardError>(
                (ApduResponse.Error(0x6A86), state)
            );

        var updatedApplication = application with { LifecycleState = newLifecycle };
        var updatedState = state with
        {
            Applications = state.Applications.SetItem(key, updatedApplication),
        };
        return Result.Success<(ApduResponse, CardState), SmartCardError>(
            (ApduResponse.Success([]), updatedState)
        );
    }

    private static Result<CardState, SmartCardError> SynchronizeApplicationRegistry(
        CardState state,
        CardConfiguration config
    )
    {
        if (state.ApplicationRegistry.HasNoValue)
            return Result.Failure<CardState, SmartCardError>(
                SmartCardError.UnexpectedError("Application registry is unavailable")
            );

        ApplicationRegistry registry = state.ApplicationRegistry.Value;
        var installedAids = state
            .Applications.Values.Select(app => app.Aid.ToImmutableArray())
            .ToImmutableList();

        foreach (var existing in registry.Applications.Values.OfType<ManagedApplication>())
        {
            if (installedAids.Any(aid => aid.SequenceEqual(existing.Aid)))
                continue;

            var removal = registry.RemoveApplication(existing.Aid);
            if (removal.IsFailure)
                return Result.Failure<CardState, SmartCardError>(removal.Error);
            registry = removal.Value;
        }

        foreach (InstalledApplication installed in state.Applications.Values)
        {
            var aid = installed.Aid.ToImmutableArray();
            var managed = new ManagedApplication(
                aid,
                installed.ExecutableModuleAid.ToImmutableArray(),
                installed.LifecycleState,
                installed.Privileges,
                config.IsdAid.ToImmutableArray(),
                Maybe<IAppletRuntime>.None
            );

            var update = registry.Applications.ContainsKey(aid)
                ? registry.UpdateApplication(managed)
                : registry.AddApplication(managed);
            if (update.IsFailure)
                return Result.Failure<CardState, SmartCardError>(update.Error);
            registry = update.Value;
        }

        return Result.Success<CardState, SmartCardError>(state.WithApplicationRegistry(registry));
    }

    /// <summary>
    /// Applies SCP security to incoming command.
    /// </summary>
    private static Result<
        (ParsedCommand command, CardState state),
        SmartCardError
    > ApplyScpSecurity(ParsedCommand cmd, CardState state, CardLogging logging)
    {
        if (state.IsSecureChannelAborted)
        {
            bool terminatesSession =
                cmd.Ins == Constants.Constants.Scp.Common.INITIALIZE_UPDATE_INS
                || cmd.Ins == Gp4Net.Constants.Apdu.Instructions.SELECT;

            if (!terminatesSession)
                return Result.Failure<(ParsedCommand, CardState), SmartCardError>(
                    SmartCardError.SecurityStatusNotSatisfied()
                );

            state = state.WithoutSecureChannel();
        }

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
            return Result.Failure<(ParsedCommand, CardState), SmartCardError>(
                securityValidationResult.Error
            );
        }

        logging.LogDebug(
            "SCP validation passed for INS=0x{Ins:X2}, security level=0x{Level:X2}",
            cmd.Ins,
            state.SecurityLevel
        );

        if (
            cmd.Ins == Constants.Constants.Scp.Common.EXTERNAL_AUTHENTICATE_INS
            || !state.SecureChannel.HasValue
        )
            return Result.Success<(ParsedCommand, CardState), SmartCardError>((cmd, state));

        // GP Card Specification v2.3.1, E.3.3 and E.4.4-E.4.6; SCP03 Amendment D
        // v1.1.2, 6.2.4-6.2.6: verify C-MAC, remove it, then decrypt C-ENC command data.
        return global::Gp4Net
            .Services.ScpOperations.Security.RemoveCommandSecurity(
                new CommandAPDU(cmd.FullCommand),
                state.SecureChannel.Value
            )
            .Bind(result =>
                ParsedCommand
                    .Parse(result.plaintextCommand.BinaryCommand)
                    .MapError(SmartCardError.InvalidData)
                    .Map(plaintext => (plaintext, state.WithUpdatedSecureChannel(result.newState)))
            );
    }

    /// <summary>
    /// Creates a successful APDU response with the provided card state.
    /// Helper method to eliminate repetitive Result.Success patterns.
    /// </summary>
    /// <param name="state">The card state to include in the response.</param>
    /// <returns>A successful result with an empty APDU response and the provided state.</returns>
    private static Result<(ApduResponse, CardState), SmartCardError> CreateSuccessResponse(
        CardState state
    ) =>
        Result.Success<(ApduResponse, CardState), SmartCardError>(
            (new ApduResponse([], Constants.Constants.StatusWords.Success), state)
        );

    private static Result<CardState, SmartCardError> EnsureApplicationRegistry(
        CardState state,
        CardConfiguration config
    )
    {
        if (state.ApplicationRegistry.HasValue)
        {
            return Result.Success<CardState, SmartCardError>(state);
        }

        return CardStateTransitions.InitializeApplicationRegistryWithDataObjects(
            state,
            config.IsdAid.ToImmutableArray(),
            config.DefaultDataObjects
        );
    }
}
