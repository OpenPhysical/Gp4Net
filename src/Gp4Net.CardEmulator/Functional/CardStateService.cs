using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Applications;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Implementation of immutable card state management service.
/// All operations are pure functions that take existing state and return new state.
/// Follows functional programming principles with no side effects or mutations.
/// </summary>
[PublicAPI]
public sealed class CardStateService : ICardStateService
{
    private readonly Maybe<ILogger> _logger;

    /// <summary>
    /// Initializes a new instance of the CardStateService.
    /// </summary>
    /// <param name="logger">Optional logger for debugging state transitions.</param>
    public CardStateService(Maybe<ILogger> logger = default)
    {
        _logger = logger;
    }

    /// <inheritdoc />
    public Result<CardState, SmartCardError> CreateInitialState()
    {
        return CardState.Create()
            .Bind(initialState => InitializeApplicationRegistry(initialState))
            .Tap(_ => LogStateTransition("Created initial card state"));
    }

    /// <inheritdoc />
    public Result<CardState, SmartCardError> CreateInitialState(CardUuid uuid)
    {
        var initialState = CardState.CreateWithUuid(uuid);
        return InitializeApplicationRegistry(initialState)
            .Tap(_ => LogStateTransition($"Created initial card state with UUID {uuid}"));
    }

    /// <inheritdoc />
    public Result<CardState, SmartCardError> ApplyCommand(
        CardState currentState,
        ApduCommand command,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        LogStateTransition($"Applying command INS=0x{command.Ins:X2} to card state");

        return ValidateState(currentState)
            .Bind(_ => ValidateCommandPreconditions(currentState, command, config))
            .Bind(_ => ProcessCommand(currentState, command, config, rngContext))
            .Bind(newState => ValidateState(newState).Map(_ => newState))
            .Tap(newState => LogStateTransition($"Command applied successfully, new security level: 0x{newState.SecurityLevel:X2}"));
    }

    /// <inheritdoc />
    public Maybe<IApplication> GetSelectedApplication(CardState state)
    {
        return state.ApplicationRegistry.Match(
            registry => registry.SelectedApplicationAid.Match(
                selectedAid => registry.Applications.TryGetValue(selectedAid, out var app) 
                    ? Maybe<IApplication>.From(app) 
                    : Maybe<IApplication>.None,
                () => Maybe<IApplication>.None
            ),
            () => Maybe<IApplication>.None
        );
    }

    /// <inheritdoc />
    public Maybe<IApplication> GetApplicationByAid(CardState state, ImmutableArray<byte> aid)
    {
        return state.ApplicationRegistry.Match(
            registry => registry.Applications.TryGetValue(aid, out var app) 
                ? Maybe<IApplication>.From(app) 
                : Maybe<IApplication>.None,
            () => Maybe<IApplication>.None
        );
    }

    /// <inheritdoc />
    public Result<CardState, SmartCardError> SelectApplication(
        CardState currentState,
        ImmutableArray<byte> aid
    )
    {
        LogStateTransition($"Selecting application with AID: {Convert.ToHexString(aid.ToArray())}");

        return currentState.ApplicationRegistry.Match(
            registry => registry.Applications.ContainsKey(aid)
                ? Result.Success<CardState, SmartCardError>(
                    currentState with
                    {
                        ApplicationRegistry = Maybe<ApplicationRegistry>.From(
                            registry with
                            {
                                SelectedApplicationAid = Maybe<ImmutableArray<byte>>.From(aid)
                            }
                        )
                    }
                )
                : Result.Failure<CardState, SmartCardError>(
                    SmartCardError.FileNotFound()
                ),
            () => Result.Failure<CardState, SmartCardError>(
                SmartCardError.UnexpectedError("No application registry available")
            )
        );
    }

    /// <inheritdoc />
    public Result<CardState, SmartCardError> UpdateSecureChannel(
        CardState currentState,
        SecureChannelState secureChannelState
    )
    {
        LogStateTransition($"Updating secure channel to security level 0x{(byte)secureChannelState.SecurityLevel:X2}");

        return ValidateSecureChannelState(secureChannelState)
            .Map(_ => currentState.WithSecureChannel(secureChannelState))
            .Tap(_ => LogStateTransition("Secure channel updated successfully"));
    }

    /// <inheritdoc />
    public CardState ClearSecureChannel(CardState currentState)
    {
        LogStateTransition("Clearing secure channel state");
        return currentState.WithoutSecureChannel();
    }

    /// <inheritdoc />
    public Result<CardState, SmartCardError> InstallApplication(
        CardState currentState,
        ImmutableArray<byte> aid,
        IApplication application
    )
    {
        LogStateTransition($"Installing application with AID: {Convert.ToHexString(aid.ToArray())}");

        return currentState.ApplicationRegistry.Match(
            registry => registry.AddApplication(application)
                .Map(updatedRegistry => currentState.WithApplicationRegistry(updatedRegistry)),
            () => Result.Failure<CardState, SmartCardError>(
                SmartCardError.UnexpectedError("No application registry available")
            )
        );
    }

    /// <inheritdoc />
    public CardState RemoveApplication(CardState currentState, ImmutableArray<byte> aid)
    {
        LogStateTransition($"Removing application with AID: {Convert.ToHexString(aid.ToArray())}");

        return currentState.ApplicationRegistry.Match(
            registry => registry.RemoveApplication(aid)
                .Match(
                    updatedRegistry => currentState.WithApplicationRegistry(updatedRegistry),
                    _ => currentState // If removal fails, return unchanged state
                ),
            () => currentState // If no registry, return unchanged state
        );
    }

    /// <inheritdoc />
    public CardState ResetCard(CardState currentState)
    {
        LogStateTransition("Resetting card state to initial conditions");
        return currentState.Reset();
    }

    /// <inheritdoc />
    public Result<UnitResult<SmartCardError>, SmartCardError> ValidateState(CardState state)
    {
        return ValidateCardUuid(state)
            .Bind(_ => ValidateSecureChannelConsistency(state))
            .Bind(_ => ValidateApplicationRegistryConsistency(state))
            .Bind(_ => ValidateSequenceCounters(state))
            .Map(_ => UnitResult.Success<SmartCardError>());
    }

    #region Private Methods

    /// <summary>
    /// Initializes the application registry with ISD as default application.
    /// </summary>
    private static Result<CardState, SmartCardError> InitializeApplicationRegistry(CardState state)
    {
        // Use standard GP ISD AID
        var isdAid = new byte[] { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 }.ToImmutableArray();
        
        return ApplicationRegistry.CreateWithIsd(isdAid, state.ScpVersion, (byte)state.ScpImplementation)
            .Map(registry => state.WithApplicationRegistry(registry));
    }
    
    /// <summary>
    /// Initializes the application registry with custom ISD AID and data objects.
    /// </summary>
    public static Result<CardState, SmartCardError> InitializeApplicationRegistryWithDataObjects(
        CardState state,
        ImmutableArray<byte> isdAid,
        ImmutableDictionary<ushort, byte[]> dataObjects)
    {
        return ApplicationRegistry.CreateWithIsdAndDataObjects(isdAid, dataObjects, state.ScpVersion, (byte)state.ScpImplementation)
            .Map(registry => state.WithApplicationRegistry(registry));
    }

    /// <summary>
    /// Processes a command using functional command routing.
    /// Routes commands to appropriate processors based on instruction type.
    /// </summary>
    private static Result<CardState, SmartCardError> ProcessCommand(
        CardState currentState,
        ApduCommand command,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        return currentState.ApplicationRegistry.Match(
            registry => ProcessCommandWithRegistry(currentState, command, registry, rngContext),
            () => Result.Failure<CardState, SmartCardError>(
                SmartCardError.UnexpectedError("No application registry for command processing")
            )
        );
    }

    /// <summary>
    /// Processes command with application registry routing.
    /// </summary>
    private static Result<CardState, SmartCardError> ProcessCommandWithRegistry(
        CardState currentState,
        ApduCommand command,
        ApplicationRegistry registry,
        IRngContext rngContext
    )
    {
        return registry.RouteCommand(command.RawBytes, currentState, rngContext)
            .Map(result =>
            {
                var (updatedRegistry, _) = result;
                return currentState.WithApplicationRegistry(updatedRegistry);
            });
    }

    /// <summary>
    /// Validates command preconditions before processing.
    /// </summary>
    private static Result<UnitResult<SmartCardError>, SmartCardError> ValidateCommandPreconditions(
        CardState state,
        ApduCommand command,
        CardConfiguration config
    )
    {
        return ValidateInstructionSupported(command.Ins, config)
            .Bind(_ => ValidateSecurityRequirements(command.Ins, state))
            .Map(_ => UnitResult.Success<SmartCardError>());
    }

    /// <summary>
    /// Validates that an instruction is supported by the card configuration.
    /// </summary>
    private static Result<UnitResult<SmartCardError>, SmartCardError> ValidateInstructionSupported(
        byte instruction,
        CardConfiguration config
    )
    {
        return config.SupportedInstructions.IsSupported(instruction)
            ? Result.Success<UnitResult<SmartCardError>, SmartCardError>(UnitResult.Success<SmartCardError>())
            : Result.Failure<UnitResult<SmartCardError>, SmartCardError>(
                SmartCardError.InstructionNotSupported()
            );
    }

    /// <summary>
    /// Validates security requirements for a command.
    /// </summary>
    private static Result<UnitResult<SmartCardError>, SmartCardError> ValidateSecurityRequirements(
        byte instruction,
        CardState state
    )
    {
        // Check if instruction requires authenticated security level
        var requiresAuthentication = instruction switch
        {
            Ins.GET_STATUS => true,
            Ins.INSTALL => true,
            Ins.LOAD => true,
            Ins.DELETE => true,
            Ins.PUT_KEY => true,
            Ins.STORE_DATA => true,
            Ins.SET_STATUS => true,
            _ => false
        };

        return !requiresAuthentication || state.SecurityLevel >= 0x01
            ? Result.Success<UnitResult<SmartCardError>, SmartCardError>(UnitResult.Success<SmartCardError>())
            : Result.Failure<UnitResult<SmartCardError>, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied()
            );
    }

    /// <summary>
    /// Validates that the card UUID is valid.
    /// </summary>
    private static Result<UnitResult<SmartCardError>, SmartCardError> ValidateCardUuid(CardState state)
    {
        return state.Uuid.ToByteArray().Length == 16
            ? Result.Success<UnitResult<SmartCardError>, SmartCardError>(UnitResult.Success<SmartCardError>())
            : Result.Failure<UnitResult<SmartCardError>, SmartCardError>(
                SmartCardError.InvalidData("Card UUID must be 16 bytes")
            );
    }

    /// <summary>
    /// Validates secure channel state consistency.
    /// </summary>
    private static Result<UnitResult<SmartCardError>, SmartCardError> ValidateSecureChannelConsistency(CardState state)
    {
        return state.SecureChannel.Match(
            sc => sc.SessionKeys.SEnc.Length == 16 && sc.SessionKeys.SMac.Length == 16
                ? Result.Success<UnitResult<SmartCardError>, SmartCardError>(UnitResult.Success<SmartCardError>())
                : Result.Failure<UnitResult<SmartCardError>, SmartCardError>(
                    SmartCardError.InvalidData("Session keys must be 16 bytes each")
                ),
            () => Result.Success<UnitResult<SmartCardError>, SmartCardError>(UnitResult.Success<SmartCardError>())
        );
    }

    /// <summary>
    /// Validates application registry consistency.
    /// </summary>
    private static Result<UnitResult<SmartCardError>, SmartCardError> ValidateApplicationRegistryConsistency(CardState state)
    {
        return state.ApplicationRegistry.Match(
            registry => registry.SelectedApplicationAid.Match(
                selectedAid => registry.Applications.ContainsKey(selectedAid)
                    ? Result.Success<UnitResult<SmartCardError>, SmartCardError>(UnitResult.Success<SmartCardError>())
                    : Result.Failure<UnitResult<SmartCardError>, SmartCardError>(
                        SmartCardError.ConditionsNotSatisfied()
                    ),
                () => Result.Success<UnitResult<SmartCardError>, SmartCardError>(UnitResult.Success<SmartCardError>())
            ),
            () => Result.Success<UnitResult<SmartCardError>, SmartCardError>(UnitResult.Success<SmartCardError>())
        );
    }

    /// <summary>
    /// Validates sequence counters are within valid ranges.
    /// Uses explicit functional validation without unsafe value access.
    /// </summary>
    private static Result<UnitResult<SmartCardError>, SmartCardError> ValidateSequenceCounters(CardState state)
    {
        var isValidCounter = (byte[] counterBytes) => counterBytes.Length == 2 || counterBytes.Length == 3;
        
        var hasInvalidCounters = state.SequenceCounters
            .Select(kvp => kvp.Value)
            .Any(counterBytes => !isValidCounter(counterBytes));

        return !hasInvalidCounters
            ? Result.Success<UnitResult<SmartCardError>, SmartCardError>(UnitResult.Success<SmartCardError>())
            : Result.Failure<UnitResult<SmartCardError>, SmartCardError>(
                SmartCardError.InvalidData("Sequence counters must be 2 or 3 bytes")
            );
    }

    /// <summary>
    /// Validates secure channel state before updating.
    /// </summary>
    private static Result<UnitResult<SmartCardError>, SmartCardError> ValidateSecureChannelState(SecureChannelState state)
    {
        return state.SessionKeys.SEnc.Length == 16 && state.SessionKeys.SMac.Length == 16
            ? Result.Success<UnitResult<SmartCardError>, SmartCardError>(UnitResult.Success<SmartCardError>())
            : Result.Failure<UnitResult<SmartCardError>, SmartCardError>(
                SmartCardError.InvalidArgument("Session keys must be 16 bytes each")
            );
    }

    /// <summary>
    /// Logs state transitions if logger is available.
    /// </summary>
    private void LogStateTransition(string message)
    {
        _logger.Match(
            logger => logger.LogDebug("[CardStateService] {Message}", message),
            () => { } // No logging if no logger
        );
    }

    #endregion
}