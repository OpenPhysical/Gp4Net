using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Applications;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Service interface for immutable card state management.
/// All operations are pure functions that take existing state and return new state.
/// No side effects or mutations - follows functional programming principles.
/// </summary>
[PublicAPI]
public interface ICardStateService
{
    /// <summary>
    /// Creates the initial card state with default configuration.
    /// Per GP Card Spec v2.3.1: ISD is implicitly selected on creation.
    /// </summary>
    /// <returns>Initial card state with ISD selected, or error if creation fails.</returns>
    Result<CardState, SmartCardError> CreateInitialState();

    /// <summary>
    /// Creates initial state with specific UUID (for testing and deserialization).
    /// </summary>
    /// <param name="uuid">The UUID to use for the card.</param>
    /// <returns>Initial card state with the specified UUID.</returns>
    Result<CardState, SmartCardError> CreateInitialState(CardUuid uuid);

    /// <summary>
    /// Applies an APDU command to the current state, producing a new state.
    /// This is the main state transition function for command processing.
    /// </summary>
    /// <param name="currentState">The current immutable card state.</param>
    /// <param name="command">The APDU command to apply.</param>
    /// <param name="config">The card configuration for validation.</param>
    /// <param name="rngContext">Random number generator context.</param>
    /// <returns>New card state after applying the command, or error.</returns>
    Result<CardState, SmartCardError> ApplyCommand(
        CardState currentState,
        ApduCommand command,
        CardConfiguration config,
        IRngContext rngContext
    );

    /// <summary>
    /// Gets the currently selected application from the card state.
    /// Uses Maybe to represent optional presence of selected application.
    /// </summary>
    /// <param name="state">The card state to query.</param>
    /// <returns>Maybe containing selected application, or None if no application selected.</returns>
    Maybe<IApplication> GetSelectedApplication(CardState state);

    /// <summary>
    /// Gets an application by AID from the card state.
    /// </summary>
    /// <param name="state">The card state to query.</param>
    /// <param name="aid">The Application Identifier to look up.</param>
    /// <returns>Maybe containing the application if found, or None.</returns>
    Maybe<IApplication> GetApplicationByAid(CardState state, ImmutableArray<byte> aid);

    /// <summary>
    /// Selects an application by AID, returning new state with updated selection.
    /// </summary>
    /// <param name="currentState">The current card state.</param>
    /// <param name="aid">The Application Identifier to select.</param>
    /// <returns>New card state with application selected, or error if not found.</returns>
    Result<CardState, SmartCardError> SelectApplication(
        CardState currentState,
        ImmutableArray<byte> aid
    );

    /// <summary>
    /// Updates the secure channel state, producing new card state.
    /// Used when secure channel parameters change (counters, MAC chaining, etc.).
    /// </summary>
    /// <param name="currentState">The current card state.</param>
    /// <param name="secureChannelState">The new secure channel state.</param>
    /// <returns>New card state with updated secure channel.</returns>
    Result<CardState, SmartCardError> UpdateSecureChannel(
        CardState currentState,
        SecureChannelState secureChannelState
    );

    /// <summary>
    /// Clears the secure channel state, returning to non-authenticated state.
    /// </summary>
    /// <param name="currentState">The current card state.</param>
    /// <returns>New card state with secure channel cleared.</returns>
    CardState ClearSecureChannel(CardState currentState);

    /// <summary>
    /// Installs a new application, returning updated card state.
    /// </summary>
    /// <param name="currentState">The current card state.</param>
    /// <param name="aid">The Application Identifier for the new application.</param>
    /// <param name="application">The application to install.</param>
    /// <returns>New card state with application installed, or error.</returns>
    Result<CardState, SmartCardError> InstallApplication(
        CardState currentState,
        ImmutableArray<byte> aid,
        IApplication application
    );

    /// <summary>
    /// Removes an application by AID, returning updated card state.
    /// </summary>
    /// <param name="currentState">The current card state.</param>
    /// <param name="aid">The Application Identifier to remove.</param>
    /// <returns>New card state with application removed.</returns>
    CardState RemoveApplication(CardState currentState, ImmutableArray<byte> aid);

    /// <summary>
    /// Resets the card state to initial conditions.
    /// Preserves installed applications, keys, and sequence counters but clears transient state.
    /// </summary>
    /// <param name="currentState">The current card state.</param>
    /// <returns>New card state in reset condition.</returns>
    CardState ResetCard(CardState currentState);

    /// <summary>
    /// Validates that a card state is internally consistent.
    /// Checks invariants like: selected application exists, secure channel state is valid, etc.
    /// </summary>
    /// <param name="state">The card state to validate.</param>
    /// <returns>Success if state is valid, error with description if invalid.</returns>
    Result<UnitResult<SmartCardError>, SmartCardError> ValidateState(CardState state);
}
