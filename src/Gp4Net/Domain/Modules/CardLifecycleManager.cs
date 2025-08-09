using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Transport;
using Gp4Net.Pipeline;

namespace Gp4Net.Domain.Modules;

/// <summary>
/// Pure functional module for managing card and application lifecycle states.
/// Handles operations like SET STATUS, DELETE, and lifecycle transitions.
/// </summary>
public static class CardLifecycleManager
{
    /// <summary>
    /// Changes the lifecycle state of an application or security domain.
    /// </summary>
    /// <param name="aid">The application identifier.</param>
    /// <param name="targetState">The target lifecycle state.</param>
    /// <param name="executeCommand">Function to execute APDU commands.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Success or error.</returns>
    public static async Task<Result<bool, SmartCardError>> SetLifecycleStateAsync(
        byte[] aid,
        LifecycleState targetState,
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        // Map lifecycle state to P1 parameter per GP specification
        Result<byte, SmartCardError> p1Result = MapLifecycleStateToP1(targetState);
        
        if (p1Result.IsFailure)
        {
            return Result.Failure<bool, SmartCardError>(p1Result.Error);
        }

        // Create SET STATUS command
        Result<SetStatusCommand, SmartCardError> cmdResult = 
            CommandFactory.CreateSetStatusCommand(aid, p1Result.Value);
        
        if (cmdResult.IsFailure)
        {
            return Result.Failure<bool, SmartCardError>(cmdResult.Error);
        }

        // Execute the command
        Result<CommandResponse, SmartCardError> response = 
            await executeCommand(cmdResult.Value, cancellationToken);
        
        if (response.IsFailure)
        {
            return Result.Failure<bool, SmartCardError>(response.Error);
        }

        return response.Value.IsSuccess
            ? Result.Success<bool, SmartCardError>(true)
            : Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidResponse($"SET STATUS failed with SW: {response.Value.StatusWord:X4}"));
    }

    /// <summary>
    /// Deletes an application or package from the card.
    /// </summary>
    /// <param name="aid">The application identifier to delete.</param>
    /// <param name="deleteRelated">Whether to delete related objects.</param>
    /// <param name="executeCommand">Function to execute APDU commands.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Success or error.</returns>
    public static async Task<Result<bool, SmartCardError>> DeleteApplicationAsync(
        byte[] aid,
        bool deleteRelated,
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        // Create DELETE command
        Result<DeleteCommand, SmartCardError> cmdResult = 
            CommandFactory.CreateDeleteCommand(aid, deleteRelated);
        
        if (cmdResult.IsFailure)
        {
            return Result.Failure<bool, SmartCardError>(cmdResult.Error);
        }

        // Execute the command
        Result<CommandResponse, SmartCardError> response = 
            await executeCommand(cmdResult.Value, cancellationToken);
        
        return response.IsSuccess
            ? ResponseParser.ParseDeleteResponse(response.Value)
            : Result.Failure<bool, SmartCardError>(response.Error);
    }

    /// <summary>
    /// Locks the card, preventing further modifications.
    /// </summary>
    /// <param name="executeCommand">Function to execute APDU commands.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Success or error.</returns>
    public static async Task<Result<bool, SmartCardError>> LockCardAsync(
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        // Card lock is setting the ISD to LOCKED state
        return await SetCardLifecycleStateAsync(
            CardLifecycleState.CardLocked,
            executeCommand,
            cancellationToken);
    }

    /// <summary>
    /// Terminates the card, making it permanently unusable.
    /// </summary>
    /// <param name="executeCommand">Function to execute APDU commands.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Success or error.</returns>
    public static async Task<Result<bool, SmartCardError>> TerminateCardAsync(
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        // Card termination is setting the ISD to TERMINATED state
        return await SetCardLifecycleStateAsync(
            CardLifecycleState.CardTerminated,
            executeCommand,
            cancellationToken);
    }

    /// <summary>
    /// Sets the card lifecycle state through the ISD.
    /// </summary>
    private static async Task<Result<bool, SmartCardError>> SetCardLifecycleStateAsync(
        CardLifecycleState targetState,
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken)
    {
        // Map card lifecycle state to P1 parameter
        byte p1 = targetState switch
        {
            CardLifecycleState.CardOpReady => 0x01,
            CardLifecycleState.CardInitialized => 0x07,
            CardLifecycleState.CardSecured => 0x0F,
            CardLifecycleState.CardLocked => 0x7F,
            CardLifecycleState.CardTerminated => 0xFF,
            _ => 0x00
        };

        if (p1 == 0x00)
        {
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument($"Unsupported card lifecycle state: {targetState}"));
        }

        // Create SET STATUS command for the card (no AID means card-level operation)
        Result<SetStatusCommand, SmartCardError> cmdResult = 
            CommandFactory.CreateSetStatusCommand(Array.Empty<byte>(), p1);
        
        if (cmdResult.IsFailure)
        {
            return Result.Failure<bool, SmartCardError>(cmdResult.Error);
        }

        // Execute the command
        Result<CommandResponse, SmartCardError> response = 
            await executeCommand(cmdResult.Value, cancellationToken);
        
        if (response.IsFailure)
        {
            return Result.Failure<bool, SmartCardError>(response.Error);
        }

        return response.Value.IsSuccess
            ? Result.Success<bool, SmartCardError>(true)
            : Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidResponse($"SET STATUS (Card) failed with SW: {response.Value.StatusWord:X4}"));
    }

    /// <summary>
    /// Maps application lifecycle state to SET STATUS P1 parameter.
    /// </summary>
    private static Result<byte, SmartCardError> MapLifecycleStateToP1(LifecycleState state) =>
        state switch
        {
            LifecycleState.Installed => Result.Success<byte, SmartCardError>(0x03),
            LifecycleState.Selectable => Result.Success<byte, SmartCardError>(0x07),
            LifecycleState.Personalized => Result.Success<byte, SmartCardError>(0x0F),
            LifecycleState.Locked => Result.Success<byte, SmartCardError>(0x83),
            _ => Result.Failure<byte, SmartCardError>(
                SmartCardError.InvalidArgument($"Cannot set lifecycle state to: {state}"))
        };

    /// <summary>
    /// Installs an application for installation.
    /// </summary>
    /// <param name="packageAid">The package AID.</param>
    /// <param name="moduleAid">The module AID.</param>
    /// <param name="applicationAid">The application AID.</param>
    /// <param name="privileges">The privileges to grant.</param>
    /// <param name="installParameters">Optional install parameters.</param>
    /// <param name="executeCommand">Function to execute APDU commands.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Success or error.</returns>
    public static async Task<Result<bool, SmartCardError>> InstallForInstallAsync(
        byte[] packageAid,
        byte[] moduleAid,
        byte[] applicationAid,
        byte privileges,
        byte[] installParameters,
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        // Create INSTALL command for installation
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> cmdResult = 
            InstallCommand.InstallForInstallCommand.Create(
                packageAid,
                moduleAid,       // moduleAid  
                applicationAid,  // applicationAid
                new[] { privileges },  // privileges as array
                installParameters ?? Array.Empty<byte>());
        
        if (cmdResult.IsFailure)
        {
            return Result.Failure<bool, SmartCardError>(cmdResult.Error);
        }

        // Execute the command
        Result<CommandResponse, SmartCardError> response = 
            await executeCommand(cmdResult.Value, cancellationToken);
        
        if (response.IsFailure)
        {
            return Result.Failure<bool, SmartCardError>(response.Error);
        }

        return response.Value.IsSuccess
            ? Result.Success<bool, SmartCardError>(true)
            : Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidResponse($"INSTALL [for install] failed with SW: {response.Value.StatusWord:X4}"));
    }

    /// <summary>
    /// Makes an installed application selectable.
    /// </summary>
    /// <param name="applicationAid">The application AID.</param>
    /// <param name="executeCommand">Function to execute APDU commands.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Success or error.</returns>
    public static async Task<Result<bool, SmartCardError>> MakeSelectableAsync(
        byte[] applicationAid,
        Func<IApduCommand, CancellationToken, Task<Result<CommandResponse, SmartCardError>>> executeCommand,
        CancellationToken cancellationToken = default)
    {
        // Create INSTALL command for make selectable
        // For make selectable only, we use CreateAndMakeSelectable with same AID
        Result<InstallCommand.InstallForInstallCommand, SmartCardError> cmdResult = 
            InstallCommand.InstallForInstallCommand.CreateAndMakeSelectable(
                applicationAid,  // packageAid
                applicationAid,  // moduleAid (same as package for make selectable)
                applicationAid,  // applicationAid
                new byte[] { 0x00 }); // privileges (default)
        
        if (cmdResult.IsFailure)
        {
            return Result.Failure<bool, SmartCardError>(cmdResult.Error);
        }

        // Execute the command
        Result<CommandResponse, SmartCardError> response = 
            await executeCommand(cmdResult.Value, cancellationToken);
        
        if (response.IsFailure)
        {
            return Result.Failure<bool, SmartCardError>(response.Error);
        }

        return response.Value.IsSuccess
            ? Result.Success<bool, SmartCardError>(true)
            : Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidResponse($"INSTALL [for make selectable] failed with SW: {response.Value.StatusWord:X4}"));
    }

    /// <summary>
    /// Card lifecycle states per GlobalPlatform specification.
    /// </summary>
    public enum CardLifecycleState
    {
        CardOpReady = 0x01,
        CardInitialized = 0x07,
        CardSecured = 0x0F,
        CardLocked = 0x7F,
        CardTerminated = 0xFF
    }
}