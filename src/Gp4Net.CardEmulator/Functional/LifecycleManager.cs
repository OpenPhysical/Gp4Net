using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Pure functional lifecycle state management per GlobalPlatform Card Specification v2.3.1 Section 5.
/// Implements state transitions for applications, load files, and executable modules.
/// </summary>
// @TODO Does this overlap with ApplicationContext?  Eliminate DRY violations.
[PublicAPI]
public static class LifecycleManager
{
    /// <summary>
    /// GlobalPlatform Card Specification v2.3.1 lifecycle states for applications per Section 5.1.
    /// </summary>
    public static class ApplicationLifecycleStates
    {
        /// <summary>Application is installed but cannot be selected.</summary>
        public const byte Installed = Gp4Net.Constants.Constants.GlobalPlatform.LifecycleStates.Installed;

        /// <summary>Application can be selected and executed.</summary>
        public const byte Selectable = Gp4Net.Constants.Constants.GlobalPlatform.LifecycleStates.Selectable;

        /// <summary>Application is blocked and cannot be selected or executed.</summary>
        public const byte Locked = Gp4Net.Constants.Constants.GlobalPlatform.LifecycleStates.Locked;
    }

    /// <summary>
    /// GlobalPlatform Card Specification v2.3.1 lifecycle states for load files per Section 5.2.
    /// </summary>
    public static class LoadFileLifecycleStates
    {
        /// <summary>Load file has been successfully loaded onto the card.</summary>
        public const byte Loaded = Gp4Net.Constants.Constants.GlobalPlatform.LifecycleStates.Loaded;

        /// <summary>Load file is locked and cannot be used for installations.</summary>
        public const byte Locked = 0x81;
    }

    /// <summary>
    /// GlobalPlatform Card Specification v2.3.1 lifecycle states for executable modules per Section 5.3.
    /// </summary>
    public static class ExecutableModuleLifecycleStates
    {
        /// <summary>Executable module is loaded and can be used for application installation.</summary>
        public const byte Loaded = Gp4Net.Constants.Constants.GlobalPlatform.LifecycleStates.Loaded;

        /// <summary>Executable module is installed and can be selected.</summary>
        public const byte Installed = Gp4Net.Constants.Constants.GlobalPlatform.LifecycleStates.Installed;
    }

    /// <summary>
    /// Validates whether a lifecycle state transition is allowed per GP specification.
    /// Returns Result with the new state if valid, or an error if the transition is invalid.
    /// </summary>
    public static Result<byte, SmartCardError> ValidateApplicationStateTransition(
        byte currentState,
        byte newState,
        string context = ""
    )
    {
        // GP Section 5.1.2 - Valid application lifecycle transitions
        ImmutableHashSet<byte> validTransitions = GetValidApplicationTransitions(currentState);

        if (!validTransitions.Contains(newState))
        {
            return Result.Failure<byte, SmartCardError>(SmartCardError.ConditionsNotSatisfied());
        }

        return Result.Success<byte, SmartCardError>(newState);
    }

    /// <summary>
    /// Validates whether a load file lifecycle state transition is allowed per GP specification.
    /// </summary>
    public static Result<byte, SmartCardError> ValidateLoadFileStateTransition(
        byte currentState,
        byte newState,
        string context = ""
    )
    {
        // GP Section 5.2.2 - Valid load file lifecycle transitions
        ImmutableHashSet<byte> validTransitions = GetValidLoadFileTransitions(currentState);

        if (!validTransitions.Contains(newState))
        {
            return Result.Failure<byte, SmartCardError>(SmartCardError.ConditionsNotSatisfied());
        }

        return Result.Success<byte, SmartCardError>(newState);
    }

    /// <summary>
    /// Creates a new application with the specified lifecycle state, validating the initial state.
    /// </summary>
    public static Result<InstalledApplication, SmartCardError> CreateApplicationWithState(
        byte[] aid,
        byte[] executableModuleAid,
        byte lifeCycleState,
        byte privileges
    )
    {
        // Validate initial state is appropriate for new applications
        if (
            lifeCycleState != ApplicationLifecycleStates.Installed
            && lifeCycleState != ApplicationLifecycleStates.Selectable
        )
        {
            return Result.Failure<InstalledApplication, SmartCardError>(
                SmartCardError.InvalidArgument("Invalid initial application lifecycle state")
            );
        }

        InstalledApplication application = new InstalledApplication(
            Aid: aid,
            ExecutableModuleAid: executableModuleAid,
            LifecycleState: lifeCycleState,
            Privileges: privileges,
            ApplicationData: ImmutableDictionary<string, byte[]>.Empty
        );

        return Result.Success<InstalledApplication, SmartCardError>(application);
    }

    /// <summary>
    /// Creates a new load file with the specified lifecycle state, validating the initial state.
    /// </summary>
    public static Result<LoadFile, SmartCardError> CreateLoadFileWithState(
        byte[] aid,
        byte[] securityDomainAid,
        byte lifeCycleState,
        ImmutableList<ExecutableModule> modules
    )
    {
        // Validate initial state is appropriate for new load files
        if (lifeCycleState != LoadFileLifecycleStates.Loaded)
        {
            return Result.Failure<LoadFile, SmartCardError>(
                SmartCardError.InvalidArgument("Invalid initial load file lifecycle state")
            );
        }

        LoadFile loadFile = new LoadFile(
            Aid: aid,
            AssociatedSecurityDomainAid: securityDomainAid,
            LifecycleState: lifeCycleState,
            ExecutableModules: modules
        );

        return Result.Success<LoadFile, SmartCardError>(loadFile);
    }

    /// <summary>
    /// Transitions an application to a new lifecycle state with validation.
    /// </summary>
    public static Result<InstalledApplication, SmartCardError> TransitionApplicationState(
        InstalledApplication application,
        byte newState
    )
    {
        return ValidateApplicationStateTransition(application.LifecycleState, newState)
            .Map(validatedState => application with { LifecycleState = validatedState });
    }

    /// <summary>
    /// Transitions a load file to a new lifecycle state with validation.
    /// </summary>
    public static Result<LoadFile, SmartCardError> TransitionLoadFileState(
        LoadFile loadFile,
        byte newState
    )
    {
        return ValidateLoadFileStateTransition(loadFile.LifecycleState, newState)
            .Map(validatedState => loadFile with { LifecycleState = validatedState });
    }

    /// <summary>
    /// Gets valid transition states for applications per GP Section 5.1.2.
    /// </summary>
    private static ImmutableHashSet<byte> GetValidApplicationTransitions(byte currentState)
    {
        return currentState switch
        {
            ApplicationLifecycleStates.Installed => ImmutableHashSet.Create(
                ApplicationLifecycleStates.Selectable,
                ApplicationLifecycleStates.Locked
            ),
            ApplicationLifecycleStates.Selectable => ImmutableHashSet.Create(
                ApplicationLifecycleStates.Locked
            ),
            ApplicationLifecycleStates.Locked => ImmutableHashSet<byte>.Empty, // Terminal state
            _ => ImmutableHashSet<byte>.Empty,
        };
    }

    /// <summary>
    /// Gets valid transition states for load files per GP Section 5.2.2.
    /// </summary>
    private static ImmutableHashSet<byte> GetValidLoadFileTransitions(byte currentState)
    {
        return currentState switch
        {
            LoadFileLifecycleStates.Loaded => ImmutableHashSet.Create(
                LoadFileLifecycleStates.Locked
            ),
            LoadFileLifecycleStates.Locked => ImmutableHashSet<byte>.Empty, // Terminal state
            _ => ImmutableHashSet<byte>.Empty,
        };
    }

    /// <summary>
    /// Gets a human-readable description of a lifecycle state.
    /// </summary>
    public static string GetStateDescription(byte state)
    {
        return state switch
        {
            ApplicationLifecycleStates.Installed => "INSTALLED",
            ApplicationLifecycleStates.Selectable => "SELECTABLE",
            ApplicationLifecycleStates.Locked => "LOCKED",
            LoadFileLifecycleStates.Loaded => "LOADED",
            0x81 => "LOCKED", // LoadFileLifecycleStates.Locked
            // Note: ExecutableModuleLifecycleStates constants overlap with Application states
            0x0F => "CARD_LOCKED",
            0x7F => "TERMINATED",
            _ => $"Unknown (0x{state:X2})",
        };
    }

    /// <summary>
    /// Determines if an application can be selected based on its lifecycle state.
    /// </summary>
    public static bool CanApplicationBeSelected(byte lifeCycleState)
    {
        return lifeCycleState == ApplicationLifecycleStates.Selectable;
    }

    /// <summary>
    /// Determines if a load file can be used for installation based on its lifecycle state.
    /// </summary>
    public static bool CanLoadFileBeUsedForInstallation(byte lifeCycleState)
    {
        return lifeCycleState == LoadFileLifecycleStates.Loaded;
    }

    /// <summary>
    /// Updates card state with a transitioned application, maintaining functional immutability.
    /// </summary>
    public static Result<CardState, SmartCardError> UpdateApplicationLifecycle(
        CardState state,
        string applicationKey,
        byte newLifecycleState
    )
    {
        if (!state.Applications.TryGetValue(applicationKey, out InstalledApplication? application))
        {
            return Result.Failure<CardState, SmartCardError>(
                SmartCardError.ReferencedDataNotFound()
            );
        }

        return TransitionApplicationState(application, newLifecycleState)
            .Map(updatedApplication =>
                state with
                {
                    Applications = state.Applications.SetItem(applicationKey, updatedApplication),
                }
            );
    }

    /// <summary>
    /// Updates card state with a transitioned load file, maintaining functional immutability.
    /// </summary>
    public static Result<CardState, SmartCardError> UpdateLoadFileLifecycle(
        CardState state,
        byte[] loadFileAid,
        byte newLifecycleState
    )
    {
        // Find matching load file index using explicit validation
        (LoadFile LoadFile, int Index)[] matchingLoadFiles = state
            .LoadFiles.Select((lf, index) => (LoadFile: lf, Index: index))
            .Where(x => x.LoadFile.Aid.SequenceEqual(loadFileAid))
            .ToArray();

        if (matchingLoadFiles.Length == 0)
        {
            return Result.Failure<CardState, SmartCardError>(
                SmartCardError.ReferencedDataNotFound()
            );
        }

        int loadFileIndex = matchingLoadFiles.First().Index;
        LoadFile loadFile = state.LoadFiles[loadFileIndex];

        return TransitionLoadFileState(loadFile, newLifecycleState)
            .Map(updatedLoadFile =>
                state with
                {
                    LoadFiles = state.LoadFiles.SetItem(loadFileIndex, updatedLoadFile),
                }
            );
    }
}
