
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using Gp4Net.Core;
using Gp4Net.Domain;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Functional privilege enforcement system according to GlobalPlatform Section 6.
/// Validates operations based on application privileges and secure channel state.
/// </summary>

public static class PrivilegeEnforcement
{
    /// <summary>
    /// Validates if a command can be executed based on current card state and privileges.
    /// </summary>
    /// <param name="state">Current card state with application context.</param>
    /// <param name="command">Command being executed.</param>
    /// <returns>Success if command is authorized, failure with specific error otherwise.</returns>
    public static Result<bool, SmartCardError> ValidateCommandPrivileges(
        CardState state,
        CommandInfo command
    )
    {
        return GetRequiredPrivileges(command)
            .Bind(requiredPrivileges => ValidatePrivilege(state, requiredPrivileges))
            .Bind(_ => ValidateSecurityLevel(state, command))
            .Bind(_ => ValidateLifecycleState(state, command));
    }

    /// <summary>
    /// Determines required privileges for a specific command.
    /// </summary>
    private static Result<CommandPrivilegeRequirements, SmartCardError> GetRequiredPrivileges(
        CommandInfo command
    )
    {
        CommandPrivilegeRequirements requirements = command.ClassInstruction switch
        {
            // Card Manager commands require Card Manager privileges
            0x80E6 => CommandPrivilegeRequirements.Create(
                Privilege.AuthorizedManagement | Privilege.SecurityDomain,
                SecurityLevel.CMac,
                true
            ), // Requires secure channel

            0x80E4 => CommandPrivilegeRequirements.Create(
                Privilege.AuthorizedManagement | Privilege.DelegatedManagement | Privilege.SecurityDomain,
                SecurityLevel.CMac,
                true
            ),

            0x80E8 => CommandPrivilegeRequirements.Create(
                Privilege.AuthorizedManagement | Privilege.SecurityDomain,
                SecurityLevel.CMac,
                true
            ),

            // Security Domain commands
            0x80F2 => command.P1 switch
            {
                0x80 or 0x90 => CommandPrivilegeRequirements.Create(
                    Privilege.SecurityDomain,
                    SecurityLevel.CMac,
                    true
                ),
                _ => CommandPrivilegeRequirements.Create(
                    Privilege.None,
                    SecurityLevel.None,
                    false
                ),
            },

            // Key management commands
            0x80D8 => CommandPrivilegeRequirements.Create(
                Privilege.SecurityDomain,
                SecurityLevel.CMac,
                true
            ),

            // Card lock/terminate commands
            0x80F0 => command.P1 switch
            {
                0x00 => CommandPrivilegeRequirements.Create(
                    Privilege.CardLock,
                    SecurityLevel.CMac,
                    true
                ),
                0x01 => CommandPrivilegeRequirements.Create(
                    Privilege.CardTerminate,
                    SecurityLevel.CMac,
                    true
                ),
                _ => CommandPrivilegeRequirements.Create(
                    Privilege.CardReset,
                    SecurityLevel.CMac,
                    true
                ),
            },

            // Basic commands (SELECT, etc.) - no special privileges
            0x00A4 => CommandPrivilegeRequirements.Create(
                Privilege.None,
                SecurityLevel.None,
                false
            ),

            // Secure channel establishment
            0x8050 or 0x8482 => CommandPrivilegeRequirements.Create(
                Privilege.None,
                SecurityLevel.None,
                false
            ),

            _ => CommandPrivilegeRequirements.Create(
                Privilege.None,
                SecurityLevel.None,
                false
            ),
        };

        return Result.Success<CommandPrivilegeRequirements, SmartCardError>(requirements);
    }

    /// <summary>
    /// Validates that the current application has required privileges.
    /// </summary>
    private static Result<bool, SmartCardError> ValidatePrivilege(
        CardState state,
        CommandPrivilegeRequirements requirements
    )
    {
        if (requirements.RequiredPrivileges == Privilege.None)
        {
            return Result.Success<bool, SmartCardError>(true);
        }

        return state.CurrentlySelectedApplication.Match(
            app => ValidateSpecificPrivileges(app, requirements.RequiredPrivileges),
            () => Result.Failure<bool, SmartCardError>(SmartCardError.ConditionsNotSatisfied())
        );
    }

    /// <summary>
    /// Validates specific application privileges.
    /// </summary>
    private static Result<bool, SmartCardError> ValidateSpecificPrivileges(
        VirtualApplication app,
        Privilege required
    )
    {
        if (app.Privileges.HasFlag(required))
        {
            return Result.Success<bool, SmartCardError>(true);
        }

        // Check for delegated management privileges
        if (
            required.HasFlag(Privilege.AuthorizedManagement | Privilege.SecurityDomain)
            && app.Privileges.HasFlag(Privilege.DelegatedManagement)
        )
        {
            return Result.Success<bool, SmartCardError>(true);
        }

        return Result.Failure<bool, SmartCardError>(SmartCardError.SecurityStatusNotSatisfied());
    }

    /// <summary>
    /// Validates that the current security level meets requirements.
    /// </summary>
    private static Result<bool, SmartCardError> ValidateSecurityLevel(
        CardState state,
        CommandInfo command
    )
    {
        return GetRequiredSecurityLevel(command)
            .Bind(required => CheckSecurityLevel(state, required));
    }

    /// <summary>
    /// Gets required security level for a command.
    /// </summary>
    private static Result<SecurityLevel, SmartCardError> GetRequiredSecurityLevel(
        CommandInfo command
    )
    {
        SecurityLevel required = command.ClassInstruction switch
        {
            // Administrative commands require C-MAC
            0x80E6 or 0x80E4 or 0x80E8 or 0x80D8 or 0x80F0 => SecurityLevel.CMac,

            // Secure GET STATUS requires C-MAC
            0x80F2 when (command.P1 & 0x80) != 0 => SecurityLevel.CMac,

            // Other commands don't require security by default
            _ => SecurityLevel.None,
        };

        return Result.Success<SecurityLevel, SmartCardError>(required);
    }

    /// <summary>
    /// Checks if current security level meets requirements.
    /// </summary>
    private static Result<bool, SmartCardError> CheckSecurityLevel(
        CardState state,
        SecurityLevel required
    )
    {
        if (required == SecurityLevel.None)
        {
            return Result.Success<bool, SmartCardError>(true);
        }

        SecurityLevel currentLevel = (SecurityLevel)state.SecurityLevel;
        if (currentLevel >= required)
        {
            return Result.Success<bool, SmartCardError>(true);
        }

        return Result.Failure<bool, SmartCardError>(SmartCardError.SecurityStatusNotSatisfied());
    }

    /// <summary>
    /// Validates application lifecycle state allows the command.
    /// </summary>
    private static Result<bool, SmartCardError> ValidateLifecycleState(
        CardState state,
        CommandInfo command
    )
    {
        return state.CurrentlySelectedApplication.Match(
            app => ValidateApplicationLifecycleState(app, command),
            () => Result.Success<bool, SmartCardError>(true) // ISD always allows basic operations
        );
    }

    /// <summary>
    /// Validates specific application lifecycle state.
    /// </summary>
    private static Result<bool, SmartCardError> ValidateApplicationLifecycleState(
        VirtualApplication app,
        CommandInfo command
    )
    {
        return app.State switch
        {
            ApplicationState.Blocked => command.ClassInstruction switch
            {
                // Only basic commands allowed when blocked
                0x00A4 => Result.Success<bool, SmartCardError>(true),
                _ => Result.Failure<bool, SmartCardError>(SmartCardError.ConditionsNotSatisfied()),
            },

            ApplicationState.Locked => command.ClassInstruction switch
            {
                // Limited commands when locked
                0x00A4 or 0x80F0 => Result.Success<bool, SmartCardError>(true),
                _ => Result.Failure<bool, SmartCardError>(SmartCardError.ConditionsNotSatisfied()),
            },

            ApplicationState.Installed => command.ClassInstruction switch
            {
                // Installation state allows personalization commands
                0x00A4 or 0x80E6 or 0x80DA => Result.Success<bool, SmartCardError>(true),
                _ => Result.Failure<bool, SmartCardError>(SmartCardError.ConditionsNotSatisfied()),
            },

            ApplicationState.Selectable or ApplicationState.Personalized => Result.Success<
                bool,
                SmartCardError
            >(true),

            _ => Result.Failure<bool, SmartCardError>(SmartCardError.ConditionsNotSatisfied()),
        };
    }
}

/// <summary>
/// Information about a command for privilege checking.
/// </summary>
public record CommandInfo(ushort ClassInstruction, byte P1, byte P2, int DataLength)
{
    public static Result<CommandInfo, SmartCardError> FromApdu(ImmutableArray<byte> apdu)
    {
        if (apdu.Length < 4)
        {
            return Result.Failure<CommandInfo, SmartCardError>(SmartCardError.WrongLength());
        }

        ushort classInstruction = (ushort)(apdu[0] << 8 | apdu[1]);
        return Result.Success<CommandInfo, SmartCardError>(
            new CommandInfo(classInstruction, apdu[2], apdu[3], apdu.Length - 4)
        );
    }
}
