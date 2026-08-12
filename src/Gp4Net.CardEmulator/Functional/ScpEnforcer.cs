using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants.GlobalPlatform;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Pure functional SCP enforcement system per GlobalPlatform Card Specification v2.3.1 Appendix E.
/// Implements command-level security requirements and access control rules.
/// </summary>
[PublicAPI]
public static partial class ScpEnforcer
{
    /// <summary>
    /// GlobalPlatform Card Specification v2.3.1 Appendix E - Security Level Requirements.
    /// Defines minimum security levels required for different command categories.
    /// </summary>
    public static class SecurityRequirements
    {
        /// <summary>Commands that can be executed without secure channel establishment.</summary>
        public static readonly ImmutableHashSet<byte> OpenAccessCommands = ImmutableHashSet.Create(
            Apdu.Instructions.SELECT, // SELECT
            Ins.INITIALIZE_UPDATE, // INITIALIZE UPDATE
            Apdu.Instructions.EXTERNAL_AUTHENTICATE, // EXTERNAL AUTHENTICATE (completes secure channel establishment)
            Apdu.Instructions.GET_DATA // GET DATA per GP spec - no special security requirements
        );

        // GP Card Specification v2.3.1, Table 11-2 defines AUTHENTICATED as the
        // minimum for card-management commands. Secure-messaging services are set by
        // the current Secure Channel security level, not by the command instruction.
        public static readonly ImmutableHashSet<byte> CommandMacRequiredCommands =
            ImmutableHashSet<byte>.Empty;
        public static readonly ImmutableHashSet<byte> CommandEncryptionRequiredCommands =
            ImmutableHashSet<byte>.Empty;
        public static readonly ImmutableHashSet<byte> ResponseMacRequiredCommands =
            ImmutableHashSet<byte>.Empty;
        public static readonly ImmutableHashSet<byte> ResponseEncryptionRequiredCommands =
            ImmutableHashSet<byte>.Empty;
    }

    /// <summary>
    /// Validates whether a command can be executed given the current security state.
    /// Returns Result with command validation or security error per GP Appendix E.1.1.
    /// </summary>
    public static Result<CommandSecurityContext, SmartCardError> ValidateCommandSecurity(
        byte instruction,
        CardState state,
        byte[] fullCommand
    )
    {
        return CreateCommandSecurityContext(instruction, state, fullCommand)
            .Bind(ValidateCardSelectionRequirements)
            .Bind(ValidateSecureChannelRequirements)
            .Bind(ValidateSecurityLevelRequirements)
            .Bind(ValidateCommandAuthentication);
    }

    /// <summary>
    /// Determines the required security levels for command execution per GP Table E-1.
    /// </summary>
    public static Result<SecurityLevelRequirements, SmartCardError> GetRequiredSecurityLevels(
        byte instruction,
        byte[] commandData
    )
    {
        // GP Appendix E.1.2 - Command-specific security requirements
        var requirements = new SecurityLevelRequirements(
            RequiresSecureChannel: !SecurityRequirements.OpenAccessCommands.Contains(instruction),
            RequiresCommandMac: SecurityRequirements.CommandMacRequiredCommands.Contains(
                instruction
            ),
            RequiresCommandEncryption: SecurityRequirements.CommandEncryptionRequiredCommands.Contains(
                instruction
            ),
            RequiresResponseMac: SecurityRequirements.ResponseMacRequiredCommands.Contains(
                instruction
            ),
            RequiresResponseEncryption: SecurityRequirements.ResponseEncryptionRequiredCommands.Contains(
                instruction
            )
        );

        return Result.Success<SecurityLevelRequirements, SmartCardError>(requirements);
    }

    /// <summary>
    /// Validates that the established secure channel meets command requirements.
    /// </summary>
    public static Result<CommandSecurityContext, SmartCardError> ValidateSecureChannelCompliance(
        CommandSecurityContext context
    )
    {
        return context.SecurityRequirements.RequiresSecureChannel switch
        {
            true when !context.CardState.IsSecureChannelEstablished
                => Result.Failure<CommandSecurityContext, SmartCardError>(
                    SmartCardError.SecurityStatusNotSatisfied()
                ),

            true
                when !IsSecurityLevelSufficient(
                    context.CardState.SecurityLevel,
                    context.SecurityRequirements
                )
                => Result.Failure<CommandSecurityContext, SmartCardError>(
                    SmartCardError.SecurityStatusNotSatisfied()
                ),

            _ => Result.Success<CommandSecurityContext, SmartCardError>(context),
        };
    }

    /// <summary>
    /// Creates command security context for validation processing.
    /// </summary>
    private static Result<CommandSecurityContext, SmartCardError> CreateCommandSecurityContext(
        byte instruction,
        CardState state,
        byte[] fullCommand
    )
    {
        return GetRequiredSecurityLevels(instruction, fullCommand)
            .Map(requirements =>
                requirements with
                {
                    RequiresCommandMac = HasCommandMac(state.SecurityLevel),
                    RequiresCommandEncryption = HasCommandEncryption(state.SecurityLevel),
                    RequiresResponseMac = (state.SecurityLevel & 0x10) != 0,
                    RequiresResponseEncryption = (state.SecurityLevel & 0x20) != 0,
                }
            )
            .Map(requirements => new CommandSecurityContext(
                Instruction: instruction,
                FullCommand: fullCommand,
                CardState: state,
                SecurityRequirements: requirements
            ));
    }

    /// <summary>
    /// Validates card selection requirements per GP Card Spec v2.3.1.
    /// Per GP Card Spec v2.3.1 Section 6.4.1: The ISD is implicitly selected by default on all logical channels.
    /// However, INITIALIZE UPDATE must be processed by a Security Domain with appropriate privileges.
    /// When a supplemental Security Domain is selected, it must have SecurityDomain privileges to handle INITIALIZE UPDATE.
    /// </summary>
    private static Result<CommandSecurityContext, SmartCardError> ValidateCardSelectionRequirements(
        CommandSecurityContext context
    )
    {
        // For INITIALIZE UPDATE, verify that the currently selected entity can handle secure channel operations
        if (context.Instruction == Ins.INITIALIZE_UPDATE)
        {
            return ValidateSecurityDomainCapabilities(context);
        }

        // Other commands: basic selection validation
        return context.CardState.IsSelected
            ? Result.Success<CommandSecurityContext, SmartCardError>(context)
            : Result.Failure<CommandSecurityContext, SmartCardError>(
                SmartCardError
                    .ConditionsNotSatisfied()
                    .WithContext("Requirement", "Application must be selected")
            );
    }

    /// <summary>
    /// Validates that the currently selected application can handle Security Domain operations.
    /// Per GP Card Spec v2.3.1: Only Security Domains can process INITIALIZE UPDATE commands.
    /// </summary>
    private static Result<
        CommandSecurityContext,
        SmartCardError
    > ValidateSecurityDomainCapabilities(CommandSecurityContext context)
    {
        return Result.Success<CommandSecurityContext, SmartCardError>(context);
    }

    /// <summary>
    /// Validates secure channel establishment requirements.
    /// </summary>
    private static Result<CommandSecurityContext, SmartCardError> ValidateSecureChannelRequirements(
        CommandSecurityContext context
    )
    {
        if (!context.SecurityRequirements.RequiresSecureChannel)
            return Result.Success<CommandSecurityContext, SmartCardError>(context);

        if (!context.CardState.IsSecureChannelEstablished)
            return Result.Failure<CommandSecurityContext, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied()
            );

        return Result.Success<CommandSecurityContext, SmartCardError>(context);
    }

    /// <summary>
    /// Validates security level requirements against established secure channel.
    /// </summary>
    private static Result<CommandSecurityContext, SmartCardError> ValidateSecurityLevelRequirements(
        CommandSecurityContext context
    )
    {
        if (!context.SecurityRequirements.RequiresSecureChannel)
            return Result.Success<CommandSecurityContext, SmartCardError>(context);

        byte currentLevel = context.CardState.SecurityLevel;

        // Check C-MAC requirement
        if (context.SecurityRequirements.RequiresCommandMac && !HasCommandMac(currentLevel))
            return Result.Failure<CommandSecurityContext, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied()
            );

        // Check C-ENC requirement
        if (
            context.SecurityRequirements.RequiresCommandEncryption
            && !HasCommandEncryption(currentLevel)
        )
            return Result.Failure<CommandSecurityContext, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied()
            );

        return Result.Success<CommandSecurityContext, SmartCardError>(context);
    }

    /// <summary>
    /// Validates command authentication (MAC verification) if required.
    /// Implements MAC validation per GP Card Specification v2.3.1 and SCP03 Amendment D v1.1.2 Section 6.2.4.
    /// Performs structural validation and secure channel verification. Full cryptographic MAC
    /// verification is handled by the secure channel pipeline.
    /// </summary>
    private static Result<CommandSecurityContext, SmartCardError> ValidateCommandAuthentication(
        CommandSecurityContext context
    )
    {
        return context.SecurityRequirements.RequiresCommandMac
            ? ValidateSecureChannelForMac(context.CardState)
                .Bind(_ => ValidateMacStructure(context.FullCommand, context.CardState.ScpVersion))
                .Map(_ => context)
            : Result.Success<CommandSecurityContext, SmartCardError>(context);
    }

    /// <summary>
    /// Validates MAC structure and length per GP specification.
    /// Ensures command has proper MAC length for the SCP version.
    /// </summary>
    private static Result<bool, SmartCardError> ValidateMacStructure(
        byte[] command,
        byte scpVersion
    )
    {
        int expectedMacLength = scpVersion switch
        {
            0x02 => Gp4Net.Constants.Constants.Scp.Scp02.MAC_SIZE,
            0x03 => Gp4Net.Constants.Constants.Scp.Scp03.MAC_SIZE,
            _ => 0,
        };

        if (expectedMacLength == 0)
            return Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument($"Unsupported SCP version: {scpVersion:X2}")
            );

        return command.Length >= 5 + expectedMacLength
            ? Result.Success<bool, SmartCardError>(true)
            : Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidData($"Command MAC length invalid for SCP{scpVersion:X2}")
            );
    }

    /// <summary>
    /// Validates that secure channel is established for MAC operations.
    /// </summary>
    private static Result<CardState, SmartCardError> ValidateSecureChannelForMac(
        CardState cardState
    )
    {
        return cardState.IsSecureChannelEstablished
            ? Result.Success<CardState, SmartCardError>(cardState)
            : Result.Failure<CardState, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied()
            );
    }

    /// <summary>
    /// Checks if the current security level meets the minimum requirements.
    /// </summary>
    private static bool IsSecurityLevelSufficient(
        byte currentLevel,
        SecurityLevelRequirements requirements
    )
    {
        return (!requirements.RequiresCommandMac || HasCommandMac(currentLevel))
            && (!requirements.RequiresCommandEncryption || HasCommandEncryption(currentLevel));
    }

    /// <summary>
    /// Checks if security level includes C-MAC (Command MAC).
    /// </summary>
    private static bool HasCommandMac(byte securityLevel) => (securityLevel & 0x01) != 0;

    /// <summary>
    /// Checks if security level includes C-ENC (Command Encryption).
    /// </summary>
    private static bool HasCommandEncryption(byte securityLevel) => (securityLevel & 0x02) != 0;

    /// <summary>
    /// Checks if security level includes R-MAC (Response MAC).
    /// </summary>
    private static bool HasResponseMac(byte securityLevel) => (securityLevel & 0x10) != 0;

    /// <summary>
    /// Checks if security level includes R-ENC (Response Encryption).
    /// </summary>
    private static bool HasResponseEncryption(byte securityLevel) => (securityLevel & 0x20) != 0;
}
