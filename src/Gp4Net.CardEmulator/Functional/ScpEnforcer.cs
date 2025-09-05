
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Core;
using static Gp4Net.Constants.Constants;
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
        public static readonly ImmutableHashSet<byte> OpenAccessCommands =
            ImmutableHashSet.Create<byte>(
                GlobalPlatform.Ins.Select, // SELECT
                GlobalPlatform.Ins.InitializeUpdate, // INITIALIZE UPDATE
                GlobalPlatform.Ins.ExternalAuthenticate, // EXTERNAL AUTHENTICATE (completes secure channel establishment)
                GlobalPlatform.Ins.GetData // GET DATA (some data objects)
            );

        /// <summary>Commands that require secure channel establishment but no additional security.</summary>
        public static readonly ImmutableHashSet<byte> AuthenticatedCommands =
            ImmutableHashSet.Create<byte>(
                GlobalPlatform.Ins.GetData // GET DATA (protected data objects)
            );

        /// <summary>Commands that require C-MAC security level (command authentication).</summary>
        public static readonly ImmutableHashSet<byte> CommandMacRequiredCommands =
            ImmutableHashSet.Create<byte>(
                GlobalPlatform.Ins.Install, // INSTALL
                GlobalPlatform.Ins.Load, // LOAD
                GlobalPlatform.Ins.Delete, // DELETE
                GlobalPlatform.Ins.PutKey, // PUT KEY
                GlobalPlatform.Ins.StoreData, // STORE DATA
                GlobalPlatform.Ins.GetStatus // GET STATUS (some variants)
            );

        /// <summary>Commands that require C-ENC security level (command encryption).</summary>
        public static readonly ImmutableHashSet<byte> CommandEncryptionRequiredCommands =
            ImmutableHashSet.Create<byte>(
                GlobalPlatform.Ins.PutKey, // PUT KEY (key data must be encrypted)
                GlobalPlatform.Ins.StoreData // STORE DATA (sensitive data)
            );

        /// <summary>Commands that require R-MAC security level (response authentication).</summary>
        public static readonly ImmutableHashSet<byte> ResponseMacRequiredCommands =
            ImmutableHashSet.Create<byte>(
                GlobalPlatform.Ins.Install, // INSTALL
                GlobalPlatform.Ins.Load, // LOAD
                GlobalPlatform.Ins.Delete, // DELETE
                GlobalPlatform.Ins.PutKey, // PUT KEY
                GlobalPlatform.Ins.GetStatus // GET STATUS
            );

        /// <summary>Commands that require R-ENC security level (response encryption).</summary>
        public static readonly ImmutableHashSet<byte> ResponseEncryptionRequiredCommands =
            ImmutableHashSet.Create<byte>(
                GlobalPlatform.Ins.GetData, // GET DATA (sensitive data)
                GlobalPlatform.Ins.GetStatus // GET STATUS (sensitive status)
            );
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
        SecurityLevelRequirements requirements = new SecurityLevelRequirements(
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

        // Special cases based on command parameters per GP Appendix E.1.3
        SecurityLevelRequirements enhancedRequirements = ApplyCommandSpecificRules(
            instruction,
            commandData,
            requirements
        );

        return Result.Success<SecurityLevelRequirements, SmartCardError>(enhancedRequirements);
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
            true when !context.CardState.IsSecureChannelEstablished => Result.Failure<
                CommandSecurityContext,
                SmartCardError
            >(SmartCardError.SecurityStatusNotSatisfied()),

            true
                when !IsSecurityLevelSufficient(
                    context.CardState.SecurityLevel,
                    context.SecurityRequirements
                ) => Result.Failure<CommandSecurityContext, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied()
            ),

            _ => Result.Success<CommandSecurityContext, SmartCardError>(context),
        };
    }

    /// <summary>
    /// Applies command-specific security enhancement rules per GP Appendix E.1.3.
    /// </summary>
    private static SecurityLevelRequirements ApplyCommandSpecificRules(
        byte instruction,
        byte[] commandData,
        SecurityLevelRequirements baseRequirements
    )
    {
        return instruction switch
        {
            // GET DATA - Security depends on requested data object
            Ins.GetData when commandData.Length >= 4 => ApplyGetDataSecurityRules(
                commandData,
                baseRequirements
            ),

            // INSTALL - All variants require C-MAC and R-MAC
            Ins.Install => baseRequirements with { RequiresCommandMac = true, RequiresResponseMac = true },

            // PUT KEY - Always requires encryption for key data
            Ins.PutKey => baseRequirements with
            {
                RequiresCommandEncryption = true,
                RequiresCommandMac = true,
                RequiresResponseMac = true,
            },

            // Default: return base requirements
            _ => baseRequirements,
        };
    }

    /// <summary>
    /// Applies GET DATA specific security rules based on requested data object per GP Table E-2.
    /// </summary>
    private static SecurityLevelRequirements ApplyGetDataSecurityRules(
        byte[] commandData,
        SecurityLevelRequirements baseRequirements
    )
    {
        // Per ISO 7816-4: APDU format is CLA INS P1 P2 [Lc] [Data] [Le]
        // GET DATA command requires P1P2 parameters to identify the requested data object
        // Minimum 4 bytes needed: CLA (0) + INS (1) + P1 (2) + P2 (3)
        if (commandData.Length < 4)
            return baseRequirements;

        // Extract P1P2 (data object identifier)
        ushort dataObjectId = (ushort)(commandData[2] << 8 | commandData[3]);

        return dataObjectId switch
        {
            // Sensitive data objects require encryption
            0x00C1
            or // Security Domain Info
            0x00CF
            or // Key Diversification Data
            0x00E0 => // Key Information Template
            baseRequirements with
            {
                RequiresResponseEncryption = true,
            },

            // Protected data objects require authentication only
            0x0066
            or // Card Capabilities
            0x0067
            or // Card Management Type and Version
            0x9F7F => // Card Production Life Cycle
            baseRequirements with
            {
                RequiresSecureChannel = true,
            },

            // Public data objects - no additional requirements
            _ => baseRequirements,
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
        if (context.Instruction == Ins.InitializeUpdate)
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
        // ISD is always implicitly selected and can always handle INITIALIZE UPDATE
        Maybe<VirtualApplication> selectedApp = context.CardState.CurrentlySelectedApplication;

        // Use functional pattern matching approach
        return selectedApp.Match(
            Some: app =>
                app.Privileges.HasFlag(Privilege.SecurityDomain)
                    ? Result.Success<CommandSecurityContext, SmartCardError>(context)
                    : Result.Failure<CommandSecurityContext, SmartCardError>(
                        SmartCardError
                            .ConditionsNotSatisfied()
                            .WithContext("Instruction", "INITIALIZE UPDATE")
                            .WithContext(
                                "Requirement",
                                "Selected application must have SecurityDomain privileges per GP Card Spec v2.3.1"
                            )
                    ),
            None: () => Result.Success<CommandSecurityContext, SmartCardError>(context)
        ); // No app selected = ISD implicitly selected
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
    /// Implements proper MAC validation per GP Card Specification v2.3.1 and SCP03 v1.1.1 Section 6.2.4.
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
            0x02 => 8, // SCP02 uses 8-byte MAC per GP Card Spec v2.3.1 Section E.4
            0x03 => 16, // SCP03 uses 16-byte AES-CMAC per GP SCP03 v1.1.1 Section 6.2.4
            _ => 8, // Default to SCP02 MAC length
        };

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
