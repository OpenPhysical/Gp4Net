using System;
using System.Collections.Immutable;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Security;
using JetBrains.Annotations;

namespace Gp4Net.CardEmulator.Functional;

/// <summary>
/// Pure functional SCP enforcement system per GlobalPlatform Card Specification v2.3.1 Appendix E.
/// Implements command-level security requirements and access control rules.
/// </summary>
[PublicAPI]
public static class ScpEnforcer
{
    /// <summary>
    /// GlobalPlatform Card Specification v2.3.1 Appendix E - Security Level Requirements.
    /// Defines minimum security levels required for different command categories.
    /// </summary>
    public static class SecurityRequirements
    {
        /// <summary>Commands that can be executed without secure channel establishment.</summary>
        public static readonly ImmutableHashSet<byte> OpenAccessCommands = ImmutableHashSet.Create<byte>(
            0xA4, // SELECT
            0x50, // INITIALIZE UPDATE
            0xCA  // GET DATA (some data objects)
        );

        /// <summary>Commands that require secure channel establishment but no additional security.</summary>
        public static readonly ImmutableHashSet<byte> AuthenticatedCommands = ImmutableHashSet.Create<byte>(
            0x82, // EXTERNAL AUTHENTICATE
            0xCA  // GET DATA (protected data objects)
        );

        /// <summary>Commands that require C-MAC security level (command authentication).</summary>
        public static readonly ImmutableHashSet<byte> CommandMacRequiredCommands = ImmutableHashSet.Create<byte>(
            0xE6, // INSTALL
            0xE8, // LOAD
            0xE4, // DELETE
            0xD8, // PUT KEY
            0xE2, // STORE DATA
            0xF2  // GET STATUS (some variants)
        );

        /// <summary>Commands that require C-ENC security level (command encryption).</summary>
        public static readonly ImmutableHashSet<byte> CommandEncryptionRequiredCommands = ImmutableHashSet.Create<byte>(
            0xD8, // PUT KEY (key data must be encrypted)
            0xE2  // STORE DATA (sensitive data)
        );

        /// <summary>Commands that require R-MAC security level (response authentication).</summary>
        public static readonly ImmutableHashSet<byte> ResponseMacRequiredCommands = ImmutableHashSet.Create<byte>(
            0xE6, // INSTALL
            0xE8, // LOAD
            0xE4, // DELETE
            0xD8, // PUT KEY
            0xF2  // GET STATUS
        );

        /// <summary>Commands that require R-ENC security level (response encryption).</summary>
        public static readonly ImmutableHashSet<byte> ResponseEncryptionRequiredCommands = ImmutableHashSet.Create<byte>(
            0xCA, // GET DATA (sensitive data)
            0xF2  // GET STATUS (sensitive status)
        );
    }

    /// <summary>
    /// Validates whether a command can be executed given the current security state.
    /// Returns Result with command validation or security error per GP Appendix E.1.1.
    /// </summary>
    public static Result<CommandSecurityContext, SmartCardError> ValidateCommandSecurity(
        byte instruction, CardState state, byte[] fullCommand)
    {
        return CreateCommandSecurityContext(instruction, state, fullCommand)
            .Bind(context => ValidateSecureChannelRequirements(context))
            .Bind(context => ValidateSecurityLevelRequirements(context))
            .Bind(context => ValidateCommandAuthentication(context));
    }

    /// <summary>
    /// Determines the required security levels for command execution per GP Table E-1.
    /// </summary>
    public static Result<SecurityLevelRequirements, SmartCardError> GetRequiredSecurityLevels(
        byte instruction, byte[] commandData)
    {
        // GP Appendix E.1.2 - Command-specific security requirements
        var requirements = new SecurityLevelRequirements(
            RequiresSecureChannel: !SecurityRequirements.OpenAccessCommands.Contains(instruction),
            RequiresCommandMac: SecurityRequirements.CommandMacRequiredCommands.Contains(instruction),
            RequiresCommandEncryption: SecurityRequirements.CommandEncryptionRequiredCommands.Contains(instruction),
            RequiresResponseMac: SecurityRequirements.ResponseMacRequiredCommands.Contains(instruction),
            RequiresResponseEncryption: SecurityRequirements.ResponseEncryptionRequiredCommands.Contains(instruction)
        );

        // Special cases based on command parameters per GP Appendix E.1.3
        var enhancedRequirements = ApplyCommandSpecificRules(instruction, commandData, requirements);

        return Result.Success<SecurityLevelRequirements, SmartCardError>(enhancedRequirements);
    }

    /// <summary>
    /// Validates that the established secure channel meets command requirements.
    /// </summary>
    public static Result<CommandSecurityContext, SmartCardError> ValidateSecureChannelCompliance(
        CommandSecurityContext context)
    {
        return context.SecurityRequirements.RequiresSecureChannel switch
        {
            true when !context.CardState.IsSecureChannelEstablished => 
                Result.Failure<CommandSecurityContext, SmartCardError>(
                    SmartCardError.SecurityStatusNotSatisfied()),
            
            true when !IsSecurityLevelSufficient(context.CardState.SecurityLevel, context.SecurityRequirements) =>
                Result.Failure<CommandSecurityContext, SmartCardError>(
                    SmartCardError.SecurityStatusNotSatisfied()),
                    
            _ => Result.Success<CommandSecurityContext, SmartCardError>(context)
        };
    }

    /// <summary>
    /// Applies command-specific security enhancement rules per GP Appendix E.1.3.
    /// </summary>
    private static SecurityLevelRequirements ApplyCommandSpecificRules(
        byte instruction, byte[] commandData, SecurityLevelRequirements baseRequirements)
    {
        return instruction switch
        {
            // GET DATA - Security depends on requested data object
            0xCA when commandData.Length >= 4 => ApplyGetDataSecurityRules(commandData, baseRequirements),
            
            // INSTALL - All variants require C-MAC and R-MAC
            0xE6 => baseRequirements with 
            { 
                RequiresCommandMac = true, 
                RequiresResponseMac = true 
            },
            
            // PUT KEY - Always requires encryption for key data
            0xD8 => baseRequirements with 
            { 
                RequiresCommandEncryption = true,
                RequiresCommandMac = true,
                RequiresResponseMac = true 
            },
            
            // Default: return base requirements
            _ => baseRequirements
        };
    }

    /// <summary>
    /// Applies GET DATA specific security rules based on requested data object per GP Table E-2.
    /// </summary>
    private static SecurityLevelRequirements ApplyGetDataSecurityRules(
        byte[] commandData, SecurityLevelRequirements baseRequirements)
    {
        if (commandData.Length < 4) return baseRequirements;

        // Extract P1P2 (data object identifier)
        var dataObjectId = (ushort)((commandData[2] << 8) | commandData[3]);

        return dataObjectId switch
        {
            // Sensitive data objects require encryption
            0x00C1 or // Security Domain Info
            0x00CF or // Key Diversification Data  
            0x00E0 => // Key Information Template
                baseRequirements with { RequiresResponseEncryption = true },
                
            // Protected data objects require authentication only
            0x0066 or // Card Capabilities
            0x0067 or // Card Management Type and Version
            0x9F7F => // Card Production Life Cycle  
                baseRequirements with { RequiresSecureChannel = true },
                
            // Public data objects - no additional requirements
            _ => baseRequirements
        };
    }

    /// <summary>
    /// Creates command security context for validation processing.
    /// </summary>
    private static Result<CommandSecurityContext, SmartCardError> CreateCommandSecurityContext(
        byte instruction, CardState state, byte[] fullCommand)
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
    /// Validates secure channel establishment requirements.
    /// </summary>
    private static Result<CommandSecurityContext, SmartCardError> ValidateSecureChannelRequirements(
        CommandSecurityContext context)
    {
        if (!context.SecurityRequirements.RequiresSecureChannel)
            return Result.Success<CommandSecurityContext, SmartCardError>(context);

        if (!context.CardState.IsSecureChannelEstablished)
            return Result.Failure<CommandSecurityContext, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied());

        return Result.Success<CommandSecurityContext, SmartCardError>(context);
    }

    /// <summary>
    /// Validates security level requirements against established secure channel.
    /// </summary>
    private static Result<CommandSecurityContext, SmartCardError> ValidateSecurityLevelRequirements(
        CommandSecurityContext context)
    {
        if (!context.SecurityRequirements.RequiresSecureChannel)
            return Result.Success<CommandSecurityContext, SmartCardError>(context);

        var currentLevel = context.CardState.SecurityLevel;
        
        // Check C-MAC requirement
        if (context.SecurityRequirements.RequiresCommandMac && !HasCommandMac(currentLevel))
            return Result.Failure<CommandSecurityContext, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied());

        // Check C-ENC requirement
        if (context.SecurityRequirements.RequiresCommandEncryption && !HasCommandEncryption(currentLevel))
            return Result.Failure<CommandSecurityContext, SmartCardError>(
                SmartCardError.SecurityStatusNotSatisfied());

        return Result.Success<CommandSecurityContext, SmartCardError>(context);
    }

    /// <summary>
    /// Validates command authentication (MAC verification) if required.
    /// </summary>
    private static Result<CommandSecurityContext, SmartCardError> ValidateCommandAuthentication(
        CommandSecurityContext context)
    {
        // Command MAC validation would be performed by secure channel processor
        // This is a placeholder for the validation logic
        return Result.Success<CommandSecurityContext, SmartCardError>(context);
    }

    /// <summary>
    /// Checks if the current security level meets the minimum requirements.
    /// </summary>
    private static bool IsSecurityLevelSufficient(byte currentLevel, SecurityLevelRequirements requirements)
    {
        return (!requirements.RequiresCommandMac || HasCommandMac(currentLevel)) &&
               (!requirements.RequiresCommandEncryption || HasCommandEncryption(currentLevel));
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

    /// <summary>
    /// Represents command security validation context.
    /// </summary>
    public record CommandSecurityContext(
        byte Instruction,
        byte[] FullCommand,
        CardState CardState,
        SecurityLevelRequirements SecurityRequirements
    );

    /// <summary>
    /// Represents security level requirements for a command per GP Appendix E.
    /// </summary>
    public record SecurityLevelRequirements(
        bool RequiresSecureChannel,
        bool RequiresCommandMac,
        bool RequiresCommandEncryption,
        bool RequiresResponseMac,
        bool RequiresResponseEncryption
    );
}