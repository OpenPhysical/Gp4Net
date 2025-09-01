using System;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Applications;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace Gp4Net.CardEmulator.Core;

/// <summary>
/// Application-based VirtualCard implementation using the new ApplicationRegistry pattern.
/// This partial class extends VirtualCard with application-based command routing.
/// </summary>
public partial class VirtualCard
{
    /// <summary>
    /// Creates a new virtual card with application-based architecture.
    /// </summary>
    /// <param name="config">The card configuration</param>
    /// <param name="rngContext">RNG context for cryptographic operations</param>
    /// <param name="logger">Optional logger</param>
    /// <returns>New virtual card with ISD application, or error</returns>
    public static Result<VirtualCard, SmartCardError> CreateWithApplications(
        CardConfiguration config,
        IRngContext rngContext,
        Maybe<ILogger> logger = default)
    {
        return CardState.Create()
            .Bind(initialState => ApplicationRegistry.CreateWithIsd(
                config.IsdAid.ToImmutableArray(),
                config.DefaultScpVersion,
                (byte)config.DefaultScpImplementation)
                .Map(registry =>
                {
                    var stateWithApps = initialState with
                    {
                        ScpVersion = config.DefaultScpVersion,
                        ScpImplementation = config.DefaultScpImplementation,
                        ApplicationRegistry = registry
                    };
                    
                    return new VirtualCard(
                        config,
                        rngContext,
                        stateWithApps,
                        new LoggingService(logger));
                }));
    }
    
    /// <summary>
    /// Application-based command processing using ApplicationRegistry for routing.
    /// This replaces the switch-based command routing with proper application dispatch.
    /// </summary>
    public static Result<(ApduResponse, CardState), SmartCardError> ProcessCommandWithApplications(
        byte[] command,
        CardState state,
        CardConfiguration config,
        IRngContext rngContext,
        LoggingService logging)
    {
        return ValidateCommand(command)
            .Bind(cmd => ValidateInstructionSupported(cmd, config))
            .Bind(cmd => ApplyScpSecurity(cmd, state, logging))
            .Bind(cmd => RouteToApplications(cmd.FullCommand, state, rngContext, logging))
            .Bind(result => ApplyResponseSecurity(result, rngContext, logging));
    }
    
    /// <summary>
    /// Routes command to applications using ApplicationRegistry.
    /// This is the core of the new application-based architecture.
    /// </summary>
    private static Result<(Core.ApduResponse, CardState), SmartCardError> RouteToApplications(
        byte[] command,
        CardState state,
        IRngContext rngContext,
        LoggingService logging)
    {
        return state.ApplicationRegistry.Match(
            registry =>
            {
                logging.LogDebug(
                    "Routing command INS=0x{Ins:X2} to application registry",
                    command[1]);
                
                return registry.RouteCommand(command, state, rngContext)
                    .Map(result =>
                    {
                        var (updatedRegistry, apduResponse) = result;
                        var newState = state with { ApplicationRegistry = Maybe<ApplicationRegistry>.From(updatedRegistry) };
                        
                        // Convert our ApduResponse to the legacy ApduResponse format
                        var legacyResponse = ConvertToLegacyApduResponse(apduResponse);
                        
                        logging.LogDebug(
                            "Application processed command - Response SW: {StatusWord:X4}",
                            GetStatusWordValue(legacyResponse.StatusWord));
                        
                        return (legacyResponse, newState);
                    });
            },
            () =>
            {
                logging.LogError("No application registry available");
                return Result.Failure<(Core.ApduResponse, CardState), SmartCardError>(
                    SmartCardError.UnexpectedError("No application registry available"));
            });
    }
    
    /// <summary>
    /// Applies SCP security to incoming command.
    /// This validates and potentially decrypts/verifies the command MAC.
    /// </summary>
    private static Result<ParsedCommand, SmartCardError> ApplyScpSecurity(
        ParsedCommand cmd,
        CardState state,
        LoggingService logging)
    {
        // Apply SCP enforcement rules per GP Appendix E before command execution
        var securityValidationResult = ScpEnforcer.ValidateCommandSecurity(cmd.Ins, state, cmd.FullCommand);
        
        if (securityValidationResult.IsFailure)
        {
            logging.LogWarning(
                "SCP validation failed for INS=0x{Ins:X2}: {Error}",
                cmd.Ins,
                securityValidationResult.Error.Message);
            return Result.Failure<ParsedCommand, SmartCardError>(securityValidationResult.Error);
        }
        
        logging.LogDebug(
            "SCP validation passed for INS=0x{Ins:X2}, security level=0x{Level:X2}",
            cmd.Ins,
            state.SecurityLevel);
        
        return Result.Success<ParsedCommand, SmartCardError>(cmd);
    }
    
    /// <summary>
    /// Converts our new Applications.ApduResponse to the legacy Core.ApduResponse format.
    /// This maintains compatibility with existing response processing.
    /// </summary>
    private static Core.ApduResponse ConvertToLegacyApduResponse(Applications.ApduResponse appResponse)
    {
        return new Core.ApduResponse(
            appResponse.Data.IsDefaultOrEmpty ? [] : appResponse.Data.ToArray(),
            appResponse.StatusWord);
    }
    
    /// <summary>
    /// Safely gets the status word value for logging.
    /// </summary>
    private static ushort GetStatusWordValue(StatusWord statusWord)
    {
        return (ushort)((statusWord.SW1 << 8) | statusWord.SW2);
    }
}