using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Security;
using Gp4Net.Transport;
using Microsoft.Extensions.Logging;
using static Gp4Net.Pipeline.CommandProcessing;

namespace Gp4Net.Pipeline;

/// <summary>
/// Pure functions for command processing.
/// </summary>
public static class CommandProcessors
{
    /// <summary>
    /// Logs command execution details.
    /// </summary>
    public static CommandProcessor LogCommand = (command, environment, cancellationToken) =>
    {
        if (!environment.EffectiveOptions.EnableLogging)
            return Task.FromResult(Result.Success<CommandResult, SmartCardError>(
                CommandResult.Success(Array.Empty<byte>(), Constants.StatusWords.Success, environment)));

        var commandName = command.GetType().Name;
        var commandBytes = GetCommandBytes(command);
        
        environment.Logger.LogDebug(
            "Executing command {CommandName}: {CommandBytes}", 
            commandName, 
            Convert.ToHexString(commandBytes));
        
        return Task.FromResult(Result.Success<CommandResult, SmartCardError>(
            CommandResult.Success(Array.Empty<byte>(), Constants.StatusWords.Success, environment)));
    };

    /// <summary>
    /// Wraps command with secure channel if available and required.
    /// </summary>
    public static CommandProcessor WrapSecureChannel = async (command, environment, cancellationToken) =>
    {
        // Check if command requires secure channel
        if (!RequiresSecureChannel(command, environment))
        {
            return Result.Success<CommandResult, SmartCardError>(
                CommandResult.Success(Array.Empty<byte>(), Constants.StatusWords.Success, environment));
        }

        // Check if secure channel is available
        if (!environment.SecureChannel.HasValue)
        {
            if (environment.EffectiveOptions.RequiresSecureChannel)
            {
                return Result.Failure<CommandResult, SmartCardError>(
                    SmartCardError.SecurityError("Secure channel required but not established"));
            }
            
            return Result.Success<CommandResult, SmartCardError>(
                CommandResult.Success(Array.Empty<byte>(), Constants.StatusWords.Success, environment));
        }

        var secureChannelState = environment.SecureChannel.Value;
        
        // Build command bytes
        var commandBytes = GetCommandBytes(command);
        
        // Apply secure channel wrapping using CommandSecurityProcessor
        var wrapResult = Domain.Security.CommandSecurityProcessor.ApplyCommandSecurity(
            command,
            secureChannelState.SecurityLevel,
            secureChannelState.SessionKeys,
            secureChannelState.MacChaining.Value,
            secureChannelState.EncryptionCounter,
            secureChannelState.ProtocolVersion);
        
        if (wrapResult.IsFailure)
        {
            environment.Logger.LogError("Failed to wrap command with secure channel: {Error}", 
                wrapResult.Error.Message);
            return Result.Failure<CommandResult, SmartCardError>(wrapResult.Error);
        }
        
        var (wrappedBytes, newState) = wrapResult.Value;
        
        // Create wrapped command that carries the secured bytes
        var wrappedCommand = new WrappedApduCommand(command, wrappedBytes);
        
        // Update environment with new secure channel state
        var newEnvironment = environment.WithSecureChannel(newState);
        
        // Log the transformation
        if (environment.EffectiveOptions.EnableLogging)
        {
            environment.Logger.LogDebug(
                "Wrapped command with secure channel: CLA {OriginalCla:X2} -> {WrappedCla:X2}, Length {OriginalLength} -> {WrappedLength}",
                command.Cla, wrappedCommand.Cla, commandBytes.Length, wrappedBytes.Length);
        }
        
        // Store wrapped command in context for ExecuteTransport to use
        var metadata = new CommandMetadata(
            SecureChannelWrapped: true);
        
        // Return success but with empty data - the actual response will come from ExecuteTransport
        return Result.Success<CommandResult, SmartCardError>(
            CommandResult.Success(Array.Empty<byte>(), Constants.StatusWords.Success, newEnvironment, metadata));
    };

    /// <summary>
    /// Executes the command via transport.
    /// </summary>
    public static CommandProcessor ExecuteTransport = async (command, environment, cancellationToken) =>
    {
        var stopwatch = Stopwatch.StartNew();
        
        try
        {
            // Check if we have a wrapped command from secure channel processing
            IApduCommand commandToSend = command;
            byte[] commandBytes;
            
            // Get command bytes - use wrapped bytes if available
            if (command is WrappedApduCommand wrapped)
            {
                commandBytes = wrapped.WrappedBytes;
                commandToSend = wrapped; // WrappedApduCommand implements ICompleteApduCommand
            }
            else
            {
                commandBytes = GetCommandBytes(command);
            }
            
            // Log the actual command being sent
            if (environment.EffectiveOptions.EnableLogging)
            {
                environment.Logger.LogDebug(
                    "Transmitting command: {CommandHex}",
                    Convert.ToHexString(commandBytes));
            }
            
            // Execute via transport
            var response = await environment.Transport.TransmitAsync(
                commandToSend, 
                environment.Channel, 
                cancellationToken);
            
            stopwatch.Stop();
            
            // Combine response bytes for metadata
            var responseBytes = CombineResponseBytes(response.Data, response.StatusWord);
            
            var metadata = new CommandMetadata(
                ExecutionTime: stopwatch.Elapsed,
                TransmittedBytes: commandBytes,
                ReceivedBytes: responseBytes);
            
            return Result.Success<CommandResult, SmartCardError>(
                CommandResult.Success(response.Data, response.StatusWord, environment, metadata));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            stopwatch.Stop();
            environment.Logger.LogError(ex, "Transport execution failed");
            
            return Result.Failure<CommandResult, SmartCardError>(
                SmartCardError.CommunicationError("Failed to execute command", Maybe<Exception>.From(ex)));
        }
    };

    /// <summary>
    /// Unwraps secure channel response if needed.
    /// </summary>
    public static CommandProcessor UnwrapSecureChannel = (command, environment, cancellationToken) =>
    {
        // This processor is a pass-through for now since secure channel unwrapping
        // is not implemented yet. We preserve the response data from ExecuteTransport.
        // The actual unwrapping would happen here in a complete implementation.
        
        // Return success without data - FunctionComposition will preserve data from ExecuteTransport
        var metadata = new CommandMetadata(SecureChannelUnwrapped: true);
        return Task.FromResult(Result.Success<CommandResult, SmartCardError>(
            CommandResult.Success(Array.Empty<byte>(), Constants.StatusWords.Success, environment, metadata)));
    };

    /// <summary>
    /// Logs response details.
    /// </summary>
    public static CommandProcessor LogResponse = (command, environment, cancellationToken) =>
    {
        if (!environment.EffectiveOptions.EnableLogging)
        {
            var metadata = new CommandMetadata(ResponseLogged: true);
            return Task.FromResult(Result.Success<CommandResult, SmartCardError>(
                CommandResult.Success(Array.Empty<byte>(), Constants.StatusWords.Success, environment, metadata)));
        }

        // This would log the response from previous processors
        environment.Logger.LogDebug("Command completed");
        
        var logMetadata = new CommandMetadata(ResponseLogged: true);
        return Task.FromResult(Result.Success<CommandResult, SmartCardError>(
            CommandResult.Success(Array.Empty<byte>(), Constants.StatusWords.Success, environment, logMetadata)));
    };

    /// <summary>
    /// Creates a processor that executes the complete command pipeline.
    /// </summary>
    public static CommandProcessor CreatePipeline(bool enableLogging = true, bool enableSecureChannel = true)
    {
        var processors = new[]
        {
            enableLogging ? LogCommand : FunctionComposition.Identity,
            enableSecureChannel ? WrapSecureChannel : FunctionComposition.Identity,
            ExecuteTransport,
            enableSecureChannel ? UnwrapSecureChannel : FunctionComposition.Identity,
            enableLogging ? LogResponse : FunctionComposition.Identity
        };
        
        return FunctionComposition.ComposeMany(processors);
    }

    /// <summary>
    /// Determines if a command requires secure channel wrapping.
    /// </summary>
    private static bool RequiresSecureChannel(IApduCommand command, CommandEnvironment environment)
    {
        // Commands that never require secure channel
        if (command is SelectCommand or InitializeUpdateCommand)
            return false;
            
        // Check command options
        return environment.EffectiveOptions.RequiresSecureChannel;
    }

    /// <summary>
    /// Gets the byte representation of a command.
    /// </summary>
    private static byte[] GetCommandBytes(IApduCommand command)
    {
        var buffer = new System.Collections.Generic.List<byte> 
        { 
            command.Cla, 
            command.Ins, 
            command.P1, 
            command.P2 
        };

        if (command.Data?.Length > 0)
        {
            if (command.Data.Length > 255)
            {
                buffer.Add(0x00);
                buffer.Add((byte)(command.Data.Length >> 8));
                buffer.Add((byte)(command.Data.Length & 0xFF));
            }
            else
            {
                buffer.Add((byte)command.Data.Length);
            }
            buffer.AddRange(command.Data);
        }

        if (command.ExpectedResponseLength.HasValue)
        {
            var le = command.ExpectedResponseLength.Value;
            if (le == 0)
            {
                buffer.Add(0x00);
            }
            else if (le <= 255)
            {
                buffer.Add((byte)le);
            }
            else
            {
                buffer.Add((byte)(le >> 8));
                buffer.Add((byte)(le & 0xFF));
            }
        }

        return buffer.ToArray();
    }

    /// <summary>
    /// Combines response data and status word into a single byte array.
    /// </summary>
    private static byte[] CombineResponseBytes(byte[] data, ushort statusWord)
    {
        var combined = new byte[data.Length + 2];
        Array.Copy(data, 0, combined, 0, data.Length);
        combined[^2] = (byte)(statusWord >> 8);
        combined[^1] = (byte)(statusWord & 0xFF);
        return combined;
    }
}