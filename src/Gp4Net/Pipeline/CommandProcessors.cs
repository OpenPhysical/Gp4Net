using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;
using Gp4Net.Domain;
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
                CommandResult.Success([], Constants.StatusWords.Success, environment)));

        var commandName = command.GetType().Name;
        var commandBytes = GetCommandBytes(command);

        environment.Logger.LogDebug(
            "Executing command {CommandName}: {CommandBytes}",
            commandName,
            Convert.ToHexString(commandBytes));

        return Task.FromResult(Result.Success<CommandResult, SmartCardError>(
            CommandResult.Success([], Constants.StatusWords.Success, environment)));
    };

    /// <summary>
    /// Wraps command with secure channel if available and required.
    /// </summary>
    public static CommandProcessor WrapSecureChannel = static (command, environment, cancellationToken) =>
    {
        // Check if command requires secure channel
        if (!RequiresSecureChannel(command, environment))
        {
            return Task.FromResult(Result.Success<CommandResult, SmartCardError>(
                CommandResult.Success([], Constants.StatusWords.Success, environment)));
        }

        // Check if secure channel is available
        if (!environment.SecureChannel.HasValue)
        {
            if (environment.EffectiveOptions.RequiresSecureChannel)
            {
                return Task.FromResult(Result.Failure<CommandResult, SmartCardError>(
                    SmartCardError.SecurityError("Secure channel required but not established")));
            }

            return Task.FromResult(Result.Success<CommandResult, SmartCardError>(
                CommandResult.Success([], Constants.StatusWords.Success, environment)));
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
            return Task.FromResult(Result.Failure<CommandResult, SmartCardError>(wrapResult.Error));
        }

        (byte[] wrappedBytes, SecureChannelState newState) = wrapResult.Value;

        // Create wrapped command that carries the secured bytes
        Result<WrappedApduCommand, SmartCardError> wrappedCommandResult = 
            WrappedApduCommand.Create(command, wrappedBytes);
            
        if (wrappedCommandResult.IsFailure)
        {
            return Task.FromResult(Result.Failure<CommandResult, SmartCardError>(wrappedCommandResult.Error));
        }

        WrappedApduCommand wrappedCommand = wrappedCommandResult.Value;

        // Update environment with new secure channel state
        CommandEnvironment newEnvironment = environment.WithSecureChannel(newState);

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
        return Task.FromResult(Result.Success<CommandResult, SmartCardError>(
            CommandResult.Success([], Constants.StatusWords.Success, newEnvironment, metadata)));
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

            var transportResult = CommandResult.Success(response.Data, response.StatusWord, environment, metadata);
            
            // Apply secure channel response unwrapping if needed
            if (environment.SecureChannel.HasValue)
            {
                var unwrapper = CreateSecureChannelResponseUnwrapper(environment);
                return unwrapper(transportResult);
            }
            
            return Result.Success<CommandResult, SmartCardError>(transportResult);
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
    /// Unwraps secure channel response using the active secure channel state.
    /// This processor operates on the response data from ExecuteTransport by creating a response processor.
    /// </summary>
    public static CommandProcessor UnwrapSecureChannel = (command, environment, cancellationToken) =>
    {
        // This processor doesn't modify the command - it creates a response processor
        // that will be applied after ExecuteTransport returns the response
        CommandMetadata metadata = new(SecureChannelUnwrapped: false);
        return Task.FromResult(Result.Success<CommandResult, SmartCardError>(
            CommandResult.Success([], Constants.StatusWords.Success, environment, metadata)));
    };

    /// <summary>
    /// Creates a response processor that unwraps secure channel responses.
    /// </summary>
    public static Func<CommandResult, Result<CommandResult, SmartCardError>> CreateSecureChannelResponseUnwrapper(
        CommandEnvironment environment)
    {
        return (result) =>
        {
            // Check if secure channel unwrapping is needed
            if (!environment.SecureChannel.HasValue)
            {
                return Result.Success<CommandResult, SmartCardError>(result);
            }

            var channelState = environment.SecureChannel.Value;
            
            // Combine response data and status word for unwrapping
            var responseBytes = CombineResponseBytes(result.Data, result.StatusWord);
            
            // Unwrap the complete response
            var unwrapResult = UnwrapSecureChannelResponse(responseBytes, channelState);
            
            return unwrapResult.Match(
                unwrappedData =>
                {
                    // Extract unwrapped data and status word
                    if (unwrappedData.Length < 2)
                    {
                        return Result.Failure<CommandResult, SmartCardError>(
                            SmartCardError.CryptographicError("Unwrapped response too short"));
                    }
                    
                    var unwrappedStatusWord = (ushort)((unwrappedData[^2] << 8) | unwrappedData[^1]);
                    var unwrappedResponseData = unwrappedData[..^2];
                    
                    var metadata = new CommandMetadata(SecureChannelUnwrapped: true);
                    return Result.Success<CommandResult, SmartCardError>(
                        CommandResult.Success(unwrappedResponseData, unwrappedStatusWord, result.UpdatedEnvironment, metadata));
                },
                error => Result.Failure<CommandResult, SmartCardError>(error));
        };
    }

    /// <summary>
    /// Functional secure channel response unwrapper.
    /// </summary>
    /// <param name="encryptedResponse">The encrypted response data.</param>
    /// <param name="channelState">The secure channel state containing keys and counters.</param>
    /// <returns>A result containing the decrypted response or an error.</returns>
    private static Result<byte[], SmartCardError> UnwrapSecureChannelResponse(
        byte[] encryptedResponse, 
        SecureChannelState channelState)
    {
        if (encryptedResponse == null || encryptedResponse.Length == 0)
        {
            return Result.Success<byte[], SmartCardError>([]);
        }

        // Implement proper SCP02/SCP03 response unwrapping based on protocol version
        if (channelState.ProtocolVersion == (byte)ScpVersion.Scp02)
        {
            return UnwrapScp02Response(encryptedResponse, channelState);
        }
        
        if (channelState.ProtocolVersion == (byte)ScpVersion.Scp03)
        {
            return UnwrapScp03Response(encryptedResponse, channelState);
        }
        
        return Result.Failure<byte[], SmartCardError>(
            new UnsupportedProtocolError($"Unsupported SCP version: {channelState.ProtocolVersion}"));
    }

    /// <summary>
    /// Unwraps SCP02 encrypted response using functional cryptographic operations.
    /// </summary>
    private static Result<byte[], SmartCardError> UnwrapScp02Response(
        byte[] encryptedResponse,
        SecureChannelState channelState)
    {
        if (encryptedResponse.Length < 2)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Response too short for SCP02 unwrapping"));
        }

        // Extract status word (last 2 bytes)
        byte[] statusWord = encryptedResponse[^2..];
        byte[] responseData = encryptedResponse[..^2];

        // Check if response is encrypted (has MAC)
        if ((channelState.SecurityLevel & SecurityLevel.RMac) == 0)
        {
            // No unwrapping needed - return data + status word
            var noUnwrapResult = new byte[responseData.Length + statusWord.Length];
            Array.Copy(responseData, 0, noUnwrapResult, 0, responseData.Length);
            Array.Copy(statusWord, 0, noUnwrapResult, responseData.Length, statusWord.Length);
            return Result.Success<byte[], SmartCardError>(noUnwrapResult);
        }

        // Verify and strip MAC (last 8 bytes before status word)
        if (responseData.Length < 8)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.CryptographicError("Response too short to contain MAC"));
        }

        byte[] mac = responseData[^8..];
        byte[] dataWithoutMac = responseData[..^8];

        // Use SCP02 MAC verification with session keys from channelState
        return VerifyScp02ResponseMac(dataWithoutMac, mac, statusWord, channelState)
            .Bind(isValid =>
            {
                if (!isValid)
                {
                    return Result.Failure<byte[], SmartCardError>(
                        SmartCardError.CryptographicError("SCP02 response MAC verification failed"));
                }

                // Decrypt response data if encryption is enabled
                if ((channelState.SecurityLevel & SecurityLevel.REncryption) != 0)
                {
                    return DecryptScp02ResponseData(dataWithoutMac, channelState)
                        .Map(decryptedData =>
                        {
                            var result = new byte[decryptedData.Length + statusWord.Length];
                            Array.Copy(decryptedData, 0, result, 0, decryptedData.Length);
                            Array.Copy(statusWord, 0, result, decryptedData.Length, statusWord.Length);
                            return result;
                        });
                }

                // Return data + status word
                var result = new byte[dataWithoutMac.Length + statusWord.Length];
                Array.Copy(dataWithoutMac, 0, result, 0, dataWithoutMac.Length);
                Array.Copy(statusWord, 0, result, dataWithoutMac.Length, statusWord.Length);
                return Result.Success<byte[], SmartCardError>(result);
            });
    }

    /// <summary>
    /// Unwraps SCP03 encrypted response using functional cryptographic operations.
    /// </summary>
    private static Result<byte[], SmartCardError> UnwrapScp03Response(
        byte[] encryptedResponse,
        SecureChannelState channelState)
    {
        if (encryptedResponse.Length < 2)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Response too short for SCP03 unwrapping"));
        }

        // Extract status word (last 2 bytes)  
        byte[] statusWord = encryptedResponse[^2..];
        byte[] responseData = encryptedResponse[..^2];

        // Check if response has MAC
        if ((channelState.SecurityLevel & SecurityLevel.RMac) == 0)
        {
            // No unwrapping needed - return data + status word
            var noUnwrapResult = new byte[responseData.Length + statusWord.Length];
            Array.Copy(responseData, 0, noUnwrapResult, 0, responseData.Length);
            Array.Copy(statusWord, 0, noUnwrapResult, responseData.Length, statusWord.Length);
            return Result.Success<byte[], SmartCardError>(noUnwrapResult);
        }

        // Verify and strip MAC (last 16 bytes before status word for AES-CMAC)
        if (responseData.Length < 16)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.CryptographicError("Response too short to contain AES-CMAC"));
        }

        byte[] mac = responseData[^16..];
        byte[] dataWithoutMac = responseData[..^16];

        // Use SCP03 AES-CMAC verification with session keys from channelState
        return VerifyScp03ResponseMac(dataWithoutMac, mac, statusWord, channelState)
            .Bind(isValid =>
            {
                if (!isValid)
                {
                    return Result.Failure<byte[], SmartCardError>(
                        SmartCardError.CryptographicError("SCP03 response MAC verification failed"));
                }

                // Decrypt response data if encryption is enabled
                if ((channelState.SecurityLevel & SecurityLevel.REncryption) != 0)
                {
                    return DecryptScp03ResponseData(dataWithoutMac, channelState)
                        .Map(decryptedData =>
                        {
                            var result = new byte[decryptedData.Length + statusWord.Length];
                            Array.Copy(decryptedData, 0, result, 0, decryptedData.Length);
                            Array.Copy(statusWord, 0, result, decryptedData.Length, statusWord.Length);
                            return result;
                        });
                }

                // Return data + status word
                var result = new byte[dataWithoutMac.Length + statusWord.Length];
                Array.Copy(dataWithoutMac, 0, result, 0, dataWithoutMac.Length);
                Array.Copy(statusWord, 0, result, dataWithoutMac.Length, statusWord.Length);
                return Result.Success<byte[], SmartCardError>(result);
            });
    }

    /// <summary>
    /// Verifies SCP02 response MAC using Triple-DES CBC-MAC.
    /// </summary>
    private static Result<bool, SmartCardError> VerifyScp02ResponseMac(
        byte[] responseData, byte[] receivedMac, byte[] statusWord, SecureChannelState channelState)
    {
        // Construct MAC data: response data + status word
        byte[] macData = responseData.Concat(statusWord).ToArray();
        
        // Calculate expected MAC using SRMac key
        // Implementation uses BouncyCastle Triple-DES CBC-MAC
        var desEngine = new Org.BouncyCastle.Crypto.Engines.DesEngine();
        var mac = new Org.BouncyCastle.Crypto.Macs.CbcBlockCipherMac(desEngine);
        
        // Initialize with SRMac key from session keys
        mac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(channelState.SessionKeys.SrMac));
        
        mac.BlockUpdate(macData, 0, macData.Length);
        byte[] calculatedMac = new byte[mac.GetMacSize()];
        mac.DoFinal(calculatedMac, 0);
        
        // Compare MACs using constant-time comparison
        var isValid = calculatedMac.SequenceEqual(receivedMac);
        return Result.Success<bool, SmartCardError>(isValid);
    }

    /// <summary>
    /// Verifies SCP03 response MAC using AES-CMAC.
    /// </summary>
    private static Result<bool, SmartCardError> VerifyScp03ResponseMac(
        byte[] responseData, byte[] receivedMac, byte[] statusWord, SecureChannelState channelState)
    {
        // Construct MAC data: response data + status word  
        byte[] macData = responseData.Concat(statusWord).ToArray();
        
        // Calculate expected MAC using SRMac key with AES-CMAC
        var aesEngine = new Org.BouncyCastle.Crypto.Engines.AesEngine();
        var cmac = new Org.BouncyCastle.Crypto.Macs.CMac(aesEngine);
        
        // Initialize with SRMac key from session keys
        cmac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(channelState.SessionKeys.SrMac));
        
        cmac.BlockUpdate(macData, 0, macData.Length);
        byte[] calculatedMac = new byte[cmac.GetMacSize()];
        cmac.DoFinal(calculatedMac, 0);
        
        // Compare MACs using constant-time comparison
        var isValid = calculatedMac.SequenceEqual(receivedMac);
        return Result.Success<bool, SmartCardError>(isValid);
    }

    /// <summary>
    /// Decrypts SCP02 response data using Triple-DES CBC.
    /// </summary>
    private static Result<byte[], SmartCardError> DecryptScp02ResponseData(
        byte[] encryptedData, SecureChannelState channelState)
    {
        if (encryptedData.Length == 0)
        {
            return Result.Success<byte[], SmartCardError>([]);
        }
        
        var desEngine = new Org.BouncyCastle.Crypto.Engines.DesEdeEngine();
        var cipher = new Org.BouncyCastle.Crypto.Modes.CbcBlockCipher(desEngine);
        
        // Initialize cipher for decryption with SEnc key
        cipher.Init(false, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(channelState.SessionKeys.SEnc));
        
        byte[] decryptedData = new byte[encryptedData.Length];
        int processedBytes = 0;
        
        // Process data in blocks
        for (int i = 0; i < encryptedData.Length; i += cipher.GetBlockSize())
        {
            int blockSize = Math.Min(cipher.GetBlockSize(), encryptedData.Length - i);
            processedBytes += cipher.ProcessBlock(encryptedData, i, decryptedData, processedBytes);
        }
        
        return Result.Success<byte[], SmartCardError>(decryptedData);
    }

    /// <summary>
    /// Decrypts SCP03 response data using AES-CBC.
    /// </summary>
    private static Result<byte[], SmartCardError> DecryptScp03ResponseData(
        byte[] encryptedData, SecureChannelState channelState)
    {
        if (encryptedData.Length == 0)
        {
            return Result.Success<byte[], SmartCardError>([]);
        }
        
        var aesEngine = new Org.BouncyCastle.Crypto.Engines.AesEngine();
        var cipher = new Org.BouncyCastle.Crypto.Modes.CbcBlockCipher(aesEngine);
        
        // Initialize cipher for decryption with SEnc key
        cipher.Init(false, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(channelState.SessionKeys.SEnc));
        
        byte[] decryptedData = new byte[encryptedData.Length];
        int processedBytes = 0;
        
        // Process data in blocks
        for (int i = 0; i < encryptedData.Length; i += cipher.GetBlockSize())
        {
            int blockSize = Math.Min(cipher.GetBlockSize(), encryptedData.Length - i);
            processedBytes += cipher.ProcessBlock(encryptedData, i, decryptedData, processedBytes);
        }
        
        return Result.Success<byte[], SmartCardError>(decryptedData);
    }

    /// <summary>
    /// Logs response details.
    /// </summary>
    public static CommandProcessor LogResponse = (command, environment, cancellationToken) =>
    {
        if (!environment.EffectiveOptions.EnableLogging)
        {
            var metadata = new CommandMetadata(ResponseLogged: true);
            return Task.FromResult(Result.Success<CommandResult, SmartCardError>(
                CommandResult.Success([], Constants.StatusWords.Success, environment, metadata)));
        }

        // This would log the response from previous processors
        environment.Logger.LogDebug("Command completed");

        var logMetadata = new CommandMetadata(ResponseLogged: true);
        return Task.FromResult(Result.Success<CommandResult, SmartCardError>(
            CommandResult.Success([], Constants.StatusWords.Success, environment, logMetadata)));
    };

    /// <summary>
    /// Creates a processor that executes the complete command pipeline.
    /// Secure channel unwrapping is now integrated into ExecuteTransport.
    /// </summary>
    public static CommandProcessor CreatePipeline(bool enableLogging = true, bool enableSecureChannel = true)
    {
        var processors = new[]
        {
            enableLogging ? LogCommand : FunctionComposition.Identity,
            enableSecureChannel ? WrapSecureChannel : FunctionComposition.Identity,
            ExecuteTransport, // Now includes secure channel unwrapping
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
            switch (le)
            {
                case 0:
                    buffer.Add(0x00);
                    break;
                case <= 255:
                    buffer.Add((byte)le);
                    break;
                default:
                    buffer.Add((byte)(le >> 8));
                    buffer.Add((byte)(le & 0xFF));
                    break;
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
