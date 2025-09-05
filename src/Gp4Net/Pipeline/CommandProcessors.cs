using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Services;
using Gp4Net.Transport;
using WSCT.Core;
using WSCT.ISO7816;
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
            return Task.FromResult(
                Result.Success<CommandResult, SmartCardError>(
                    CommandResult.Success([], Constants.Constants.StatusWords.Legacy.Success, environment)
                )
            );

        string commandName = command.GetType().Name;
        
        var commandBytesResult = GetCommandBytes(command);
        if (commandBytesResult.IsFailure)
        {
            return Task.FromResult(Result.Failure<CommandResult, SmartCardError>(commandBytesResult.Error));
        }

        byte[] commandBytes = commandBytesResult.Value;
        environment.Logger.LogDebug(
            "Executing command {CommandName}: {CommandBytes}",
            commandName,
            Convert.ToHexString(commandBytes)
        );

        return Task.FromResult(
            Result.Success<CommandResult, SmartCardError>(
                CommandResult.Success([], Constants.Constants.StatusWords.Legacy.Success, environment)
            )
        );
    };

    /// <summary>
    /// Wraps command with secure channel if available and required.
    /// </summary>
    public static CommandProcessor WrapSecureChannel = static (
        command,
        environment,
        cancellationToken
    ) =>
    {
        // Check if command requires secure channel
        bool requiresSecureChannel = RequiresSecureChannel(command, environment);
        Console.WriteLine(
            $"🔍 WrapSecureChannel: Command {command.GetType().Name} requires secure channel: {requiresSecureChannel}"
        );
        Console.WriteLine(
            $"🔍 WrapSecureChannel: EffectiveOptions.RequiresSecureChannel: {environment.EffectiveOptions.RequiresSecureChannel}"
        );

        if (!requiresSecureChannel)
        {
            return Task.FromResult(
                Result.Success<CommandResult, SmartCardError>(
                    CommandResult.Success([], Constants.Constants.StatusWords.Legacy.Success, environment)
                )
            );
        }

        // Check if secure channel is available
        if (!environment.SecureChannel.HasValue)
        {
            // Use the command-specific requiresSecureChannel flag, not the global option
            if (requiresSecureChannel)
            {
                return Task.FromResult(
                    Result.Failure<CommandResult, SmartCardError>(
                        SmartCardError.SecurityError("Secure channel required but not established")
                    )
                );
            }

            return Task.FromResult(
                Result.Success<CommandResult, SmartCardError>(
                    CommandResult.Success([], Constants.Constants.StatusWords.Legacy.Success, environment)
                )
            );
        }

        SecureChannelState secureChannelState = environment.SecureChannel.Value;

        // Apply secure channel wrapping using ScpService with proper functional handling
        environment.Logger.LogDebug("Applying command security using ScpService for protocol {Protocol:X2}", secureChannelState.ProtocolVersion);

        return Task.FromResult(
            Result.Success<byte[], SmartCardError>(command.ToBytes())
                .Bind(commandBytes => 
                    ScpService.Security.ApplyCommandSecurity(commandBytes, secureChannelState)
                        .Bind(wrapResult =>
                        {
                            (byte[] wrappedBytes, SecureChannelState newState) = wrapResult;

                            environment.Logger.LogDebug(
                                "ScpService returned {ByteCount} wrapped bytes: {WrappedBytes}",
                                wrappedBytes.Length,
                                Convert.ToHexString(wrappedBytes)
                            );

                            return Result.Success<WrappedApduCommand, SmartCardError>(
                                WrappedApduCommand.Create(wrappedBytes))
                                .Map(wrappedCommand =>
                                {
                                    // Update environment with new secure channel state and wrapped command
                                    CommandEnvironment newEnvironment = environment.WithSecureChannel(
                                        newState
                                    );

                                    // Log the transformation
                                    if (environment.EffectiveOptions.EnableLogging)
                                    {
                                        environment.Logger.LogDebug(
                                            "Applied secure channel wrapping: {OriginalLength} → {WrappedLength} bytes",
                                            commandBytes.Length,
                                            wrappedBytes.Length
                                        );
                                    }

                            // Create metadata indicating secure channel wrapping was applied
                            CommandMetadata metadata = new CommandMetadata(
                                SecureChannelWrapped: true
                            );

                            // Return wrapped bytes in Data field as expected by pipeline architecture
                            // FunctionComposition will create WrappedApduCommand from this data
                            return CommandResult.Success(
                                wrappedBytes,
                                Constants.Constants.StatusWords.Legacy.Success,
                                newEnvironment,
                                metadata
                            );
                        });
                        }))
                .MapError(error =>
                {
                    environment.Logger.LogError(
                        "Secure channel wrapping failed: {Error}",
                        error
                    );
                    return error;
                })
        );
    };

    /// <summary>
    /// Executes the command via transport.
    /// </summary>
    public static CommandProcessor ExecuteTransport = async (
        command,
        environment,
        cancellationToken
    ) =>
    {
        Stopwatch stopwatch = Stopwatch.StartNew();

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

                Console.WriteLine(
                    $"🔍 ExecuteTransport: Using wrapped command: {commandBytes.Length} bytes - {Convert.ToHexString(commandBytes)}"
                );
                environment.Logger.LogDebug(
                    "Using wrapped command: {ByteCount} bytes",
                    commandBytes.Length
                );
            }
            else
            {
                var commandBytesResult = GetCommandBytes(command);
                if (commandBytesResult.IsFailure)
                {
                    return Result.Failure<CommandResult, SmartCardError>(commandBytesResult.Error);
                }
                
                commandBytes = commandBytesResult.Value;
                Console.WriteLine(
                    $"🔍 ExecuteTransport: Using unwrapped command: {commandBytes.Length} bytes - {Convert.ToHexString(commandBytes)}"
                );
            }

            // Log the actual command being sent
            if (environment.EffectiveOptions.EnableLogging)
            {
                environment.Logger.LogDebug(
                    "Transmitting command: {CommandHex}",
                    Convert.ToHexString(commandBytes)
                );
            }

            // Execute via transport
            var transmitResult = await environment.Transport.TransmitAsync(
                commandToSend,
                environment.Channel,
                cancellationToken
            );

            if (transmitResult.IsFailure)
            {
                return Result.Failure<CommandResult, SmartCardError>(transmitResult.Error);
            }

            ApduResponse response = transmitResult.Value;

            stopwatch.Stop();

            // Combine response bytes for metadata
            byte[] responseBytes = CombineResponseBytes(response.Data, response.StatusWord);

            CommandMetadata metadata = new CommandMetadata(
                ExecutionTime: stopwatch.Elapsed,
                TransmittedBytes: commandBytes,
                ReceivedBytes: responseBytes
            );

            CommandResult transportResult = CommandResult.Success(
                response.Data,
                response.StatusWord,
                environment,
                metadata
            );

            // Apply secure channel response unwrapping if needed
            if (environment.SecureChannel.HasValue)
            {
                Func<CommandResult, Result<CommandResult, SmartCardError>> unwrapper =
                    CreateSecureChannelResponseUnwrapper(environment);
                return unwrapper(transportResult);
            }

            return Result.Success<CommandResult, SmartCardError>(transportResult);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            stopwatch.Stop();
            environment.Logger.LogError(ex, "Transport execution failed");

            return Result.Failure<CommandResult, SmartCardError>(
                SmartCardError.CommunicationError(
                    "Failed to execute command",
                    Maybe<Exception>.From(ex)
                )
            );
        }
    };

    /// <summary>
    /// Unwraps secure channel response using the active secure channel state.
    /// This processor operates on the response data from ExecuteTransport by creating a response processor.
    /// </summary>
    public static CommandProcessor UnwrapSecureChannel = (
        command,
        environment,
        cancellationToken
    ) =>
    {
        // This processor doesn't modify the command - it creates a response processor
        // that will be applied after ExecuteTransport returns the response
        CommandMetadata metadata = new(SecureChannelUnwrapped: false);
        return Task.FromResult(
            Result.Success<CommandResult, SmartCardError>(
                CommandResult.Success([], Constants.Constants.StatusWords.Legacy.Success, environment, metadata)
            )
        );
    };

    /// <summary>
    /// Creates a response processor that unwraps secure channel responses.
    /// </summary>
    public static Func<
        CommandResult,
        Result<CommandResult, SmartCardError>
    > CreateSecureChannelResponseUnwrapper(CommandEnvironment environment)
    {
        return result =>
        {
            // Check if secure channel unwrapping is needed
            if (!environment.SecureChannel.HasValue)
            {
                return Result.Success<CommandResult, SmartCardError>(result);
            }

            SecureChannelState channelState = environment.SecureChannel.Value;

            // Combine response data and status word for unwrapping
            byte[] responseBytes = CombineResponseBytes(result.Data, result.StatusWord);

            // Unwrap the complete response
            Result<byte[], SmartCardError> unwrapResult = UnwrapSecureChannelResponse(
                responseBytes,
                channelState
            );

            return unwrapResult.Match(
                unwrappedData =>
                {
                    // Extract unwrapped data and status word
                    if (unwrappedData.Length < 2)
                    {
                        return Result.Failure<CommandResult, SmartCardError>(
                            SmartCardError.CryptographicError("Unwrapped response too short")
                        );
                    }

                    ushort unwrappedStatusWord = (ushort)(
                        unwrappedData[^2] << 8 | unwrappedData[^1]
                    );
                    byte[] unwrappedResponseData = unwrappedData[..^2];

                    CommandMetadata metadata = new CommandMetadata(SecureChannelUnwrapped: true);
                    return Result.Success<CommandResult, SmartCardError>(
                        CommandResult.Success(
                            unwrappedResponseData,
                            unwrappedStatusWord,
                            result.UpdatedEnvironment,
                            metadata
                        )
                    );
                },
                error => Result.Failure<CommandResult, SmartCardError>(error)
            );
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
        SecureChannelState channelState
    )
    {
        if (encryptedResponse == null || encryptedResponse.Length == 0)
        {
            return Result.Success<byte[], SmartCardError>([]);
        }

        // Implement proper SCP02/SCP03 response unwrapping based on protocol version
        if (channelState.ProtocolVersion == CryptoService.ScpVersion.Scp02)
        {
            return UnwrapScp02Response(encryptedResponse, channelState);
        }

        if (channelState.ProtocolVersion == CryptoService.ScpVersion.Scp03)
        {
            return UnwrapScp03Response(encryptedResponse, channelState);
        }

        return Result.Failure<byte[], SmartCardError>(
            new UnsupportedProtocolError($"Unsupported SCP version: {channelState.ProtocolVersion}")
        );
    }

    /// <summary>
    /// Unwraps SCP02 encrypted response using functional cryptographic operations.
    /// </summary>
    private static Result<byte[], SmartCardError> UnwrapScp02Response(
        byte[] encryptedResponse,
        SecureChannelState channelState
    )
    {
        if (encryptedResponse.Length < 2)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Response too short for SCP02 unwrapping")
            );
        }

        // Extract status word (last 2 bytes)
        byte[] statusWord = encryptedResponse[^2..];
        byte[] responseData = encryptedResponse[..^2];

        // Check if response is encrypted (has MAC)
        if ((channelState.SecurityLevel & SecurityLevel.RMac) == 0)
        {
            // No unwrapping needed - return data + status word
            byte[] noUnwrapResult = new byte[responseData.Length + statusWord.Length];
            Array.Copy(responseData, 0, noUnwrapResult, 0, responseData.Length);
            Array.Copy(statusWord, 0, noUnwrapResult, responseData.Length, statusWord.Length);
            return Result.Success<byte[], SmartCardError>(noUnwrapResult);
        }

        // Verify and strip MAC (last 8 bytes before status word)
        if (responseData.Length < 8)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.CryptographicError("Response too short to contain MAC")
            );
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
                        SmartCardError.CryptographicError("SCP02 response MAC verification failed")
                    );
                }

                // Decrypt response data if encryption is enabled
                if ((channelState.SecurityLevel & SecurityLevel.REncryption) != 0)
                {
                    return DecryptScp02ResponseData(dataWithoutMac, channelState)
                        .Map(decryptedData =>
                        {
                            byte[] result = new byte[decryptedData.Length + statusWord.Length];
                            Array.Copy(decryptedData, 0, result, 0, decryptedData.Length);
                            Array.Copy(
                                statusWord,
                                0,
                                result,
                                decryptedData.Length,
                                statusWord.Length
                            );
                            return result;
                        });
                }

                // Return data + status word
                byte[] result = new byte[dataWithoutMac.Length + statusWord.Length];
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
        SecureChannelState channelState
    )
    {
        if (encryptedResponse.Length < 2)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.InvalidArgument("Response too short for SCP03 unwrapping")
            );
        }

        // Extract status word (last 2 bytes)
        byte[] statusWord = encryptedResponse[^2..];
        byte[] responseData = encryptedResponse[..^2];

        // Check if response has MAC
        if ((channelState.SecurityLevel & SecurityLevel.RMac) == 0)
        {
            // No unwrapping needed - return data + status word
            byte[] noUnwrapResult = new byte[responseData.Length + statusWord.Length];
            Array.Copy(responseData, 0, noUnwrapResult, 0, responseData.Length);
            Array.Copy(statusWord, 0, noUnwrapResult, responseData.Length, statusWord.Length);
            return Result.Success<byte[], SmartCardError>(noUnwrapResult);
        }

        // Verify and strip MAC (last 16 bytes before status word for AES-CMAC)
        if (responseData.Length < 16)
        {
            return Result.Failure<byte[], SmartCardError>(
                SmartCardError.CryptographicError("Response too short to contain AES-CMAC")
            );
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
                        SmartCardError.CryptographicError("SCP03 response MAC verification failed")
                    );
                }

                // Decrypt response data if encryption is enabled
                if ((channelState.SecurityLevel & SecurityLevel.REncryption) != 0)
                {
                    return DecryptScp03ResponseData(dataWithoutMac, channelState)
                        .Map(decryptedData =>
                        {
                            byte[] result = new byte[decryptedData.Length + statusWord.Length];
                            Array.Copy(decryptedData, 0, result, 0, decryptedData.Length);
                            Array.Copy(
                                statusWord,
                                0,
                                result,
                                decryptedData.Length,
                                statusWord.Length
                            );
                            return result;
                        });
                }

                // Return data + status word
                byte[] result = new byte[dataWithoutMac.Length + statusWord.Length];
                Array.Copy(dataWithoutMac, 0, result, 0, dataWithoutMac.Length);
                Array.Copy(statusWord, 0, result, dataWithoutMac.Length, statusWord.Length);
                return Result.Success<byte[], SmartCardError>(result);
            });
    }

    /// <summary>
    /// Verifies SCP02 response MAC using centralized SCP operations.
    /// </summary>
    private static Result<bool, SmartCardError> VerifyScp02ResponseMac(
        byte[] responseData,
        byte[] receivedMac,
        byte[] statusWord,
        SecureChannelState channelState
    )
    {
        // Construct complete response: response data + status word
        byte[] fullResponse = [.. responseData, .. statusWord];

        // Use centralized SCP02 response MAC calculation with proper chaining
        return CryptoService.ScpOperations.Scp02.CalculateResponseMac(
                fullResponse,
                channelState.SessionKeys.SrMac,
                channelState.MacChainingValue
            )
            .Map(calculatedMac =>
            {
                // Compare MACs using constant-time comparison
                return CryptoService.Utils.CompareBytes(calculatedMac, receivedMac);
            });
    }

    /// <summary>
    /// Verifies SCP03 response MAC using centralized SCP operations.
    /// </summary>
    private static Result<bool, SmartCardError> VerifyScp03ResponseMac(
        byte[] responseData,
        byte[] receivedMac,
        byte[] statusWord,
        SecureChannelState channelState
    )
    {
        // Construct complete response: response data + status word
        byte[] fullResponse = [.. responseData, .. statusWord];

        // Use centralized SCP03 response MAC calculation with proper chaining
        return CryptoService.ScpOperations.Scp03.CalculateResponseMac(
                fullResponse,
                channelState.SessionKeys.SrMac,
                channelState.MacChainingValue
            )
            .Map(calculatedMac =>
            {
                // Compare MACs using constant-time comparison
                return CryptoService.Utils.CompareBytes(calculatedMac, receivedMac);
            });
    }

    /// <summary>
    /// Decrypts SCP02 response data using centralized cipher operations.
    /// </summary>
    private static Result<byte[], SmartCardError> DecryptScp02ResponseData(
        byte[] encryptedData,
        SecureChannelState channelState
    )
    {
        if (encryptedData.Length == 0)
        {
            return Result.Success<byte[], SmartCardError>([]);
        }

        // Use centralized cipher operation with SCP02 parameters (zero IV for response decryption)
        return CryptoService.Cipher.Decrypt3DesCbc(channelState.SessionKeys.SEnc, Constants.Constants.Scp.Common.ZeroIv8, encryptedData);
    }

    /// <summary>
    /// Decrypts SCP03 response data using centralized cipher operations.
    /// </summary>
    private static Result<byte[], SmartCardError> DecryptScp03ResponseData(
        byte[] encryptedData,
        SecureChannelState channelState
    )
    {
        if (encryptedData.Length == 0)
        {
            return Result.Success<byte[], SmartCardError>([]);
        }

        // Use centralized cipher operation with SCP03 parameters (zero IV for response decryption)
        return CryptoService.Cipher.DecryptAesCbc(channelState.SessionKeys.SEnc, Constants.Constants.Scp.Common.ZeroIv16, encryptedData);
    }

    /// <summary>
    /// Logs response details.
    /// </summary>
    public static CommandProcessor LogResponse = (command, environment, cancellationToken) =>
    {
        if (!environment.EffectiveOptions.EnableLogging)
        {
            CommandMetadata metadata = new CommandMetadata(ResponseLogged: true);
            return Task.FromResult(
                Result.Success<CommandResult, SmartCardError>(
                    CommandResult.Success([], Constants.Constants.StatusWords.Legacy.Success, environment, metadata)
                )
            );
        }

        // This would log the response from previous processors
        environment.Logger.LogDebug("Command completed");

        CommandMetadata logMetadata = new CommandMetadata(ResponseLogged: true);
        return Task.FromResult(
            Result.Success<CommandResult, SmartCardError>(
                CommandResult.Success([], Constants.Constants.StatusWords.Legacy.Success, environment, logMetadata)
            )
        );
    };

    /// <summary>
    /// Creates a processor that executes the complete command pipeline.
    /// Secure channel unwrapping is now integrated into ExecuteTransport.
    /// </summary>
    public static CommandProcessor CreatePipeline(
        bool enableLogging = true,
        bool enableSecureChannel = true
    )
    {
        CommandProcessor[] processors =
        [
            enableLogging ? LogCommand : FunctionComposition.Identity,
            enableSecureChannel ? WrapSecureChannel : FunctionComposition.Identity,
            ExecuteTransport, // Now includes secure channel unwrapping
            enableLogging ? LogResponse : FunctionComposition.Identity,
        ];

        return FunctionComposition.ComposeMany(processors);
    }

    /// <summary>
    /// Determines if a command requires secure channel wrapping.
    /// Per GlobalPlatform Card Specification v2.3.1:
    /// - SELECT (to ISD or applications) does not require secure channel for initial selection
    /// - INITIALIZE UPDATE starts secure channel establishment (cannot be wrapped)
    /// - EXTERNAL AUTHENTICATE completes secure channel establishment (cannot be wrapped)
    /// </summary>
    private static bool RequiresSecureChannel(IApduCommand command, CommandEnvironment environment)
    {
        // Commands that never require secure channel per GP specification:
        // - SELECT: Used to establish application context (both ISD and applications)
        // - INITIALIZE UPDATE: Starts secure channel establishment (runs before channel exists)
        // - EXTERNAL AUTHENTICATE: Completes secure channel establishment (validates but doesn't require existing channel)
        if (command is SelectCommand or InitializeUpdateCommand or ExternalAuthenticateCommand)
            return false;

        // For all other commands, check if secure channel is required
        // This includes GET DATA, PUT KEY, DELETE, INSTALL, LOAD, etc.
        return environment.EffectiveOptions.RequiresSecureChannel;
    }

    /// <summary>
    /// Gets the byte representation of a command.
    /// </summary>
    private static Result<byte[], SmartCardError> GetCommandBytes(IApduCommand command)
    {
        return Result.Success<byte[], SmartCardError>(command.ToBytes());
    }

    /// <summary>
    /// Combines response data and status word into a single byte array.
    /// </summary>
    private static byte[] CombineResponseBytes(byte[] data, ushort statusWord)
    {
        byte[] combined = new byte[data.Length + 2];
        Array.Copy(data, 0, combined, 0, data.Length);
        combined[^2] = (byte)(statusWord >> 8);
        combined[^1] = (byte)(statusWord & 0xFF);
        return combined;
    }
}
