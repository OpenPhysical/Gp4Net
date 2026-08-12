using System;
using System.Diagnostics;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Domain;
using Gp4Net.Services;
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
    /// Logs command execution details with support for verbose and debug levels.
    /// </summary>
    public static CommandProcessor LogCommand = (command, environment, cancellationToken) =>
    {
        if (!environment.Options.EnableLogging)
            return Task.FromResult(
                Result.Success<CommandResult, SmartCardError>(
                    CommandResult.Success(
                        [],
                        Constants.Constants.StatusWords.Legacy.Success,
                        environment
                    )
                )
            );

        string commandName = command.GetType().Name;

        var commandBytesResult = GetCommandBytes(command);
        if (commandBytesResult.IsFailure)
        {
            return Task.FromResult(
                Result.Failure<CommandResult, SmartCardError>(commandBytesResult.Error)
            );
        }

        byte[] commandBytes = commandBytesResult.Value;

        // Verbose logging: Show pre-wrapping APDU details
        if (environment.Options.VerboseLogging)
        {
            environment.Logger.LogInformation(
                "[VERBOSE] Pre-wrap APDU: {CommandName} -> {CommandBytes}",
                commandName,
                Convert.ToHexString(commandBytes)
            );

            // Parse and display APDU structure for verbose mode
            LogApduStructure(environment.Logger, commandBytes, "Pre-wrap");
        }
        else if (environment.Options.DebugLogging)
        {
            environment.Logger.LogDebug(
                "Executing command {CommandName}: {CommandBytes}",
                commandName,
                Convert.ToHexString(commandBytes)
            );
        }

        return Task.FromResult(
            Result.Success<CommandResult, SmartCardError>(
                CommandResult.Success(
                    [],
                    Constants.Constants.StatusWords.Legacy.Success,
                    environment
                )
            )
        );
    };

    /// <summary>
    /// Wraps command with secure channel if explicitly requested.
    /// </summary>
    public static CommandProcessor WrapSecureChannel = static (
        command,
        environment,
        cancellationToken
    ) =>
    {
        // Check if caller explicitly wants secure channel
        if (!environment.Options.UseSecureChannel)
        {
            // No secure channel requested - pass through
            return Task.FromResult(
                Result.Success<CommandResult, SmartCardError>(
                    CommandResult.Success(
                        [],
                        Constants.Constants.StatusWords.Legacy.Success,
                        environment
                    )
                )
            );
        }

        // Secure channel was explicitly requested - check if it's available
        if (!environment.SecureChannel.HasValue)
        {
            return Task.FromResult(
                Result.Failure<CommandResult, SmartCardError>(
                    SmartCardError.SecurityError("Secure channel requested but not established")
                )
            );
        }

        var secureChannelState = environment.SecureChannel.Value;

        // Apply secure channel wrapping using ScpService with proper functional handling
        environment.Logger.LogDebug(
            "Applying command security using ScpService for protocol {Protocol:X2}",
            (byte)secureChannelState.ProtocolVersion
        );

        return Task.FromResult(
            Result
                .Success<byte[], SmartCardError>(command.ToBytes())
                .Bind(commandBytes =>
                    ScpService
                        .Security.ApplyCommandSecurity(
                            new WSCT.ISO7816.CommandAPDU(commandBytes),
                            secureChannelState
                        )
                        .Bind(wrapResult =>
                        {
                            (WSCT.ISO7816.CommandAPDU wrappedCommand, var newState) = wrapResult;
                            byte[] wrappedBytes = wrappedCommand.BinaryCommand;

                            // Log secure channel wrapping details
                            if (environment.Options.VerboseLogging)
                            {
                                environment.Logger.LogInformation(
                                    "[VERBOSE] Post-wrap APDU: Secured with SCP{Protocol:X2} -> {WrappedBytes}",
                                    (byte)secureChannelState.ProtocolVersion,
                                    Convert.ToHexString(wrappedBytes)
                                );
                                LogApduStructure(
                                    environment.Logger,
                                    wrappedBytes,
                                    "Post-wrap (Secured)"
                                );
                            }
                            else if (environment.Options.DebugLogging)
                            {
                                environment.Logger.LogDebug(
                                    "ScpService returned {ByteCount} wrapped bytes: {WrappedBytes}",
                                    wrappedBytes.Length,
                                    Convert.ToHexString(wrappedBytes)
                                );
                            }

                            return Result
                                .Success<WrappedApduCommand, SmartCardError>(
                                    WrappedApduCommand.Create(wrappedBytes)
                                )
                                .Map(wrappedCommand =>
                                {
                                    // Update environment with new secure channel state and wrapped command
                                    var newEnvironment = environment.WithSecureChannel(newState);

                                    // Log the transformation
                                    if (environment.Options.EnableLogging)
                                    {
                                        environment.Logger.LogDebug(
                                            "Applied secure channel wrapping: {OriginalLength} → {WrappedLength} bytes",
                                            commandBytes.Length,
                                            wrappedBytes.Length
                                        );
                                    }

                                    // Create metadata indicating secure channel wrapping was applied
                                    var metadata = new CommandMetadata(SecureChannelWrapped: true);

                                    // Return wrapped bytes in Data field as expected by pipeline architecture
                                    // FunctionComposition will create WrappedApduCommand from this data
                                    return CommandResult.Success(
                                        wrappedBytes,
                                        Constants.Constants.StatusWords.Legacy.Success,
                                        newEnvironment,
                                        metadata
                                    );
                                });
                        })
                )
                .MapError(error =>
                {
                    environment.Logger.LogError("Secure channel wrapping failed: {Error}", error);
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
        var stopwatch = Stopwatch.StartNew();

        // Get command bytes - use wrapped bytes if available
        var commandBytesResult = command is WrappedApduCommand wrapped
            ? Result.Success<(byte[] bytes, IApduCommand cmd), SmartCardError>(
                (wrapped.WrappedBytes, wrapped)
            )
            : GetCommandBytes(command).Map(bytes => (bytes, command));

        return await commandBytesResult.Match(
            async commandData =>
            {
                var (commandBytes, commandToSend) = commandData;

                // Log command details
                if (command is WrappedApduCommand)
                {
                    if (environment.Options.DebugLogging)
                    {
                        environment.Logger.LogInformation(
                            "[DEBUG] Wire-level APDU (wrapped): {CommandHex}",
                            Convert.ToHexString(commandBytes)
                        );
                        LogApduStructure(environment.Logger, commandBytes, "Wire-level (Secured)");
                    }
                    else if (environment.Options.EnableLogging)
                    {
                        environment.Logger.LogDebug(
                            "Using wrapped command: {ByteCount} bytes - {CommandHex}",
                            commandBytes.Length,
                            Convert.ToHexString(commandBytes)
                        );
                    }
                }
                else
                {
                    if (environment.Options.DebugLogging)
                    {
                        environment.Logger.LogInformation(
                            "[DEBUG] Wire-level APDU (unwrapped): {CommandHex}",
                            Convert.ToHexString(commandBytes)
                        );
                        LogApduStructure(
                            environment.Logger,
                            commandBytes,
                            "Wire-level (Plaintext)"
                        );
                    }
                    else if (environment.Options.EnableLogging)
                    {
                        environment.Logger.LogDebug(
                            "Using unwrapped command: {ByteCount} bytes - {CommandHex}",
                            commandBytes.Length,
                            Convert.ToHexString(commandBytes)
                        );
                    }
                }

                // Log the actual command being sent
                if (environment.Options.EnableLogging)
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

                return await transmitResult.Match(
                    response =>
                    {
                        stopwatch.Stop();

                        // Combine response bytes for metadata
                        byte[] responseBytes = CombineResponseBytes(
                            response.Data,
                            response.StatusWord
                        );

                        // Log response details
                        if (environment.Options.DebugLogging)
                        {
                            environment.Logger.LogInformation(
                                "[DEBUG] Wire-level Response: {ResponseHex} (SW={StatusWord:X4})",
                                Convert.ToHexString(responseBytes),
                                response.StatusWord
                            );
                            LogResponseStructure(
                                environment.Logger,
                                response.Data,
                                response.StatusWord,
                                "Wire-level Response"
                            );
                        }
                        else if (environment.Options.VerboseLogging)
                        {
                            environment.Logger.LogInformation(
                                "[VERBOSE] Response: {DataLength} bytes + SW={StatusWord:X4}",
                                response.Data.Length,
                                response.StatusWord
                            );
                        }

                        var metadata = new CommandMetadata(
                            ExecutionTime: stopwatch.Elapsed,
                            TransmittedBytes: commandBytes,
                            ReceivedBytes: responseBytes
                        );

                        var transportResult = CommandResult.Success(
                            response.Data,
                            response.StatusWord,
                            environment,
                            metadata
                        );

                        // Apply secure channel response unwrapping if needed
                        if (environment.SecureChannel.HasValue)
                        {
                            var unwrapper = CreateSecureChannelResponseUnwrapper();
                            return Task.FromResult(unwrapper(transportResult));
                        }

                        return Task.FromResult(
                            Result.Success<CommandResult, SmartCardError>(transportResult)
                        );
                    },
                    error =>
                    {
                        stopwatch.Stop();
                        return Task.FromResult(
                            Result.Failure<CommandResult, SmartCardError>(error)
                        );
                    }
                );
            },
            error =>
            {
                stopwatch.Stop();
                return Task.FromResult(Result.Failure<CommandResult, SmartCardError>(error));
            }
        );
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
                CommandResult.Success(
                    [],
                    Constants.Constants.StatusWords.Legacy.Success,
                    environment,
                    metadata
                )
            )
        );
    };

    /// <summary>
    /// Creates a response processor that unwraps secure channel responses.
    /// </summary>
    public static Func<
        CommandResult,
        Result<CommandResult, SmartCardError>
    > CreateSecureChannelResponseUnwrapper()
    {
        return result =>
        {
            if (!result.UpdatedEnvironment.SecureChannel.HasValue)
                return Result.Success<CommandResult, SmartCardError>(result);

            byte[] responseBytes = CombineResponseBytes(result.Data, result.StatusWord);
            var securedResponse = new WSCT.ISO7816.ResponseAPDU(responseBytes);
            return ScpService
                .Security.RemoveResponseSecurity(
                    securedResponse,
                    result.UpdatedEnvironment.SecureChannel.Value
                )
                .Map(unwrapped =>
                {
                    byte[] plaintext = unwrapped.plaintextResponse.ToBytes();
                    ushort statusWord = (ushort)(plaintext[^2] << 8 | plaintext[^1]);
                    CommandEnvironment updatedEnvironment =
                        result.UpdatedEnvironment.WithSecureChannel(unwrapped.newState);
                    return CommandResult.Success(
                        plaintext[..^2],
                        statusWord,
                        updatedEnvironment,
                        result.Metadata with
                        {
                            SecureChannelUnwrapped = true
                        }
                    );
                });
        };
    }

    /// <summary>
    /// Logs response details.
    /// </summary>
    public static CommandProcessor LogResponse = (command, environment, cancellationToken) =>
    {
        if (!environment.Options.EnableLogging)
        {
            var metadata = new CommandMetadata(ResponseLogged: true);
            return Task.FromResult(
                Result.Success<CommandResult, SmartCardError>(
                    CommandResult.Success(
                        [],
                        Constants.Constants.StatusWords.Legacy.Success,
                        environment,
                        metadata
                    )
                )
            );
        }

        // This would log the response from previous processors
        environment.Logger.LogDebug("Command completed");

        var logMetadata = new CommandMetadata(ResponseLogged: true);
        return Task.FromResult(
            Result.Success<CommandResult, SmartCardError>(
                CommandResult.Success(
                    [],
                    Constants.Constants.StatusWords.Legacy.Success,
                    environment,
                    logMetadata
                )
            )
        );
    };

    /// <summary>
    /// Creates a processor that executes the complete command pipeline.
    /// ExecuteTransport verifies secure-channel response protection.
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
            ExecuteTransport,
            enableLogging ? LogResponse : FunctionComposition.Identity,
        ];

        return FunctionComposition.ComposeMany(processors);
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

    /// <summary>
    /// Logs APDU structure details for verbose and debug output.
    /// </summary>
    private static void LogApduStructure(ILogger logger, byte[] apduBytes, string context)
    {
        if (apduBytes.Length < 4)
        {
            logger.LogInformation(
                "  {Context}: Invalid APDU length ({Length} bytes)",
                context,
                apduBytes.Length
            );
            return;
        }

        byte cla = apduBytes[0];
        byte ins = apduBytes[1];
        byte p1 = apduBytes[2];
        byte p2 = apduBytes[3];

        string structure = $"  {context}: CLA={cla:X2} INS={ins:X2} P1={p1:X2} P2={p2:X2}";

        if (apduBytes.Length > 4)
        {
            if (apduBytes.Length == 5)
            {
                byte le = apduBytes[4];
                structure += $" Le={le:X2} (expecting {(le == 0 ? 256 : le)} bytes)";
            }
            else
            {
                byte lc = apduBytes[4];
                structure += $" Lc={lc:X2} ({lc} data bytes)";

                if (apduBytes.Length > 5 + lc)
                {
                    byte le = apduBytes[5 + lc];
                    structure += $" Le={le:X2} (expecting {(le == 0 ? 256 : le)} bytes)";
                }
            }
        }

        logger.LogInformation(structure);
    }

    /// <summary>
    /// Logs response structure details for verbose and debug output.
    /// </summary>
    private static void LogResponseStructure(
        ILogger logger,
        byte[] responseData,
        ushort statusWord,
        string context
    )
    {
        string structure =
            $"  {context}: {responseData.Length} data bytes + Status Word {statusWord:X4}";

        // Interpret common status words
        string swMeaning = statusWord switch
        {
            0x9000 => "Success",
            0x6700 => "Wrong Length",
            0x6982 => "Security Condition Not Satisfied",
            0x6985 => "Conditions of Use Not Satisfied",
            0x6A82 => "File or Application Not Found",
            0x6A86 => "Incorrect Parameters P1-P2",
            0x6A88 => "Referenced Data Not Found",
            0x6B00 => "Wrong Parameters P1-P2",
            0x6D00 => "Instruction Not Supported",
            0x6E00 => "Class Not Supported",
            _ when (statusWord & 0xFF00) == 0x6100
                => $"More Data Available ({statusWord & 0xFF} bytes)",
            _ when (statusWord & 0xFF00) == 0x6C00 => $"Wrong Le ({statusWord & 0xFF} expected)",
            _ => "Unknown",
        };

        structure += $" ({swMeaning})";
        logger.LogInformation(structure);
    }
}
