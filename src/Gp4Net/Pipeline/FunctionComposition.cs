using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Transport;
using static Gp4Net.Pipeline.CommandProcessing;

namespace Gp4Net.Pipeline;

/// <summary>
/// Functional composition utilities for command processors.
/// </summary>
public static class FunctionComposition
{
    /// <summary>
    /// Composes two command processors sequentially.
    /// The environment from the first processor is passed to the second.
    /// </summary>
    public static CommandProcessor Compose(this CommandProcessor first, CommandProcessor second)
    {
        return async (command, environment, cancellationToken) =>
        {
            Result<CommandResult, SmartCardError> result = await first(
                command,
                environment,
                cancellationToken
            );

            return await result.Bind(async cmdResult =>
            {
                // Check if the first processor created a wrapped command
                IApduCommand commandForSecond = command;

                // Only create WrappedApduCommand if we have wrapped command bytes AND we're not dealing with response data
                // The key insight: wrapped command bytes are only valid if they represent an APDU command (>=4 bytes)
                // Response data can be smaller and should never be treated as wrapped commands
                bool hasWrappedCommandBytes =
                    cmdResult.Metadata?.SecureChannelWrapped == true
                    && cmdResult.Data.Length >= 4
                    && // Must be valid APDU command
                    !IsResponseData(cmdResult); // Must not be response data

                if (hasWrappedCommandBytes)
                {
                    // First processor wrapped the command, create WrappedApduCommand for subsequent processors
                    Result<WrappedApduCommand, SmartCardError> wrappedResult =
                        WrappedApduCommand.Create(command, cmdResult.Data);

                    if (wrappedResult.IsFailure)
                    {
                        return Result.Failure<CommandResult, SmartCardError>(wrappedResult.Error);
                    }

                    // Safe access after success check
                    commandForSecond = wrappedResult.Value;
                }

                // Use the updated environment from the first processor
                Result<CommandResult, SmartCardError> secondResult = await second(
                    commandForSecond,
                    cmdResult.UpdatedEnvironment,
                    cancellationToken
                );

                // Merge results, but prefer response data from transport processors
                return secondResult.Map(secondCmd =>
                    secondCmd with
                    {
                        // For actual response data, prefer the second processor (e.g., ExecuteTransport)
                        // unless it's empty and the first has data
                        Data = secondCmd.Data.Length > 0 ? secondCmd.Data : cmdResult.Data,
                        // For status word, prefer non-success or the second processor's value
                        StatusWord =
                            secondCmd.StatusWord != Constants.Constants.StatusWords.Legacy.Success
                                ? secondCmd.StatusWord
                                : cmdResult.StatusWord,
                        Metadata = MergeMetadata(cmdResult.Metadata, secondCmd.Metadata),
                    }
                );
            });
        };
    }

    /// <summary>
    /// Composes multiple command processors sequentially.
    /// </summary>
    public static CommandProcessor ComposeMany(params CommandProcessor[] processors)
    {
        if (processors.Length == 0)
            return Identity;

        return processors.Aggregate((acc, next) => acc.Compose(next));
    }

    /// <summary>
    /// Applies a processor conditionally based on a predicate.
    /// </summary>
    public static CommandProcessor When(
        Func<IApduCommand, CommandEnvironment, bool> predicate,
        CommandProcessor processor
    )
    {
        return (command, environment, cancellationToken) =>
            predicate(command, environment)
                ? processor(command, environment, cancellationToken)
                : Identity(command, environment, cancellationToken);
    }

    /// <summary>
    /// Adds retry logic to a processor.
    /// </summary>
    public static CommandProcessor WithRetry(
        this CommandProcessor processor,
        int maxRetries = 3,
        Func<CommandResult, bool> shouldRetry = null
    )
    {
        shouldRetry ??= result => !result.IsSuccess && IsRetriableError(result.StatusWord);

        return async (command, environment, cancellationToken) =>
        {
            return await ExecuteWithRetry(
                processor,
                command,
                environment,
                shouldRetry,
                maxRetries,
                0,
                cancellationToken
            );
        };
    }

    /// <summary>
    /// Functional recursive retry implementation that eliminates imperative loops.
    /// Uses tail recursion pattern with accumulator for retry count.
    /// </summary>
    private static async Task<Result<CommandResult, SmartCardError>> ExecuteWithRetry(
        CommandProcessor processor,
        IApduCommand command,
        CommandEnvironment environment,
        Func<CommandResult, bool> shouldRetry,
        int maxRetries,
        int currentAttempt,
        CancellationToken cancellationToken
    )
    {
        var result = await processor(command, environment, cancellationToken);

        return await result.Match(
            onSuccess: async commandResult =>
            {
                if (!shouldRetry(commandResult) || currentAttempt >= maxRetries)
                    return Result.Success<CommandResult, SmartCardError>(
                        commandResult with
                        {
                            Metadata = commandResult.Metadata with { RetryCount = currentAttempt },
                        }
                    );

                await Task.Delay(
                    TimeSpan.FromMilliseconds(100 * (currentAttempt + 1)),
                    cancellationToken
                );
                return await ExecuteWithRetry(
                    processor,
                    command,
                    environment,
                    shouldRetry,
                    maxRetries,
                    currentAttempt + 1,
                    cancellationToken
                );
            },
            onFailure: async error =>
            {
                if (currentAttempt >= maxRetries)
                    return Result.Failure<CommandResult, SmartCardError>(error);

                await Task.Delay(
                    TimeSpan.FromMilliseconds(100 * (currentAttempt + 1)),
                    cancellationToken
                );
                return await ExecuteWithRetry(
                    processor,
                    command,
                    environment,
                    shouldRetry,
                    maxRetries,
                    currentAttempt + 1,
                    cancellationToken
                );
            }
        );
    }

    /// <summary>
    /// Adds timeout handling to a processor.
    /// </summary>
    public static CommandProcessor WithTimeout(
        this CommandProcessor processor,
        TimeSpan? timeout = null
    )
    {
        return async (command, environment, cancellationToken) =>
        {
            TimeSpan effectiveTimeout =
                timeout ?? environment.EffectiveOptions.Timeout ?? TimeSpan.FromSeconds(30);

            using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken
            );
            cts.CancelAfter(effectiveTimeout);

            try
            {
                return await processor(command, environment, cts.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return Result.Failure<CommandResult, SmartCardError>(
                    SmartCardError.CommunicationError($"Command timed out after {effectiveTimeout}")
                );
            }
        };
    }

    /// <summary>
    /// The identity processor - returns the command result unchanged.
    /// </summary>
    public static readonly CommandProcessor Identity = (command, environment, cancellationToken) =>
        Task.FromResult(
            Result.Success<CommandResult, SmartCardError>(
                CommandResult.Success([], Constants.Constants.StatusWords.Legacy.Success, environment)
            )
        );

    /// <summary>
    /// Merges two metadata instances, preferring values from the second if both present.
    /// </summary>
    private static CommandMetadata MergeMetadata(CommandMetadata first, CommandMetadata second)
    {
        if (first == null)
            return second;
        if (second == null)
            return first;

        return new CommandMetadata(
            ExecutionTime: second.ExecutionTime ?? first.ExecutionTime,
            TransmittedBytes: second.TransmittedBytes ?? first.TransmittedBytes,
            ReceivedBytes: second.ReceivedBytes ?? first.ReceivedBytes,
            SecureChannelWrapped: second.SecureChannelWrapped || first.SecureChannelWrapped,
            SecureChannelUnwrapped: second.SecureChannelUnwrapped || first.SecureChannelUnwrapped,
            ResponseLogged: second.ResponseLogged || first.ResponseLogged,
            RetryCount: first.RetryCount + second.RetryCount
        );
    }

    /// <summary>
    /// Determines if an error is retriable based on status word.
    /// </summary>
    private static bool IsRetriableError(StatusWord statusWord)
    {
        // Communication errors and failures
        return statusWord == 0x6F00
            || // No precise diagnosis
            statusWord == 0x6581
            || // Memory failure
            statusWord == 0x6A86; // Incorrect P1/P2
    }

    /// <summary>
    /// Determines if the command result contains response data rather than command data.
    /// Response data comes from transport processors after command execution.
    /// </summary>
    private static bool IsResponseData(CommandResult cmdResult)
    {
        // Response data has these characteristics:
        // 1. Has execution time metadata (from transport)
        // 2. Has received bytes metadata (from transport)
        // 3. StatusWord is not the default Success from intermediate processors
        return Maybe<CommandMetadata>
            .From(cmdResult.Metadata)
            .Match(
                metadata =>
                    metadata.ExecutionTime.HasValue
                    || Maybe<byte[]>.From(metadata.ReceivedBytes).HasValue
                    || cmdResult.StatusWord != Constants.Constants.StatusWords.Legacy.Success && cmdResult.Data.Length < 4,
                () => false
            );
    }
}
