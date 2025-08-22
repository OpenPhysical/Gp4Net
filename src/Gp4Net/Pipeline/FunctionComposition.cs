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
    public static CommandProcessor Compose(
        this CommandProcessor first,
        CommandProcessor second)
    {
        return async (command, environment, cancellationToken) =>
        {
            var result = await first(command, environment, cancellationToken);
            
            return await result.Bind(async cmdResult =>
            {
                // Check if the first processor created a wrapped command
                var commandForSecond = command;
                if (cmdResult.Data.Length > 0 && cmdResult.Metadata?.SecureChannelWrapped == true)
                {
                    // First processor wrapped the command, create WrappedApduCommand for subsequent processors
                    commandForSecond = new WrappedApduCommand(command, cmdResult.Data);
                }
                
                // Use the updated environment from the first processor
                var secondResult = await second(commandForSecond, cmdResult.UpdatedEnvironment, cancellationToken);
                
                // Merge results, but prefer response data from transport processors
                return secondResult.Map(secondCmd =>
                    secondCmd with
                    {
                        // For actual response data, prefer the second processor (e.g., ExecuteTransport)
                        // unless it's empty and the first has data
                        Data = secondCmd.Data.Length > 0 ? secondCmd.Data : cmdResult.Data,
                        // For status word, prefer non-success or the second processor's value
                        StatusWord = secondCmd.StatusWord != Constants.StatusWords.Success ? secondCmd.StatusWord : cmdResult.StatusWord,
                        Metadata = MergeMetadata(cmdResult.Metadata, secondCmd.Metadata)
                    });
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
        CommandProcessor processor)
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
        Func<CommandResult, bool> shouldRetry = null)
    {
        shouldRetry ??= result => !result.IsSuccess && IsRetriableError(result.StatusWord);
        
        return async (command, environment, cancellationToken) =>
        {
            var retryCount = 0;
            Result<CommandResult, SmartCardError> lastResult = Result.Failure<CommandResult, SmartCardError>(
                SmartCardError.CommunicationError("No attempts made"));
            
            while (retryCount <= maxRetries)
            {
                lastResult = await processor(command, environment, cancellationToken);
                
                if (lastResult.IsSuccess && !shouldRetry(lastResult.Value))
                    break;
                    
                if (retryCount < maxRetries)
                {
                    retryCount++;
                    await Task.Delay(TimeSpan.FromMilliseconds(100 * retryCount), cancellationToken);
                }
                else
                {
                    break;
                }
            }
            
            return lastResult.Map(result => 
                result with 
                { 
                    Metadata = result.Metadata with { RetryCount = retryCount } 
                });
        };
    }

    /// <summary>
    /// Adds timeout handling to a processor.
    /// </summary>
    public static CommandProcessor WithTimeout(
        this CommandProcessor processor,
        TimeSpan? timeout = null)
    {
        return async (command, environment, cancellationToken) =>
        {
            var effectiveTimeout = timeout ?? 
                                 environment.EffectiveOptions.Timeout ?? 
                                 TimeSpan.FromSeconds(30);
            
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(effectiveTimeout);
            
            try
            {
                return await processor(command, environment, cts.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return Result.Failure<CommandResult, SmartCardError>(
                    SmartCardError.CommunicationError($"Command timed out after {effectiveTimeout}"));
            }
        };
    }

    /// <summary>
    /// The identity processor - returns the command result unchanged.
    /// </summary>
    public static readonly CommandProcessor Identity = 
        (command, environment, cancellationToken) =>
            Task.FromResult(Result.Success<CommandResult, SmartCardError>(
                CommandResult.Success([], Constants.StatusWords.Success, environment)));

    /// <summary>
    /// Merges two metadata instances, preferring values from the second if both present.
    /// </summary>
    private static CommandMetadata MergeMetadata(CommandMetadata first, CommandMetadata second)
    {
        if (first == null) return second;
        if (second == null) return first;
        
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
        // Communication errors and temporary failures
        return statusWord == 0x6F00 || // No precise diagnosis
               statusWord == 0x6581 || // Memory failure
               statusWord == 0x6A86;   // Incorrect P1/P2
    }
}