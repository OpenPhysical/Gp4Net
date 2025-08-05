using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Gp4Net.Constants;
using Gp4Net.Core;

namespace Gp4Net.Pipeline;

/// <summary>
/// Represents the response from executing a command through the pipeline.
/// </summary>
public record CommandResponse(
    byte[] Data,
    StatusWord StatusWord,
    IPipelineContext UpdatedContext,
    IReadOnlyDictionary<string, object> Metadata)
{
    /// <summary>
    /// Gets a value indicating whether the command was successful (SW=9000).
    /// </summary>
    public bool IsSuccess
    {
        get
        {
            return StatusWord == StatusWords.Success;
        }
    }

    /// <summary>
    /// Creates a successful response.
    /// </summary>
    public static CommandResponse Success(
        byte[] data = null,
        IPipelineContext context = null,
        IReadOnlyDictionary<string, object> metadata = null) =>
        new(
            data ?? [],
            StatusWords.Success,
            context ?? ImmutablePipelineContext.Empty,
            metadata ?? new Dictionary<string, object>());

    /// <summary>
    /// Creates a failed response.
    /// </summary>
    public static CommandResponse Failure(
        StatusWord statusWord,
        IPipelineContext context = null,
        IReadOnlyDictionary<string, object> metadata = null) =>
        new(
            [],
            statusWord,
            context ?? ImmutablePipelineContext.Empty,
            metadata ?? new Dictionary<string, object>());

    /// <summary>
    /// Converts this response to a Result type.
    /// </summary>
    public Result<CommandResponse, SmartCardError> ToResult() =>
        IsSuccess
            ? Result.Success<CommandResponse, SmartCardError>(this)
            : Result.Failure<CommandResponse, SmartCardError>(
                SmartCardError.FromStatusWord(StatusWord));

    /// <summary>
    /// Creates a new response with additional metadata.
    /// </summary>
    public CommandResponse WithMetadata(string key, object value)
    {
        var newMetadata = new Dictionary<string, object>(Metadata)
        {
            [key] = value
        };
        return this with { Metadata = newMetadata };
    }

    /// <summary>
    /// Creates a new response with updated context.
    /// </summary>
    public CommandResponse WithContext(IPipelineContext context) =>
        this with { UpdatedContext = context };

    /// <summary>
    /// Creates a new response with a context value added.
    /// </summary>
    public CommandResponse WithContextValue<T>(string key, T value) where T : class =>
        this with { UpdatedContext = UpdatedContext.With(key, value) };
}

/// <summary>
/// Standard metadata keys for command responses.
/// </summary>
public static class ResponseMetadata
{
    /// <summary>
    /// The time taken to execute the command.
    /// </summary>
    public const string ExecutionTime = "ExecutionTime";

    /// <summary>
    /// The number of retries attempted.
    /// </summary>
    public const string RetryCount = "RetryCount";

    /// <summary>
    /// Whether the command was wrapped with secure channel.
    /// </summary>
    public const string SecureChannelWrapped = "SecureChannelWrapped";

    /// <summary>
    /// The actual bytes sent to the card.
    /// </summary>
    public const string TransmittedBytes = "TransmittedBytes";

    /// <summary>
    /// The actual bytes received from the card.
    /// </summary>
    public const string ReceivedBytes = "ReceivedBytes";

    /// <summary>
    /// Any warnings or non-fatal issues during execution.
    /// </summary>
    public const string Warnings = "Warnings";
}