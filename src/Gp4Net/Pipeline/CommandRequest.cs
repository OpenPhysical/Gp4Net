using System;
using Gp4Net.Transport;

namespace Gp4Net.Pipeline;

/// <summary>
/// Represents a request to execute a command through the pipeline.
/// </summary>
public record CommandRequest(
    IApduCommand Command,
    IPipelineContext Context,
    CommandOptions? Options = null)
{
    /// <summary>
    /// Creates a simple request with just a command.
    /// </summary>
    public static CommandRequest Create(IApduCommand command) =>
        new(command, ImmutablePipelineContext.Empty);

    /// <summary>
    /// Creates a request with a command and context.
    /// </summary>
    public static CommandRequest Create(IApduCommand command, IPipelineContext context) =>
        new(command, context);

    /// <summary>
    /// Creates a new request with updated context.
    /// </summary>
    public CommandRequest WithContext(IPipelineContext context) =>
        this with { Context = context };

    /// <summary>
    /// Creates a new request with updated options.
    /// </summary>
    public CommandRequest WithOptions(CommandOptions options) =>
        this with { Options = options };

    /// <summary>
    /// Creates a new request with a context value added.
    /// </summary>
    public CommandRequest WithContextValue<T>(string key, T value) where T : class =>
        this with { Context = Context.With(key, value) };
}

/// <summary>
/// Options for command execution.
/// </summary>
public record CommandOptions(
    TimeSpan? Timeout = null,
    int MaxRetries = 0,
    bool RequiresSecureChannel = true,
    bool CaptureMetrics = true,
    bool EnableLogging = true)
{
    /// <summary>
    /// Default options for most commands.
    /// </summary>
    public static CommandOptions Default { get; } = new();

    /// <summary>
    /// Options for commands that don't require secure channel.
    /// </summary>
    public static CommandOptions NoSecureChannel { get; } = new(RequiresSecureChannel: false);

    /// <summary>
    /// Options for commands with extended timeout.
    /// </summary>
    public static CommandOptions ExtendedTimeout { get; } = new(Timeout: TimeSpan.FromMinutes(5));
}