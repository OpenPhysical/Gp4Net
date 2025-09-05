using System;
using WSCT.ISO7816;

namespace Gp4Net.Pipeline;

/// <summary>
/// Represents a request to execute a command through the pipeline.
/// </summary>
public record CommandRequest(
    CommandAPDU Command,
    IPipelineContext Context,
    CommandOptions Options = null
)
{
    /// <summary>
    /// Creates a simple request with just a command.
    /// </summary>
    public static CommandRequest Create(CommandAPDU command)
    {
        return new(command, ImmutablePipelineContext.Empty);
    }

    /// <summary>
    /// Creates a request with a command and context.
    /// </summary>
    public static CommandRequest Create(CommandAPDU command, IPipelineContext context)
    {
        return new(command, context);
    }

    /// <summary>
    /// Creates a new request with updated context.
    /// </summary>
    public CommandRequest WithContext(IPipelineContext context)
    {
        return this with { Context = context };
    }

    /// <summary>
    /// Creates a new request with updated options.
    /// </summary>
    public CommandRequest WithOptions(CommandOptions options)
    {
        return this with { Options = options };
    }

    /// <summary>
    /// Creates a new request with a context value added.
    /// </summary>
    public CommandRequest WithContextValue<T>(string key, T value)
        where T : class
    {
        return this with { Context = Context.With(key, value) };
    }
}

/// <summary>
/// Options for command execution.
/// </summary>
public record CommandOptions(
    bool RequiresSecureChannel = true,
    bool CaptureMetrics = true,
    bool EnableLogging = true
)
{
    /// <summary>
    /// Default options for most commands.
    /// </summary>
    public static CommandOptions Default { get; } = new();

    /// <summary>
    /// Options for commands that don't require secure channel.
    /// </summary>
    public static CommandOptions NoSecureChannel { get; } = new(RequiresSecureChannel: false);
}
