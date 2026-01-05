using WSCT.ISO7816;

namespace Gp4Net.Pipeline;

/// <summary>
/// Represents a request to execute a command through the pipeline.
/// </summary>
public record CommandRequest
{
    /// <summary>
    /// Gets the command to execute.
    /// </summary>
    public CommandAPDU Command { get; init; }

    /// <summary>
    /// Gets the pipeline context used for execution.
    /// </summary>
    public IPipelineContext Context { get; init; }

    /// <summary>
    /// Gets the execution options to apply.
    /// </summary>
    public CommandOptions Options { get; init; }

    private CommandRequest(CommandAPDU command, IPipelineContext context, CommandOptions options)
    {
        Command = command;
        Context = context;
        Options = options;
    }

    /// <summary>
    /// Creates a simple request with just a command.
    /// </summary>
    public static CommandRequest Create(CommandAPDU command)
    {
        return new(command, ImmutablePipelineContext.Empty, CommandOptions.Default);
    }

    /// <summary>
    /// Creates a request with a command and context.
    /// </summary>
    public static CommandRequest Create(CommandAPDU command, IPipelineContext context)
    {
        return new(command, context, CommandOptions.Default);
    }

    /// <summary>
    /// Creates a request with a command, context, and options.
    /// </summary>
    public static CommandRequest Create(
        CommandAPDU command,
        IPipelineContext context,
        CommandOptions options
    )
    {
        return new(command, context, options);
    }

    /// <summary>
    /// Creates a new request with updated context.
    /// </summary>
    public CommandRequest WithContext(IPipelineContext context)
    {
        return new(Command, context, Options);
    }

    /// <summary>
    /// Creates a new request with updated options.
    /// </summary>
    public CommandRequest WithOptions(CommandOptions options)
    {
        return new(Command, Context, options);
    }

    /// <summary>
    /// Creates a new request with a context value added.
    /// </summary>
    public CommandRequest WithContextValue<T>(string key, T value)
        where T : class
    {
        return new(Command, Context.With(key, value), Options);
    }
}

/// <summary>
/// Options for command execution.
/// </summary>
public record CommandOptions(
    bool UseSecureChannel,
    bool CaptureMetrics = true,
    bool EnableLogging = true,
    bool VerboseLogging = false,
    bool DebugLogging = false
)
{
    /// <summary>
    /// Gets the default command options (no secure channel, metrics and logging enabled).
    /// </summary>
    public static CommandOptions Default { get; } = new(false);
}
