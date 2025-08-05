using System.Threading.Tasks;
using JetBrains.Annotations;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Extension methods for testing commands.
/// </summary>
[PublicAPI]
public static class CommandTestExtensions
{
    /// <summary>
    /// Executes a command with a mock context for testing.
    /// </summary>
    public static async Task<CommandTestResult> ExecuteWithMockContext<TSettings>(
        this IPipelineCommand<TSettings> command,
        TSettings settings,
        MockCliContext mockContext = null
    )
        where TSettings : CommandSettings
    {
        mockContext ??= new MockCliContext();

        var result = await command.ExecuteAsync(mockContext, settings);

        return new CommandTestResult
        {
            ExitCode = result,
            Context = mockContext,
            DisplayMessages = ((MockDisplayService)mockContext.Display).Messages,
            MethodCalls = mockContext.MethodCalls
        };
    }

    /// <summary>
    /// Creates a mock context with specific configuration.
    /// </summary>
    public static MockCliContext CreateMockContext(
        bool shouldConnectSucceed = true,
        bool shouldSecureChannelSucceed = true
    )
    {
        return new MockCliContext
        {
            ShouldConnectSucceed = shouldConnectSucceed,
            ShouldSecureChannelSucceed = shouldSecureChannelSucceed
        };
    }
}

/// <summary>
/// Result of a command test execution.
/// </summary>
[PublicAPI]
public class CommandTestResult
{
    /// <summary>
    /// Gets or sets the exit code returned by the command.
    /// </summary>
    public int ExitCode { get; set; }

    /// <summary>
    /// Gets or sets the mock context used during execution.
    /// </summary>
    public MockCliContext Context { get; set; } = null!;

    /// <summary>
    /// Gets or sets the display messages captured during execution.
    /// </summary>
    public System.Collections.Generic.List<string> DisplayMessages { get; set; } = null!;

    /// <summary>
    /// Gets or sets the method calls made to the context during execution.
    /// </summary>
    public System.Collections.Generic.List<string> MethodCalls { get; set; } = null!;

    /// <summary>
    /// Gets a value indicating whether the command succeeded.
    /// </summary>
    public bool Succeeded
    {
        get
        {
            return ExitCode == 0;
        }
    }

    /// <summary>
    /// Gets a value indicating whether the command failed.
    /// </summary>
    public bool Failed
    {
        get
        {
            return ExitCode != 0;
        }
    }
}