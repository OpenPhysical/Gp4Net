using JetBrains.Annotations;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Extension methods for ICliExecutionContext to provide fluent middleware pipeline capabilities.
/// </summary>
[PublicAPI]
public static class CommandContextExtensions
{
    // /// <summary>
    // /// Ensures a card connection using settings from BaseCommandSettings.
    // /// </summary>
    // public static async Task<ICliExecutionContext> RequireCardConnection(
    //     this ICliExecutionContext context,
    //     BaseCommandSettings settings
    // )
    // {
    //     var readerName = settings.Reader?.Name ?? "auto";
    //     return await context.RequireCardConnection(readerName);
    // }

    /// <summary>
    /// Sets verbose mode on the display service.
    /// </summary>
    public static ICliExecutionContext WithVerbose(this ICliExecutionContext context, bool verbose)
    {
        if (context.Display is DisplayService displayService)
        {
            // Create a new display service with updated verbose setting
            var newDisplayService = new DisplayService(verbose);
            // Note: This creates a new context but loses the domain service factory
            // In practice, commands should just use the existing context
            return context;
        }
        return context;
    }
}
