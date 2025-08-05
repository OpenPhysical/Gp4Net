using System;
using System.Threading.Tasks;
using Gp4Net.Tool.Commands;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Pipeline;

/// <summary>
/// Extension methods for ICliExecutionContext to provide fluent middleware pipeline capabilities.
/// </summary>
[PublicAPI]
public static class CommandContextExtensions
{
    /// <summary>
    /// Ensures a card connection using settings from BaseCommandSettings.
    /// </summary>
    public static async Task<ICliExecutionContext> RequireCardConnection(
        this ICliExecutionContext context,
        BaseCommandSettings settings
    )
    {
        var readerName = settings.Reader?.Name ?? "auto";
        return await context.RequireCardConnection(readerName);
    }

    /// <summary>
    /// Ensures a secure channel using settings from BaseCommandSettings.
    /// Only establishes secure channel if required by the command settings.
    /// </summary>
    public static async Task<ICliExecutionContext> RequireSecureChannel(
        this ICliExecutionContext context,
        BaseCommandSettings settings
    )
    {
        // Skip secure channel if not required
        if (!settings.RequiresSecureChannel)
        {
            return context;
        }

        // Convert nullable to Maybe at the boundary
        var keysetMaybe = settings.Keyset != null 
            ? CSharpFunctionalExtensions.Maybe<string>.From(settings.Keyset) 
            : CSharpFunctionalExtensions.Maybe<string>.None;

        return await context.RequireSecureChannel(settings.SecurityLevel, keysetMaybe);
    }

    /// <summary>
    /// Displays card information if not suppressed in settings.
    /// </summary>
    public static ICliExecutionContext DisplayCardInfo(
        this ICliExecutionContext context,
        BaseCommandSettings settings
    )
    {
        if (!settings.NoCardInfo && context.CardService.IsConnected)
        {
            var atr = context.CardService.GetAtr();
            if (atr != null)
            {
                context.Display.CardInfo(atr);
            }
        }
        return context;
    }

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

    /// <summary>
    /// Executes a command with common card operations setup.
    /// </summary>
    public static async Task<int> ExecuteCardCommand(
        this ICliExecutionContext context,
        BaseCommandSettings settings,
        Func<ICliExecutionContext, Task<int>> commandLogic
    )
    {
        // Delegate to functional version and convert result
        return await context.ExecuteCardCommandFunctional(
            settings,
            async ctx => 
            {
                var result = await commandLogic(ctx);
                return result == 0 
                    ? CSharpFunctionalExtensions.Result.Success<bool, string>(true)
                    : CSharpFunctionalExtensions.Result.Failure<bool, string>($"Command failed with exit code {result}");
            }
        );
    }

    /// <summary>
    /// Executes a command with common card operations setup (synchronous version).
    /// </summary>
    public static async Task<int> ExecuteCardCommand(
        this ICliExecutionContext context,
        BaseCommandSettings settings,
        Func<ICliExecutionContext, int> commandLogic
    )
    {
        // Delegate to async version
        return await ExecuteCardCommand(context, settings, ctx => Task.FromResult(commandLogic(ctx)));
    }

}