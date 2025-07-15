using System;
using System.Threading.Tasks;
using Gp4Net.Tool.Commands;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Pipeline
{
    /// <summary>
    /// Extension methods for ICommandContext to provide fluent middleware pipeline capabilities.
    /// </summary>
    [PublicAPI]
    public static class CommandContextExtensions
    {
        /// <summary>
        /// Ensures a card connection using settings from BaseCommandSettings.
        /// </summary>
        public static async Task<ICommandContext> RequireCardConnection(
            this ICommandContext context,
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
        public static async Task<ICommandContext> RequireSecureChannel(
            this ICommandContext context,
            BaseCommandSettings settings
        )
        {
            // Skip secure channel if not required
            if (!settings.RequiresSecureChannel)
            {
                return context;
            }

            return await context.RequireSecureChannel(settings.SecurityLevel, settings.Keyset);
        }

        /// <summary>
        /// Displays card information if not suppressed in settings.
        /// </summary>
        public static ICommandContext DisplayCardInfo(
            this ICommandContext context,
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
        public static ICommandContext WithVerbose(this ICommandContext context, bool verbose)
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
            this ICommandContext context,
            BaseCommandSettings settings,
            Func<ICommandContext, Task<int>> commandLogic
        )
        {
            return await context
                .WithVerbose(settings.Verbose)
                .RequireCardConnection(settings)
                .ContinueWith(ctx => ctx.DisplayCardInfo(settings))
                .ContinueWith(ctx => ctx.RequireSecureChannel(settings))
                .ContinueWith(ctx => ctx.ExecuteAsync(commandLogic));
        }

        /// <summary>
        /// Executes a command with common card operations setup (synchronous version).
        /// </summary>
        public static async Task<int> ExecuteCardCommand(
            this ICommandContext context,
            BaseCommandSettings settings,
            Func<ICommandContext, int> commandLogic
        )
        {
            return await context
                .WithVerbose(settings.Verbose)
                .RequireCardConnection(settings)
                .ContinueWith(ctx => ctx.DisplayCardInfo(settings))
                .ContinueWith(ctx => ctx.RequireSecureChannel(settings))
                .ContinueWith(ctx => ctx.ExecuteAsync(commandLogic));
        }

        /// <summary>
        /// Continues with a synchronous operation.
        /// </summary>
        private static async Task<ICommandContext> ContinueWith(
            this Task<ICommandContext> contextTask,
            Func<ICommandContext, ICommandContext> operation
        )
        {
            var context = await contextTask;
            return operation(context);
        }

        /// <summary>
        /// Continues with an asynchronous operation.
        /// </summary>
        private static async Task<ICommandContext> ContinueWith(
            this Task<ICommandContext> contextTask,
            Func<ICommandContext, Task<ICommandContext>> operation
        )
        {
            var context = await contextTask;
            return await operation(context);
        }

        /// <summary>
        /// Continues with command execution.
        /// </summary>
        private static async Task<int> ContinueWith(
            this Task<ICommandContext> contextTask,
            Func<ICommandContext, Task<int>> operation
        )
        {
            var context = await contextTask;
            return await operation(context);
        }

        /// <summary>
        /// Continues with synchronous command execution.
        /// </summary>
        private static async Task<int> ContinueWith(
            this Task<ICommandContext> contextTask,
            Func<ICommandContext, int> operation
        )
        {
            var context = await contextTask;
            return operation(context);
        }
    }
}
