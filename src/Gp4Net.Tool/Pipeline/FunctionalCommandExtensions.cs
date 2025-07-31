using System;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Tool.Commands;
using JetBrains.Annotations;

namespace Gp4Net.Tool.Pipeline
{
    /// <summary>
    /// Extension methods for functional command execution without exceptions.
    /// </summary>
    [PublicAPI]
    public static class FunctionalCommandExtensions
    {
        /// <summary>
        /// Executes a command with functional error handling.
        /// </summary>
        public static async Task<Result<T, string>> ExecuteFunctionalAsync<T>(
            this ICliExecutionContext context,
            Func<ICliExecutionContext, Task<Result<T, string>>> commandLogic)
        {
            try
            {
                return await commandLogic(context);
            }
            catch (Exception ex)
            {
                return Result.Failure<T, string>($"Unexpected error: {ex.Message}");
            }
        }

        /// <summary>
        /// Ensures a card connection using functional patterns.
        /// </summary>
        public static async Task<Result<ICliExecutionContext, string>> RequireCardConnectionFunctional(
            this ICliExecutionContext context,
            string? readerName = null)
        {
            if (context.CardService.IsConnected)
            {
                return Result.Success<ICliExecutionContext, string>(context);
            }

            try
            {
                await context.RequireCardConnection(readerName);
                return Result.Success<ICliExecutionContext, string>(context);
            }
            catch (Exception ex)
            {
                return Result.Failure<ICliExecutionContext, string>(ex.Message);
            }
        }

        /// <summary>
        /// Ensures a secure channel using functional patterns.
        /// </summary>
        public static async Task<Result<ICliExecutionContext, string>> RequireSecureChannelFunctional(
            this ICliExecutionContext context,
            byte securityLevel = 1,
            string? keyset = null)
        {
            try
            {
                await context.RequireSecureChannel(securityLevel, keyset);
                return Result.Success<ICliExecutionContext, string>(context);
            }
            catch (Exception ex)
            {
                return Result.Failure<ICliExecutionContext, string>(ex.Message);
            }
        }

        /// <summary>
        /// Executes a card command with functional composition.
        /// </summary>
        public static async Task<int> ExecuteCardCommandFunctional(
            this ICliExecutionContext context,
            BaseCommandSettings settings,
            Func<ICliExecutionContext, Task<Result<bool, string>>> commandLogic)
        {
            var result = await context
                .RequireCardConnectionFunctional(settings.Reader?.Name)
                .Bind(async ctx =>
                {
                    ctx.DisplayCardInfo(settings);
                    return settings.RequiresSecureChannel
                        ? await ctx.RequireSecureChannelFunctional(settings.SecurityLevel, settings.Keyset)
                        : Result.Success<ICliExecutionContext, string>(ctx);
                })
                .Bind(async ctx => 
                {
                    var commandResult = await commandLogic(ctx);
                    return commandResult.Map(_ => ctx);
                });

            return result.Match(
                onSuccess: _ => 0,
                onFailure: error =>
                {
                    context.Display.Error($"Command failed: {error}");
                    return 1;
                });
        }

        /// <summary>
        /// Chains functional operations on the CLI context.
        /// </summary>
        public static async Task<Result<TResult, string>> ThenAsync<TResult>(
            this Task<Result<ICliExecutionContext, string>> contextTask,
            Func<ICliExecutionContext, Task<Result<TResult, string>>> operation)
        {
            var contextResult = await contextTask;
            return await contextResult.Bind(operation);
        }

        /// <summary>
        /// Chains functional operations that return the context.
        /// </summary>
        public static async Task<Result<ICliExecutionContext, string>> ThenAsync(
            this Task<Result<ICliExecutionContext, string>> contextTask,
            Func<ICliExecutionContext, Task<Result<ICliExecutionContext, string>>> operation)
        {
            var contextResult = await contextTask;
            return await contextResult.Bind(operation);
        }

        /// <summary>
        /// Maps a successful context result.
        /// </summary>
        public static async Task<Result<TResult, string>> MapAsync<TResult>(
            this Task<Result<ICliExecutionContext, string>> contextTask,
            Func<ICliExecutionContext, TResult> mapper)
        {
            var contextResult = await contextTask;
            return contextResult.Map(mapper);
        }
    }
}