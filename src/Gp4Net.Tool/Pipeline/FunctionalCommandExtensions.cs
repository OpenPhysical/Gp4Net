using System;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using JetBrains.Annotations;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Pipeline;

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
        string readerName = null)
    {
        Result<bool, SmartCardError> connectionResult = await context.CardService.IsConnectedAsync();
        return await connectionResult.Match(
            isConnected => isConnected 
                ? Task.FromResult(Result.Success<ICliExecutionContext, string>(context))
                : EstablishConnection(context, readerName),
            error => Task.FromResult(Result.Failure<ICliExecutionContext, string>(error.Message))
        );
    }

    private static async Task<Result<ICliExecutionContext, string>> EstablishConnection(
        ICliExecutionContext context, 
        string readerName)
    {
        try
        {
            _ = await context.RequireCardConnection(readerName);
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
        string keyset = null)
    {
        try
        {
            _ = await context.RequireSecureChannel(securityLevel, keyset);
            return Result.Success<ICliExecutionContext, string>(context);
        }
        catch (Exception ex)
        {
            return Result.Failure<ICliExecutionContext, string>(ex.Message);
        }
    }


    /// <summary>
    /// Chains functional operations on the CLI context.
    /// </summary>
    public static async Task<Result<TResult, string>> ThenAsync<TResult>(
        this Task<Result<ICliExecutionContext, string>> contextTask,
        Func<ICliExecutionContext, Task<Result<TResult, string>>> operation)
    {
        Result<ICliExecutionContext, string> contextResult = await contextTask;
        return await contextResult.Bind(operation);
    }

    /// <summary>
    /// Chains functional operations that return the context.
    /// </summary>
    public static async Task<Result<ICliExecutionContext, string>> ThenAsync(
        this Task<Result<ICliExecutionContext, string>> contextTask,
        Func<ICliExecutionContext, Task<Result<ICliExecutionContext, string>>> operation)
    {
        Result<ICliExecutionContext, string> contextResult = await contextTask;
        return await contextResult.Bind(operation);
    }

    /// <summary>
    /// Maps a successful context result.
    /// </summary>
    public static async Task<Result<TResult, string>> MapAsync<TResult>(
        this Task<Result<ICliExecutionContext, string>> contextTask,
        Func<ICliExecutionContext, TResult> mapper)
    {
        Result<ICliExecutionContext, string> contextResult = await contextTask;
        return contextResult.Map(mapper);
    }

    /// <summary>
    /// Executes a card command using functional patterns with connection and error handling.
    /// </summary>
    public static async Task<int> ExecuteCardCommandFunctional(
        this ICliExecutionContext context,
        CommandSettings settings,
        Func<ICliExecutionContext, Task<Result<bool, string>>> commandLogic)
    {
        Result<ICliExecutionContext, string> connectionResult = await context.RequireCardConnectionFunctional();
        Result<bool, string> commandResult = await connectionResult.Match(
            async ctx => await commandLogic(ctx),
            error => Task.FromResult(Result.Failure<bool, string>(error)));
            
        return commandResult.Match(
                success => 0,
                error =>
                {
                    context.Display.Error($"Command failed: {error}");
                    return 1;
                });
    }
}