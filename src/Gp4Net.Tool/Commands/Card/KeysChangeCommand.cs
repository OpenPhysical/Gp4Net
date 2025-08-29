using System.Collections.Generic;
using System.ComponentModel;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Command to change keys on a smart card.
/// </summary>
[PublicAPI]
[CommandHandler]
public class KeysChangeCommand : IPipelineCommand<KeysChangeCommand.Settings>
{

    /// <summary>
    /// Executes the keys change command to update the cryptographic keys on the card.
    /// </summary>
    /// <param name="context">The CLI execution context.</param>
    /// <param name="settings">The command settings.</param>
    /// <returns>0 if successful, 1 if failed.</returns>
    public async Task<int> ExecuteAsync(
        ICliExecutionContext context,
        Settings settings
    )
    {
        return await context.ExecuteAsync(async ctx =>
        {
            // Validate required parameters functionally
            Result<bool, SmartCardError> result = await ValidateSettings(settings)
                .Bind(_ => 
                {
                    ctx.Display.Info("Starting key change operation...");
                    return Result.Success<bool, SmartCardError>(true);
                })
                .Bind(_ => PerformKeyChange(ctx, settings));
            
            return result.Match(
                success => 0,
                error =>
                {
                    ctx.Display.Error($"Key change failed: {error.Message}");
                    return 1;
                });
        });
    }

    /// <summary>
    /// Validates command settings.
    /// </summary>
    private static Result<bool, SmartCardError> ValidateSettings(Settings settings)
    {
        return string.IsNullOrEmpty(settings.NewKeyset)
            ? Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("New keyset specification is required"))
            : Result.Success<bool, SmartCardError>(true);
    }

    /// <summary>
    /// Performs the key change operation using functional composition.
    /// </summary>
    private static async Task<Result<bool, SmartCardError>> PerformKeyChange(ICliExecutionContext context, Settings settings)
    {
        return await ResolveNewKeyset(context, settings)
            .Bind(async keyset => await ExecuteKeyChange(context, keyset));
    }

    private static Result<IKeySet, SmartCardError> ResolveNewKeyset(ICliExecutionContext context, Settings settings)
    {
        return Result.Try(() => context.KeysetResolver.ResolveKeyset(
                settings.NewKeyset,
                new Dictionary<string, string>(), // Empty keyset params
                null, // No explicit enc key
                null, // No explicit mac key
                null, // No explicit dek key
                0x01,
                null  // No card response
            ),
            ex => SmartCardError.InvalidArgument($"Failed to resolve keyset: {ex.Message}"))
            .Bind(keyset =>
                Maybe<IKeySet>.From(keyset).ToResult(
                    SmartCardError.InvalidArgument("Keyset resolver returned empty result")));
    }

    private static async Task<Result<bool, SmartCardError>> ExecuteKeyChange(ICliExecutionContext context, IKeySet newKeyset)
    {
        context.Display.Info("New keyset resolved from configuration");
        context.Display.Info($"New key version: {newKeyset.KeyVersion:X2}");
        context.Display.Info($"Protocol: {(newKeyset is Scp02KeySet ? "SCP02" : "SCP03")}");

        IGlobalPlatformService gpService = context.GetGlobalPlatformService();
        context.Display.Info("Changing keys...");
        
        Result<bool, SmartCardError> putKeyResult = await gpService.PutKeysAsync(
            (Domain.Keys.KeySet)newKeyset,
            newKeyset.KeyVersion
        );

        return putKeyResult.Match(
            success =>
            {
                context.Display.Success("Keys changed successfully");
                return Result.Success<bool, SmartCardError>(true);
            },
            error =>
            {
                context.Display.Error($"Failed to change keys: {error.Message}");
                return Result.Failure<bool, SmartCardError>(error);
            }
        );
    }


    /// <summary>
    /// Settings for the keys change command.
    /// </summary>
    public class Settings : CommandSettings
    {
        /// <summary>
        /// Gets or sets the new keyset specification.
        /// </summary>
        [CommandArgument(0, "<NEW_KEYSET>")]
        [Description(
            "New keyset specification (e.g., 'visa2:00000000000000000000000000000000' or 'gp_test_keys')"
        )]
        public string NewKeyset { get; set; } = string.Empty;
    }
}