using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Services.GlobalPlatform;
using Gp4Net.Tool.Commands.Common;
using Gp4Net.Tool.Extensions;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Pipeline;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card;

/// <summary>
/// Command to change keys on a smart card.
/// </summary>
[PublicAPI]
[CliCommand(
    "change-keys",
    "Change cryptographic keys on the card (WARNING: This permanently modifies card keys)",
    "card"
)]
[CommandHandler]
public class KeysChangeCommand : IPipelineCommand<KeysChangeCommand.Settings>
{
    /// <summary>
    /// Executes the keys change command to update the cryptographic keys on the card.
    /// </summary>
    /// <param name="context">The CLI execution context.</param>
    /// <param name="settings">The command settings.</param>
    /// <returns>0 if successful, 1 if failed.</returns>
    public async Task<int> ExecuteAsync(ICliExecutionContext context, Settings settings)
    {
        var validation = ValidateSettings(settings);
        if (validation.IsFailure)
        {
            context.Display.Error(validation.Error.Message);
            return 1;
        }

        var connected = await context.RequireCardConnection(settings.GetReaderName());
        if (connected.IsFailure)
        {
            context.Display.Error($"Card connection failed: {connected.Error.Message}");
            return 1;
        }

        var secured = await connected.Value.RequireSecureChannel(settings.ToSecureChannelRequest());
        if (secured.IsFailure)
        {
            context.Display.Error($"Secure channel establishment failed: {secured.Error.Message}");
            return 1;
        }

        var result = await PerformKeyChange(secured.Value, settings);
        return result.Match(
            _ => 0,
            error =>
            {
                context.Display.Error($"Key change failed: {error.Message}");
                return 1;
            }
        );
    }

    /// <summary>
    /// Validates command settings.
    /// </summary>
    private static Result<bool, SmartCardError> ValidateSettings(Settings settings)
    {
        return string.IsNullOrEmpty(settings.NewKeyset)
            ? Result.Failure<bool, SmartCardError>(
                SmartCardError.InvalidArgument("New keyset specification is required")
            )
            : Result.Success<bool, SmartCardError>(true);
    }

    /// <summary>
    /// Performs the key change operation using functional composition.
    /// </summary>
    private static async Task<Result<bool, SmartCardError>> PerformKeyChange(
        ICliExecutionContext context,
        Settings settings
    )
    {
        var channel = context.CardService.Context.Get<Gp4Net.Domain.SecureChannelState>(
            "SecureChannelSession"
        );
        if (channel.HasNoValue || channel.Value.KeyVersion == 0x00)
            return SmartCardError.InvalidResponse(
                "The active key version could not be autodetected from INITIALIZE UPDATE."
            );

        byte activeVersion = channel.Value.KeyVersion;
        var defaultVersions = KeyChange.GetDefaultVersions(activeVersion);
        if (defaultVersions.IsFailure)
            return defaultVersions.Error;
        byte defaultReplacedVersion = defaultVersions.Value.ReplacedVersion;
        byte replacedVersion = ParseVersion(settings.ReplaceKeyVersion, defaultReplacedVersion);
        byte nextVersion = defaultVersions.Value.NewVersion;
        byte newVersion = ParseVersion(settings.NewKeyVersion, nextVersion);
        var resolved = ResolveNewKeyset(settings, channel.Value.ProtocolVersion, newVersion);
        if (resolved.IsFailure)
            return resolved.Error;

        using var keyset = resolved.Value;
        context.Display.Info(
            $"Replace key version {replacedVersion:X2} with {keyset.KeyVersion:X2} "
                + $"({(keyset is Scp02KeySet ? "SCP02" : "SCP03")})"
        );

        if (settings.DryRun)
        {
            context.Display.Info("Dry run complete; no keys were changed.");
            return true;
        }
        if (!settings.Force && !AnsiConsole.Confirm("Permanently replace the card keys?", false))
            return SmartCardError.InvalidArgument("Key change cancelled.");

        return await ExecuteKeyChange(context, keyset, replacedVersion);
    }

    private static Result<IKeySet, SmartCardError> ResolveNewKeyset(
        Settings settings,
        Gp4Net.Cryptography.CryptoOperations.ScpVersion protocol,
        byte newVersion
    )
    {
        return KeysetParser.ParseKeysetSpecification(settings.NewKeyset, protocol, newVersion);
    }

    private static async Task<Result<bool, SmartCardError>> ExecuteKeyChange(
        ICliExecutionContext context,
        IKeySet newKeyset,
        byte replacedVersion
    )
    {
        context.Display.Info("New keyset resolved from configuration");
        context.Display.Info($"New key version: {newKeyset.KeyVersion:X2}");
        context.Display.Info($"Protocol: {(newKeyset is Scp02KeySet ? "SCP02" : "SCP03")}");

        var secureChannel = context.CardService.Context.Get<SecureChannelState>(
            "SecureChannelSession"
        );
        if (!secureChannel.HasValue)
        {
            return SmartCardError.AuthenticationFailed(
                "An authenticated secure channel is required."
            );
        }

        var response = await KeyChange.ExecuteAsync(
            context.CardService.ExecuteCommandAsync,
            secureChannel.Value,
            newKeyset,
            replacedVersion
        );
        return response.Map(result =>
        {
            context.Display.Info(
                $"Keys changed successfully; card confirmed key version {result.KeyVersion:X2}."
            );
            context.Display.Info(
                "Reconnect with the new keys before issuing another secure command."
            );
            return true;
        });
    }

    private static byte ParseVersion(string value, byte defaultValue) =>
        string.IsNullOrWhiteSpace(value)
            ? defaultValue
            : byte.Parse(
                value.Replace("0x", "", System.StringComparison.OrdinalIgnoreCase),
                NumberStyles.HexNumber
            );

    /// <summary>
    /// Settings for the keys change command.
    /// </summary>
    public class Settings : SecureCommandSettings
    {
        /// <summary>
        /// Gets or sets the new keyset specification.
        /// </summary>
        [CommandArgument(0, "<NEW_KEYSET>")]
        [Description(
            "New keyset specification (e.g., 'visa2:00000000000000000000000000000000' or 'gp_test_keys')"
        )]
        public string NewKeyset { get; set; } = string.Empty;

        [CommandOption("--new-key-version")]
        [Description("New key version (hex; default is active + 1, with 7F/FF becoming 01)")]
        public string NewKeyVersion { get; set; } = string.Empty;

        [CommandOption("--replace-key-version")]
        [Description("Existing key version (hex; default is autodetected by INITIALIZE UPDATE)")]
        public string ReplaceKeyVersion { get; set; } = string.Empty;

        [CommandOption("-f|--force")]
        [Description("Skip the destructive-operation confirmation")]
        public bool Force { get; set; }

        [CommandOption("--dry-run")]
        [Description("Resolve and display the change without sending PUT KEY")]
        public bool DryRun { get; set; }
    }
}
