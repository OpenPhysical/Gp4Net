using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card
{
    /// <summary>
    /// Command to change keys on a smart card.
    /// </summary>
    [PublicAPI]
    public class KeysChangeCommand : BaseCommand<KeysChangeCommand.Settings>
    {
        /// <summary>
        /// Initializes a new instance of the KeysChangeCommand class.
        /// </summary>
        public KeysChangeCommand(
            ICardService cardService,
            Gp4Net.Services.IGlobalPlatformService globalPlatformService,
            IKeysetResolver keysetResolver
        )
            : base(cardService, globalPlatformService, keysetResolver) { }

        /// <summary>
        /// Executes the keys change command to update the cryptographic keys on the card.
        /// </summary>
        /// <param name="context">The command context.</param>
        /// <param name="settings">The command settings.</param>
        /// <returns>0 if successful, 1 if failed.</returns>
        protected override async Task<int> ExecuteCommandAsync(
            CommandContext context,
            Settings settings
        )
        {
            // Validate required parameters
            if (string.IsNullOrEmpty(settings.NewKeyset))
            {
                AnsiConsole.MarkupLine("[red]Error: New keyset specification is required[/]");
                return 1;
            }

            // Auto-detect card reader and connect
            if (!EnsureCardConnection(settings))
            {
                return 1;
            }

            // Auto-detect secure channel parameters and establish connection
            if (!EnsureSecureChannel(settings))
            {
                AnsiConsole.MarkupLine(
                    "[red]Failed to establish secure channel with current keys[/]"
                );
                return 1;
            }

            try
            {
                AnsiConsole.MarkupLine("[yellow]Resolving new keyset from Lua script...[/]");

                // Resolve new keyset using only the script specification
                // The KeysetResolver will handle calling the Lua script with any parameters
                var newKeySet = KeysetResolver.ResolveKeyset(
                    settings.NewKeyset,
                    null, // No additional parameters needed - script handles everything
                    null,
                    null,
                    null, // No individual keys - all from script
                    0x01, // Default new key version
                    null // Card response for diversification will be auto-detected
                );

                AnsiConsole.MarkupLine("[green]✓ New keyset resolved from Lua script[/]");

                if (settings.Verbose)
                {
                    AnsiConsole.MarkupLine($"[dim]New key version: {newKeySet.KeyVersion:X2}[/]");
                    AnsiConsole.MarkupLine(
                        $"[dim]Protocol: {(newKeySet is Scp02KeySet ? "SCP02" : "SCP03")}[/]"
                    );
                }

                // Perform PUT KEY operation
                AnsiConsole.MarkupLine("[yellow]Changing keys...[/]");

                var putKeyResult = await GlobalPlatformService.PutKeysAsync(
                    (KeySet)newKeySet,
                    newKeySet.KeyVersion
                );

                if (putKeyResult.IsSuccess)
                {
                    AnsiConsole.MarkupLine("[green]✓ Keys changed successfully[/]");
                    return 0;
                }
                else
                {
                    AnsiConsole.MarkupLine($"[red]✗ Failed to change keys: {putKeyResult.Error.Message}[/]");
                    return 1;
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error changing keys: {ex.Message}[/]");
                if (settings.Verbose)
                {
                    AnsiConsole.WriteException(ex);
                }
                return 1;
            }
        }

        /// <summary>
        /// Settings for the keys change command.
        /// </summary>
        public class Settings : BaseCommandSettings
        {
            /// <summary>
            /// Gets or sets the new keyset specification.
            /// </summary>
            [CommandArgument(0, "<NEW_KEYSET>")]
            [Description(
                "New keyset specification (e.g., 'visa2:00000000000000000000000000000000' or 'gp_test_keys')"
            )]
            public string NewKeyset { get; set; } = string.Empty;

            /// <summary>
            /// This command requires a secure channel to authenticate with current keys.
            /// </summary>
            public override bool RequiresSecureChannel => true;
        }
    }
}
