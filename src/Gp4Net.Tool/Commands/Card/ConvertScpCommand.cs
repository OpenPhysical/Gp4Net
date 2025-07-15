using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Gp4Net.Domain;
using Gp4Net.Domain.Commands;
using Gp4Net.Domain.Keys;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Services;
using Gp4Net.Transport;
using JetBrains.Annotations;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands.Card
{
    /// <summary>
    /// Command to convert a card from SCP02 to SCP03.
    /// </summary>
    [PublicAPI]
    /// <summary>
    /// Command to convert a GlobalPlatform card from SCP02 to SCP03 protocol.
    /// </summary>
    [Description("Convert card from SCP02 to SCP03")]
    public class ConvertScpCommand : BaseCommand<ConvertScpCommand.Settings>
    {
        /// <summary>
        /// Initializes a new instance of the ConvertScpCommand class.
        /// </summary>
        public ConvertScpCommand(
            ICardService cardService,
            Gp4Net.Services.IGlobalPlatformService globalPlatformService,
            IKeysetResolver keysetResolver
        )
            : base(cardService, globalPlatformService, keysetResolver) { }

        /// <summary>
        /// Executes the convert SCP command to upgrade a card from SCP02 to SCP03.
        /// </summary>
        /// <param name="context">The command context.</param>
        /// <param name="settings">The command settings.</param>
        /// <returns>0 if successful, 1 if failed.</returns>
        protected override async Task<int> ExecuteCommandAsync(
            CommandContext context,
            Settings settings
        )
        {
            AnsiConsole.MarkupLine("[blue]Converting card from SCP02 to SCP03...[/]");

            // Ensure card connection
            if (!EnsureCardConnection(settings))
            {
                return 1;
            }

            try
            {
                // Step 1: Connect with factory keys
                AnsiConsole.MarkupLine("[yellow]Step 1: Authenticating with factory keys...[/]");

                // Override keyset with factory keys if not specified
                if (
                    settings.FactoryKeyEnc == null
                    && settings.FactoryKeyMac == null
                    && settings.FactoryKeyDek == null
                )
                {
                    AnsiConsole.MarkupLine("[red]Factory keys are required for SCP conversion[/]");
                    return 1;
                }

                // Establish secure channel with factory keys
                settings.KeyEnc = settings.FactoryKeyEnc;
                settings.KeyMac = settings.FactoryKeyMac;
                settings.KeyDek = settings.FactoryKeyDek;
                settings.KeyVersion = 0xFF; // Factory key version

                if (!EnsureSecureChannel(settings))
                {
                    AnsiConsole.MarkupLine("[red]Failed to authenticate with factory keys[/]");
                    return 1;
                }

                AnsiConsole.MarkupLine("[green]✓ Authenticated with factory keys[/]");

                // Step 2: Set SCP_ENABLE to SCP03 only
                AnsiConsole.MarkupLine("[yellow]Step 2: Setting SCP_ENABLE to SCP03 i=70...[/]");

                var implementations = new List<ScpImplementation> { ScpImplementation.Scp03I70 };
                var storeDataResult = StoreDataCommand.CreateScpEnableCommand(implementations);
                if (storeDataResult.IsFailure)
                {
                    AnsiConsole.MarkupLine($"[red]Failed to create STORE DATA command: {storeDataResult.Error.Message}[/]");
                    return 1;
                }
                var response = CardService.SendCommand(storeDataResult.Value);

                if (!response.IsSuccessful)
                {
                    AnsiConsole.MarkupLine(
                        $"[red]Failed to set SCP_ENABLE: SW={response.StatusWord:X4}[/]"
                    );
                    return 1;
                }

                AnsiConsole.MarkupLine("[green]✓ SCP_ENABLE set to SCP03 i=70[/]");

                // Secure channel will be forcibly closed after SCP_ENABLE change
                AnsiConsole.MarkupLine("[yellow]Secure channel closed by card. Reconnecting...[/]");

                // Step 3: Reconnect and re-authenticate
                CardService.Disconnect();
                await Task.Delay(500); // Brief delay for card reset

                if (!EnsureCardConnection(settings))
                {
                    return 1;
                }

                if (!EnsureSecureChannel(settings))
                {
                    AnsiConsole.MarkupLine("[red]Failed to re-authenticate with factory keys[/]");
                    return 1;
                }

                // Step 4: Check SCP_ENABLE configuration
                AnsiConsole.MarkupLine("[yellow]Step 3: Checking SCP_ENABLE configuration...[/]");

                var commandResult = GetDataCommand.Create(0x00CF);
                if (commandResult.IsFailure)
                {
                    AnsiConsole.MarkupLine($"[red]✗ Failed to create GET DATA command: {commandResult.Error.Message}[/]");
                    return 1;
                }
                
                response = CardService.SendCommand(commandResult.Value);

                if (response.IsSuccessful && response.Data.Length > 0)
                {
                    AnsiConsole.MarkupLine(
                        $"[green]✓ SCP configuration: {Convert.ToHexString(response.Data)}[/]"
                    );
                }

                // Step 5: Install GP test keys as KVN 1
                if (settings.InstallTestKeys)
                {
                    AnsiConsole.MarkupLine(
                        "[yellow]Step 4: Installing GP test keys as KVN 1...[/]"
                    );

                    var testKey = settings.NewKey ?? GpTestKeys.StandardTestKey;

                    // Create PUT KEY command for 3 AES keys
                    var keyDataBlocks = new List<KeyDataBlock>();
                    
                    for (int i = 0; i < 3; i++) // ENC, MAC, DEK keys
                    {
                        var keyResult = KeyDataBlock.CreateAes128Key(testKey);
                        if (keyResult.IsFailure)
                        {
                            AnsiConsole.MarkupLine($"[red]Failed to create key data block: {keyResult.Error.Message}[/]");
                            return 1;
                        }
                        keyDataBlocks.Add(keyResult.Value);
                    }

                    var putKeyCommandResult = PutKeyCommand.Create(0x01, keyDataBlocks); // KVN 1
                    if (putKeyCommandResult.IsFailure)
                    {
                        AnsiConsole.MarkupLine($"[red]Failed to create PUT KEY command: {putKeyCommandResult.Error.Message}[/]");
                        return 1;
                    }
                    var putKeyCommand = putKeyCommandResult.Value;

                    // Add key version byte at the beginning of data
                    var putKeyData = new byte[] { 0x01 }; // KVN 1
                    putKeyData = [.. putKeyData, .. putKeyCommand.Data ?? Array.Empty<byte>()];

                    // Send modified PUT KEY command
                    var apdu = new byte[] { 0x80, 0xD8, 0x00, 0x81, (byte)putKeyData.Length };
                    apdu = [.. apdu, .. putKeyData];

                    response = CardService.SendCommand(apdu);

                    if (!response.IsSuccessful)
                    {
                        AnsiConsole.MarkupLine(
                            $"[red]Failed to install GP test keys: SW={response.StatusWord:X4}[/]"
                        );
                        return 1;
                    }

                    AnsiConsole.MarkupLine("[green]✓ GP test keys installed as KVN 1[/]");

                    // Step 6: Set default key version to 1
                    AnsiConsole.MarkupLine(
                        "[yellow]Step 5: Setting default key version to 1...[/]"
                    );

                    storeDataResult = StoreDataCommand.CreateDefaultKeyVersionCommand(0x01);
                    if (storeDataResult.IsFailure)
                    {
                        AnsiConsole.MarkupLine($"[red]Failed to create default key version command: {storeDataResult.Error.Message}[/]");
                        return 1;
                    }
                    response = CardService.SendCommand(storeDataResult.Value);

                    if (!response.IsSuccessful)
                    {
                        AnsiConsole.MarkupLine(
                            $"[red]Failed to set default key version: SW={response.StatusWord:X4}[/]"
                        );
                        return 1;
                    }

                    AnsiConsole.MarkupLine("[green]✓ Default key version set to 1[/]");
                }

                // Step 7: Power cycle the card
                AnsiConsole.MarkupLine(
                    "[yellow]Step 6: Power cycling card to activate changes...[/]"
                );

                CardService.Disconnect();
                await Task.Delay(2000); // Wait for card to fully reset

                if (!EnsureCardConnection(settings))
                {
                    return 1;
                }

                // Step 8: Test connection with new keys
                if (settings.InstallTestKeys)
                {
                    AnsiConsole.MarkupLine("[yellow]Step 7: Testing SCP03 with GP test keys...[/]");

                    // Update settings to use test keys
                    var testKey = settings.NewKey ?? GpTestKeys.StandardTestKey;
                    settings.KeyEnc = testKey;
                    settings.KeyMac = testKey;
                    settings.KeyDek = testKey;
                    settings.KeyVersion = 0x01;

                    if (!EnsureSecureChannel(settings))
                    {
                        AnsiConsole.MarkupLine(
                            "[red]Failed to authenticate with GP test keys over SCP03[/]"
                        );
                        return 1;
                    }

                    AnsiConsole.MarkupLine(
                        "[green]✓ Successfully authenticated with SCP03 i=70[/]"
                    );

                    // Final verification
                    var cardDataResult = GetDataCommand.Create(0x0066);
                    if (cardDataResult.IsFailure)
                    {
                        AnsiConsole.MarkupLine($"[red]✗ Failed to create card data command: {cardDataResult.Error.Message}[/]");
                        return 1;
                    }
                    
                    response = CardService.SendCommand(cardDataResult.Value);

                    if (response.IsSuccessful)
                    {
                        AnsiConsole.MarkupLine("[green]✓ Card data verified[/]");
                    }
                }

                AnsiConsole.MarkupLine("");
                AnsiConsole.MarkupLine("[green]✓ CONVERSION COMPLETED SUCCESSFULLY[/]");
                AnsiConsole.MarkupLine("Card now supports ONLY SCP03 i=70");

                if (settings.InstallTestKeys)
                {
                    AnsiConsole.MarkupLine("GP test keys installed as KVN 1 (default)");
                    AnsiConsole.MarkupLine(
                        "Card should work with standard GP tools using default keys"
                    );
                }

                return 0;
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error during conversion: {ex.Message}[/]");
                if (settings.Verbose)
                {
                    AnsiConsole.WriteException(ex);
                }
                return 1;
            }
            finally
            {
                CardService.Disconnect();
            }
        }

        /// <summary>
        /// Settings for the convert-scp command.
        /// </summary>
        [PublicAPI]
        public class Settings : BaseCommandSettings
        {
            /// <summary>
            /// Gets or sets the factory encryption key.
            /// </summary>
            [CommandOption("--factory-key-enc")]
            [Description("Factory encryption key (hex string)")]
            [TypeConverter(typeof(HexStringTypeConverter))]
            public byte[]? FactoryKeyEnc { get; set; }

            /// <summary>
            /// Gets or sets the factory MAC key.
            /// </summary>
            [CommandOption("--factory-key-mac")]
            [Description("Factory MAC key (hex string)")]
            [TypeConverter(typeof(HexStringTypeConverter))]
            public byte[]? FactoryKeyMac { get; set; }

            /// <summary>
            /// Gets or sets the factory DEK key.
            /// </summary>
            [CommandOption("--factory-key-dek")]
            [Description("Factory data encryption key (hex string)")]
            [TypeConverter(typeof(HexStringTypeConverter))]
            public byte[]? FactoryKeyDek { get; set; }

            /// <summary>
            /// Gets or sets whether to install GP test keys.
            /// </summary>
            [CommandOption("--install-test-keys")]
            [Description("Install GP test keys after conversion")]
            [DefaultValue(true)]
            public bool InstallTestKeys { get; set; } = true;

            /// <summary>
            /// Gets or sets the new key to install.
            /// </summary>
            [CommandOption("--new-key")]
            [Description("New key to install (hex string). Defaults to GP test key.")]
            [TypeConverter(typeof(HexStringTypeConverter))]
            public byte[]? NewKey { get; set; }

            /// <summary>
            /// Gets or sets the target SCP implementation.
            /// </summary>
            [CommandOption("--scp-implementation")]
            [Description("Target SCP03 implementation (hex). Defaults to 0x70.")]
            [DefaultValue("70")]
            public string ScpImplementation { get; set; } = "70";

            /// <summary>
            /// Validates the command settings.
            /// </summary>
            /// <returns>Success if valid, or an error message if validation fails.</returns>
            public override ValidationResult Validate()
            {
                var result = base.Validate();
                if (!result.Successful)
                {
                    return result;
                }

                // Validate factory keys
                if (FactoryKeyEnc == null || FactoryKeyMac == null || FactoryKeyDek == null)
                {
                    return ValidationResult.Error(
                        "All factory keys (--factory-key-enc, --factory-key-mac, --factory-key-dek) are required"
                    );
                }

                // Validate SCP implementation
                if (
                    !byte.TryParse(
                        ScpImplementation,
                        System.Globalization.NumberStyles.HexNumber,
                        null,
                        out var impl
                    )
                )
                {
                    return ValidationResult.Error("Invalid SCP implementation value");
                }

                var validImplementations = new byte[] { 0x00, 0x10, 0x20, 0x60, 0x70 };
                if (!validImplementations.Contains(impl))
                {
                    return ValidationResult.Error(
                        "Invalid SCP03 implementation. Valid values: 00, 10, 20, 60, 70"
                    );
                }

                return ValidationResult.Success();
            }
        }
    }
}
