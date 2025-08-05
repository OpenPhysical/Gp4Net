using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Threading.Tasks;
using Gp4Net.Domain.Keys;
using Gp4Net.Services;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using log4net;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands;

/// <summary>
/// Base class for all GP4Net commands.
/// </summary>
[PublicAPI]
public abstract class BaseCommand<TSettings> : AsyncCommand<TSettings>
    where TSettings : BaseCommandSettings
{
    protected static readonly ILog Logger = LogManager.GetLogger(
        typeof(BaseCommand<TSettings>)
    );

    protected readonly ICardService CardService;
    protected readonly IGlobalPlatformService GlobalPlatformService;
    protected readonly IKeysetResolver KeysetResolver;

    /// <summary>
    /// Initializes a new instance of the BaseCommand class.
    /// </summary>
    protected BaseCommand(
        ICardService cardService,
        IGlobalPlatformService globalPlatformService,
        IKeysetResolver keysetResolver
    )
    {
        CardService = cardService ?? throw new ArgumentNullException(nameof(cardService));
        GlobalPlatformService =
            globalPlatformService
            ?? throw new ArgumentNullException(nameof(globalPlatformService));
        KeysetResolver =
            keysetResolver ?? throw new ArgumentNullException(nameof(keysetResolver));
    }

    /// <summary>
    /// Executes the command asynchronously with error handling and logging.
    /// </summary>
    /// <param name="context">The command context.</param>
    /// <param name="settings">The command settings.</param>
    /// <returns>0 if successful, 1 if failed.</returns>
    public override async Task<int> ExecuteAsync(CommandContext context, TSettings settings)
    {
        try
        {
            // Enable verbose console logging if requested
            Pipeline.VerboseLoggingHelper.EnableVerboseLogging(settings.Verbose);
                
            if (settings.Verbose)
            {
                Logger.Info($"Executing command: {GetType().Name}");
            }

            return await ExecuteCommandAsync(context, settings);
        }
        catch (Exception ex)
        {
            Logger.Error($"Command execution failed: {ex.Message}", ex);
            AnsiConsole.WriteException(ex);
            return 1;
        }
    }

    /// <summary>
    /// Executes the specific command logic.
    /// </summary>
    protected abstract Task<int> ExecuteCommandAsync(
        CommandContext context,
        TSettings settings
    );

    /// <summary>
    /// Ensures a card connection is established.
    /// </summary>
    protected bool EnsureCardConnection(TSettings settings)
    {
        if (CardService.IsConnected)
        {
            return true;
        }

        try
        {
            // The Reader property should already be resolved by the TypeConverter
            if (settings.Reader == null)
            {
                AnsiConsole.MarkupLine("[red]Reader not specified or resolved[/]");
                return false;
            }

            var readerName = settings.Reader.Name;

            if (!CardService.Connect(readerName))
            {
                AnsiConsole.MarkupLine($"[red]Failed to connect to reader: {readerName}[/]");
                return false;
            }

            // Show appropriate connection message based on how reader was resolved
            if (settings.Reader.IsAutoDetected)
            {
                AnsiConsole.MarkupLine(
                    $"[green]Connected to auto-detected reader:[/] {readerName}"
                );
            }
            else if (settings.Reader.IsPartialMatch)
            {
                AnsiConsole.MarkupLine(
                    $"[green]Connected to reader (partial match):[/] {readerName}"
                );
            }
            else
            {
                AnsiConsole.MarkupLine($"[green]Connected to reader:[/] {readerName}");
            }

            return true;
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Reader connection error: {ex.Message}[/]");
            return false;
        }
    }

    /// <summary>
    /// Ensures a secure channel is established if required.
    /// </summary>
    protected bool EnsureSecureChannel(TSettings settings)
    {
        if (!settings.RequiresSecureChannel)
        {
            return true;
        }

        if (CardService.IsSecureChannelEstablished)
        {
            return true;
        }

        try
        {
            AnsiConsole.MarkupLine("[yellow]Establishing secure channel...[/]");

            // Resolve keyset
            var keySet = KeysetResolver.ResolveKeyset(
                settings.Keyset,
                settings.KeysetParams,
                settings.KeyEnc,
                settings.KeyMac,
                settings.KeyDek,
                settings.KeyVersion,
                null // TODO: Get card response for diversification
            );

            var securityLevel = settings.SecurityLevel;

            // For now, use first key as static key
            // TODO: Update CardService to accept IKeySet
            var keyBytes =
                settings.KeyEnc
                ?? settings.KeyMac
                ?? settings.KeyDek
                ?? GpTestKeys.StandardTestKey;

            if (CardService.EstablishSecureChannel(keyBytes, securityLevel))
            {
                AnsiConsole.MarkupLine("[green]✓ Secure channel established[/]");
                return true;
            }
            else
            {
                AnsiConsole.MarkupLine("[red]✗ Failed to establish secure channel[/]");
                return false;
            }
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Secure channel error: {ex.Message}[/]");
            if (settings.Verbose)
            {
                AnsiConsole.WriteException(ex);
            }
            return false;
        }
    }

    /// <summary>
    /// Displays card information.
    /// </summary>
    protected void DisplayCardInfo()
    {
        if (!CardService.IsConnected)
        {
            return;
        }

        var atr = CardService.GetAtr();
        if (atr != null)
        {
            AnsiConsole.MarkupLine($"[green]Card ATR:[/] {Convert.ToHexString(atr)}");
        }
    }
}

/// <summary>
/// Base settings for all commands.
/// </summary>
[PublicAPI]
public class BaseCommandSettings : CommandSettings
{
    /// <summary>
    /// Gets or sets the card reader.
    /// </summary>
    [CommandOption("-r|--reader <READER>")]
    [Description(
        "The card reader to use (exact name, partial name, or 'auto' for automatic detection)"
    )]
    [TypeConverter(typeof(ReaderNameTypeConverter))]
    [DefaultValue("auto")]
    public Reader? Reader { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to use verbose output.
    /// </summary>
    [CommandOption("-v|--verbose")]
    [Description("Enable verbose output")]
    public bool Verbose { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to suppress card info display.
    /// </summary>
    [CommandOption("--no-card-info")]
    [Description("Don't display card information")]
    public bool NoCardInfo { get; set; }

    /// <summary>
    /// Gets or sets the security level for secure channel.
    /// </summary>
    [CommandOption("-s|--security-level")]
    [Description("Security level (0=None, 1=C-MAC, 3=C-MAC+C-DECRYPTION)")]
    [TypeConverter(typeof(ByteTypeConverter))]
    public byte SecurityLevel { get; set; } = 1;

    /// <summary>
    /// Gets or sets the keyset specification.
    /// </summary>
    [CommandOption("--keyset")]
    [Description(
        "Keyset function (e.g., 'gp_test_keys' or 'script:function'). Defaults to 'gp_test_keys'."
    )]
    public string? Keyset { get; set; }

    /// <summary>
    /// Gets or sets keyset parameters.
    /// </summary>
    [CommandOption("--keyset-param")]
    [Description(
        "Parameters for keyset function (format: key=value). Can be specified multiple times."
    )]
    public string[]? KeysetParamArray { get; set; }

    /// <summary>
    /// Gets the parsed keyset parameters.
    /// </summary>
    public Dictionary<string, string> KeysetParams
    {
        get
        {
            var result = new Dictionary<string, string>();
            if (KeysetParamArray != null)
            {
                foreach (var param in KeysetParamArray)
                {
                    var parts = param.Split('=', 2);
                    if (parts.Length == 2)
                    {
                        result[parts[0]] = parts[1];
                    }
                }
            }
            return result;
        }
    }

    /// <summary>
    /// Gets or sets the encryption key.
    /// </summary>
    [CommandOption("--key-enc")]
    [Description("Encryption key (hex string). Overrides keyset.")]
    [TypeConverter(typeof(HexStringTypeConverter))]
    public byte[]? KeyEnc { get; set; }

    /// <summary>
    /// Gets or sets the MAC key.
    /// </summary>
    [CommandOption("--key-mac")]
    [Description("MAC key (hex string). Overrides keyset.")]
    [TypeConverter(typeof(HexStringTypeConverter))]
    public byte[]? KeyMac { get; set; }

    /// <summary>
    /// Gets or sets the DEK key.
    /// </summary>
    [CommandOption("--key-dek")]
    [Description("Data encryption key (hex string). Overrides keyset.")]
    [TypeConverter(typeof(HexStringTypeConverter))]
    public byte[]? KeyDek { get; set; }

    /// <summary>
    /// Gets or sets the key version.
    /// </summary>
    [CommandOption("--key-version")]
    [Description("Key version (default: 0x00 for auto-detection).")]
    [TypeConverter(typeof(ByteTypeConverter))]
    public byte KeyVersion { get; set; } = 0x00;

    /// <summary>
    /// Gets whether this command requires a secure channel.
    /// Override in derived settings to change default behavior.
    /// </summary>
    public virtual bool RequiresSecureChannel => true;
}