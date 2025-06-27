using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Gp4Net.Tool.Infrastructure;
using Gp4Net.Tool.Services;
using JetBrains.Annotations;
using log4net;
using Spectre.Console;
using Spectre.Console.Cli;

namespace Gp4Net.Tool.Commands
{
    /// <summary>
    /// Base class for all GP4Net commands.
    /// </summary>
    [PublicAPI]
    public abstract class BaseCommand<TSettings> : AsyncCommand<TSettings>
        where TSettings : BaseCommandSettings
    {
        protected static readonly ILog Logger = LogManager.GetLogger(typeof(BaseCommand<TSettings>));

        protected readonly ICardService CardService;
        protected readonly IGlobalPlatformService GlobalPlatformService;

        /// <summary>
        /// Initializes a new instance of the BaseCommand class.
        /// </summary>
        protected BaseCommand(ICardService cardService, IGlobalPlatformService globalPlatformService)
        {
            CardService = cardService ?? throw new ArgumentNullException(nameof(cardService));
            GlobalPlatformService = globalPlatformService ?? throw new ArgumentNullException(nameof(globalPlatformService));
        }

        /// <inheritdoc />
        public override async Task<int> ExecuteAsync(CommandContext context, TSettings settings)
        {
            try
            {
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
        protected abstract Task<int> ExecuteCommandAsync(CommandContext context, TSettings settings);

        /// <summary>
        /// Ensures a card connection is established.
        /// </summary>
        protected bool EnsureCardConnection(TSettings settings)
        {
            if (CardService.IsConnected)
                return true;

            try
            {
                // The Reader property should already be resolved by the TypeConverter
                var readerName = settings.Reader.Name;
                
                if (!CardService.Connect(readerName))
                {
                    AnsiConsole.MarkupLine($"[red]Failed to connect to reader: {readerName}[/]");
                    return false;
                }

                // Show appropriate connection message based on how reader was resolved
                if (settings.Reader.IsAutoDetected)
                {
                    AnsiConsole.MarkupLine($"[green]Connected to auto-detected reader:[/] {readerName}");
                }
                else if (settings.Reader.IsPartialMatch)
                {
                    AnsiConsole.MarkupLine($"[green]Connected to reader (partial match):[/] {readerName}");
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
        /// Displays card information.
        /// </summary>
        protected void DisplayCardInfo()
        {
            if (!CardService.IsConnected)
                return;

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
        [Description("The card reader to use (exact name, partial name, or 'auto' for automatic detection)")]
        [TypeConverter(typeof(ReaderNameTypeConverter))]
        public Reader Reader { get; set; } = new Reader("auto");

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
    }
}